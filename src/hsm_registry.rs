use constant_time::{Choice, CtEqOps};
use zeroize::Zeroize;

use crate::capability::{self, CapError};
use crate::syscall::{SyscallContext, SyscallError, is_user_address};

//
// 상수 / 컴파일-타임 불변식
//

pub const HSM_MAX_SLOTS: usize = 8;

// HsmCapability 의 ABI 정렬 크기는 16바이트 (u64 정렬 강제, prior art `Capability` 와 동일).
// 16 옥텟 전부를 가시 필드로 채워 implicit padding 0 — CR-03 Ring0→Ring3 info-leak 봉쇄.
// 레이아웃: token(0..8) + slot(8) + _pad0(9) + rights(10..12) + _pad(12) + _pad1(13..16).
// `#[repr(C, packed)]` 미사용 — 필드 참조 시 unaligned access 위험 회피.
const _: () = assert!(core::mem::size_of::<HsmCapability>() == 16);
const _: () = assert!(core::mem::size_of::<HsmSlotState>() == 1);
const _: () = assert!(HSM_MAX_SLOTS == 8);

//
// HSM 슬롯 인덱스 (D-02)
//

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct HsmSlotIdx(pub u8);

impl HsmSlotIdx {
    pub const INVALID: Self = Self(0xFF);
}

//
// HSM 권한 비트 플래그 (D-03 — 비트 인덱스 0..5 잠금)
//

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct HsmRights(pub u16);

impl HsmRights {
    pub const NONE: Self = Self(0);
    pub const USE: Self = Self(1 << 0);
    pub const ENUMERATE: Self = Self(1 << 1);
    pub const REVOKE: Self = Self(1 << 2);
    #[allow(dead_code)]
    pub const RELAY_SRC: Self = Self(1 << 3); // Phase 3 reserved
    #[allow(dead_code)]
    pub const RELAY_DST: Self = Self(1 << 4); // Phase 3 reserved
    #[allow(dead_code)]
    pub const NETWORK_ATTACH: Self = Self(1 << 5); // Phase 6 reserved
}

impl core::ops::BitOr for HsmRights {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        HsmRights(self.0 | rhs.0)
    }
}

//
// 슬롯 상태 머신 (D-11 — 재사용 가능 3-state)
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HsmSlotState {
    Empty = 0,
    Attached = 1,
    Detaching = 2,
}

//
// 에러 (D Claude's Discretion + TokenGen for gen_token_u64 surface)
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsmCapError {
    InvalidToken,
    InvalidSlot,
    RightsMissing,
    Full,
    NotAttached,
    Busy,
    TokenGen,
}

//
// HSM Capability (D-02 — 12 byte minimal layout)
//

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct HsmCapability {
    pub token: u64,
    pub slot: HsmSlotIdx,
    // CR-03: offset 9 의 align-pad 를 명시 필드로 흡수 (rights u16 정렬 보장)
    _pad0: u8,
    pub rights: HsmRights,
    _pad: u8,
    // CR-03: trailing pad (offset 13..16) 를 명시 필드로 흡수 — 16옥텟 전부 가시 필드
    _pad1: [u8; 3],
}

impl HsmCapability {
    pub const fn invalid() -> Self {
        Self {
            token: 0,
            slot: HsmSlotIdx::INVALID,
            _pad0: 0,
            rights: HsmRights::NONE,
            _pad: 0,
            _pad1: [0; 3],
        }
    }

    #[cfg(debug_assertions)]
    pub const fn with_forged_token(token: u64, slot: HsmSlotIdx, rights: HsmRights) -> Self {
        Self {
            token,
            slot,
            _pad0: 0,
            rights,
            _pad: 0,
            _pad1: [0; 3],
        }
    }

    // CT: token-nonzero & slot-eq & rights-subset, single-branch exit (CAP-03, SC-4b)
    #[inline]
    pub fn is_valid_for(&self, slot: HsmSlotIdx, required: HsmRights) -> bool {
        let token_nonzero: Choice = CtEqOps::ne(&self.token, &0u64);
        let slot_eq: Choice = CtEqOps::eq(&self.slot.0, &slot.0);
        let masked: u16 = self.rights.0 & required.0;
        let rights_ok: Choice = CtEqOps::eq(&masked, &required.0);

        (token_nonzero & slot_eq & rights_ok).unwrap_u8() == 1
    }

    #[inline]
    pub fn ct_token_eq(&self, other: &Self) -> Choice {
        CtEqOps::eq(&self.token, &other.token)
    }
}

impl Zeroize for HsmCapability {
    fn zeroize(&mut self) {
        self.token.zeroize();
        self.rights = HsmRights::NONE;
        self.slot = HsmSlotIdx::INVALID;
        self._pad0 = 0;
        self._pad = 0;
        self._pad1 = [0; 3];
    }
}

//
// 슬롯 데이터 (D-14 — Drop은 안전망, 정상 detach 경로가 주 경로)
//
// `Copy` 미파생: `Drop` 구현 존재 → 컴파일러가 E0184 로 거절함.
// Drop 보장 (RESEARCH §4 line 561-569) 이 우선 — 슬롯은 정적 풀 안에서만
// 존재하므로 값 복사 / 값 이동 요구가 없음 (배열 인덱싱 + &mut 만 사용).
pub struct HsmSlot {
    pub state: HsmSlotState,
    pub token: u64,
    pub rights: HsmRights,
}

impl HsmSlot {
    pub const fn new() -> Self {
        Self {
            state: HsmSlotState::Empty,
            token: 0,
            rights: HsmRights::NONE,
        }
    }
}

impl Zeroize for HsmSlot {
    fn zeroize(&mut self) {
        // 비밀(토큰) 먼저 소거 — 관찰자가 Detaching 상태에서 본문을 읽어도 키 자료는 이미 0
        self.token.zeroize();
        self.rights = HsmRights::NONE;
        // 상태 전이는 가장 마지막 (PATTERNS B-4)
        self.state = HsmSlotState::Empty;
    }
}

impl Drop for HsmSlot {
    // SAFETY-net: Drop은 폴백. 정상 detach 경로가 명시적으로 zeroize 를 먼저 호출함.
    // panic = abort 환경에서는 unwind 가 Drop 을 트리거하지 않으므로 본 경로는 테스트
    // 및 향후 SMP 종료 시점 보호 목적임.
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// HSM 레지스트리 (D-09 — static mut + 안전 래퍼)
//

pub struct HsmRegistry {
    slots: [HsmSlot; HSM_MAX_SLOTS],
}

impl HsmRegistry {
    pub const fn new() -> Self {
        Self {
            slots: [const { HsmSlot::new() }; HSM_MAX_SLOTS],
        }
    }

    pub fn attached_count(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < HSM_MAX_SLOTS {
            if matches!(self.slots[i].state, HsmSlotState::Attached) {
                n += 1;
            }
            i += 1;
        }
        n
    }

    pub fn slot_is_empty(&self, idx: HsmSlotIdx) -> bool {
        let raw = idx.0 as usize;
        if raw >= HSM_MAX_SLOTS {
            return false;
        }
        matches!(self.slots[raw].state, HsmSlotState::Empty)
    }

    // SAFETY contract (D-09, D-12): BSP single-core; CAP_DRBG must be initialized
    // via capability::init_prng() before this is entered.
    pub unsafe fn attach(&mut self, rights: HsmRights) -> Result<HsmCapability, HsmCapError> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if matches!(slot.state, HsmSlotState::Empty) {
                // SAFETY: BSP single-core; capability::init_prng() completed in boot order
                // before REGISTRY mutation entry. CAP_DRBG 는 단일 인스턴스 (D-05).
                let token = unsafe {
                    capability::gen_token_u64().map_err(|e| match e {
                        CapError::PrngNotInitialized => HsmCapError::TokenGen,
                        CapError::DrbgInit => HsmCapError::TokenGen,
                        CapError::NoEntropy => HsmCapError::TokenGen,
                        _ => HsmCapError::TokenGen,
                    })?
                };
                // 상태 전이는 마지막: token / rights 가 모두 기록된 뒤에야 Attached 노출
                slot.token = token;
                slot.rights = rights;
                slot.state = HsmSlotState::Attached;
                // CR-03: padding 까지 명시 0 (struct literal 이 모든 가시 필드 초기화)
                return Ok(HsmCapability {
                    token,
                    slot: HsmSlotIdx(i as u8),
                    _pad0: 0,
                    rights,
                    _pad: 0,
                    _pad1: [0; 3],
                });
            }
        }
        Err(HsmCapError::Full)
    }

    // CR-01/CR-02: cap 을 *레지스트리* 와 대조 인증.
    //
    // is_valid_for(cap.slot, ...) 은 user-supplied 필드끼리만 비교하므로 tautology — 본
    // 메서드만이 "슬롯에 저장된 진본 토큰 + 진본 rights" 와 비교한다. 세 검사를 CT-AND 로
    // 결합하여 early-return 없음 (Pitfall 1): slot 인덱스 범위, slot 상태 Attached,
    // 토큰 일치, *저장된* rights ⊇ required, *cap* rights ⊇ required (둘 다 통과해야 함 —
    // 위조 cap 이 rights 비트를 임의로 세팅했더라도 슬롯이 발급한 권한을 넘지 못함).
    //
    // SAFETY: 호출자는 &self 만 빌려주므로 BSP single-core 가정만 충족하면 됨.
    pub fn authenticate(&self, cap: &HsmCapability, required: HsmRights) -> bool {
        let idx = cap.slot.0 as usize;
        // slot index out of range → cap 합성 자체가 의미 없음. 단, CT 평면화를 위해 가짜
        // cap_in_slot 으로 비교는 끝까지 수행하고 마지막에 in_range 비트로 AND.
        let in_range = idx < HSM_MAX_SLOTS;
        let safe_idx = if in_range { idx } else { 0 };
        let slot = &self.slots[safe_idx];

        let state_ok: Choice = CtEqOps::eq(&(slot.state as u8), &(HsmSlotState::Attached as u8));

        let cap_in_slot = HsmCapability {
            token: slot.token,
            slot: HsmSlotIdx(safe_idx as u8),
            _pad0: 0,
            rights: slot.rights,
            _pad: 0,
            _pad1: [0; 3],
        };
        let token_eq: Choice = cap.ct_token_eq(&cap_in_slot);
        // 저장된 rights ⊇ required (위조 cap rights 무시)
        let stored_masked: u16 = slot.rights.0 & required.0;
        let stored_rights_ok: Choice = CtEqOps::eq(&stored_masked, &required.0);
        // cap rights ⊇ required (요청자가 명시한 권한이 부족하면 거부 — REVOKE 비트 누락 차단)
        let cap_masked: u16 = cap.rights.0 & required.0;
        let cap_rights_ok: Choice = CtEqOps::eq(&cap_masked, &required.0);
        // 토큰 != 0 (invalid cap 사전 차단)
        let token_nonzero: Choice = CtEqOps::ne(&cap.token, &0u64);

        let all_ct = token_nonzero & state_ok & token_eq & stored_rights_ok & cap_rights_ok;
        // CT-AND 결과를 마지막에만 bool in_range 와 결합 (in_range 가 false 면 결과 false)
        (all_ct.unwrap_u8() == 1) & in_range
    }

    // SAFETY contract: BSP single-core. CR-02: required (예: HsmRights::REVOKE) 미보유 시 거부.
    pub unsafe fn detach(
        &mut self,
        cap: &HsmCapability,
        required: HsmRights,
    ) -> Result<(), HsmCapError> {
        // (1) CT 인증 — 슬롯에 저장된 진본 토큰 + 저장된 rights + cap rights 동시 검증
        if !self.authenticate(cap, required) {
            // syscall 경계에서 Denied 로 collapse 되므로 어떤 실패 사유이든 InvalidToken 반환
            // (Pitfall 7: variant 노출 최소화). idx 가 범위 밖이면 별도 처리도 동일 매핑.
            let idx = cap.slot.0 as usize;
            if idx >= HSM_MAX_SLOTS {
                return Err(HsmCapError::InvalidSlot);
            }
            match self.slots[idx].state {
                HsmSlotState::Detaching => return Err(HsmCapError::Busy),
                HsmSlotState::Empty => return Err(HsmCapError::NotAttached),
                HsmSlotState::Attached => return Err(HsmCapError::InvalidToken),
            }
        }
        // (2) 인증 통과 — Attached 상태 보장됨
        let idx = cap.slot.0 as usize;
        let slot = &mut self.slots[idx];
        // D-13: 명시적 Detaching 윈도우 — in-flight 호출자가 stale token 으로
        // 본 슬롯을 다시 잡으면 Busy 거부됨
        slot.state = HsmSlotState::Detaching;
        // 명시적 소거 (Drop 폴백이 아닌 주 경로) — zeroize 가 state 를 Empty 로 되돌림
        slot.zeroize();
        Ok(())
    }
}

//
// 전역 싱글턴 (D-09 — capability.rs / ipc.rs 패턴 일관)
//

pub static mut REGISTRY: HsmRegistry = HsmRegistry::new();

pub unsafe fn with_registry<R>(f: impl FnOnce(&HsmRegistry) -> R) -> R {
    // SAFETY: BSP single-core syscall dispatch is the only entry; preempt-disabled by FMASK.
    let r = unsafe { &*(&raw const REGISTRY) };
    f(r)
}

pub unsafe fn with_registry_mut<R>(f: impl FnOnce(&mut HsmRegistry) -> R) -> R {
    // SAFETY: BSP single-core; same invariant as with_registry.
    let r = unsafe { &mut *(&raw mut REGISTRY) };
    f(r)
}

//
// 슬롯 정보 ABI (enumerate 출력 — 8바이트, _reserved 는 Phase 2/5 확장 슬롯)
//

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmSlotInfo {
    pub slot: u8,
    pub state: u8,
    _reserved: [u8; 6],
}

const _: () = assert!(core::mem::size_of::<HsmSlotInfo>() == 8);

impl HsmSlotInfo {
    pub const fn empty() -> Self {
        Self {
            slot: 0xFF,
            state: 0,
            _reserved: [0; 6],
        }
    }
}

impl HsmRegistry {
    pub fn enumerate(&self, out: &mut [HsmSlotInfo]) -> usize {
        let mut written = 0usize;
        let cap = out.len().min(HSM_MAX_SLOTS);
        for (i, slot) in self.slots.iter().enumerate() {
            if i >= cap {
                break;
            }
            if matches!(slot.state, HsmSlotState::Attached) {
                out[written] = HsmSlotInfo {
                    slot: i as u8,
                    state: slot.state as u8,
                    _reserved: [0; 6],
                };
                written += 1;
            }
        }
        written
    }
}

//
// Plan 05 boot smoke 진입점 (Ring 3 ABI 우회). D-16: Phase 1 attach 는 비인증.
//
// SAFETY: BSP 단일 코어 + capability::init_prng() 완료 가정.
pub unsafe fn attach_kernel_side(rights: HsmRights) -> Result<HsmCapability, HsmCapError> {
    // SAFETY: BSP single-core; with_registry_mut 의 invariant 위임
    unsafe { with_registry_mut(|r| r.attach(rights)) }
}

//
// syscall 핸들러 — D-10 매핑 + Pitfall 1/2/3/4/7 강제
//

pub fn handle_attach(ctx: &mut SyscallContext) -> u64 {
    let _bus_kind_hint = ctx.rdi; // Phase 1 ignored; Phase 2 BusKind hint 예약
    let out_ptr = ctx.rsi;
    let user_cap_size = ctx.rdx;

    // (1) 크기 sanity — HsmCapability ABI 정렬 크기와 정확히 일치
    if user_cap_size != core::mem::size_of::<HsmCapability>() as u64 {
        return SyscallError::BadArg.as_rax();
    }
    // (2) user-pointer dual range check (Pitfall 3)
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(user_cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }

    // (3) D-16: cap 검사 없이 직접 attach (Phase 5 에서 attestation 게이트가 본 호출 자체를 감쌈)
    // SAFETY: BSP single-core + capability::init_prng() 완료 가정
    let cap = match unsafe { with_registry_mut(|r| r.attach(HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE)) } {
        Ok(c) => c,
        Err(HsmCapError::Full) => return SyscallError::BadArg.as_rax(),
        Err(_) => return SyscallError::Internal.as_rax(),
    };

    // (4) SMAP write window — 단일 copy_nonoverlapping (Pitfall 2)
    // SAFETY: out_ptr 는 사용자 주소 dual-check 통과; copy 폭은 HsmCapability ABI 크기
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            &cap as *const HsmCapability as *const u8,
            out_ptr as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    0
}

pub fn handle_detach(ctx: &mut SyscallContext) -> u64 {
    let in_ptr = ctx.rdi;
    let user_cap_size = ctx.rdx;

    // (1) 크기 sanity
    if user_cap_size != core::mem::size_of::<HsmCapability>() as u64 {
        return SyscallError::BadArg.as_rax();
    }
    // (2) user-pointer dual range check (Pitfall 3)
    if !is_user_address(in_ptr) || !is_user_address(in_ptr.saturating_add(user_cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }

    // (3) SMAP read window — 단일 copy_nonoverlapping (Pitfall 2)
    let mut cap = HsmCapability::invalid();
    // SAFETY: in_ptr dual-check 통과; copy 폭은 HsmCapability ABI 크기
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            in_ptr as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (4) detach — CR-02: registry 가 REVOKE 비트 + 저장 토큰 일치 동시 인증
    // Pitfall 7: capability-거부 variant 전부 Denied 로 collapse
    // SAFETY: BSP single-core
    let result = unsafe { with_registry_mut(|r| r.detach(&cap, HsmRights::REVOKE)) };
    let rax = match result {
        Ok(()) => 0u64,
        Err(HsmCapError::InvalidToken)
        | Err(HsmCapError::InvalidSlot)
        | Err(HsmCapError::NotAttached)
        | Err(HsmCapError::Busy)
        | Err(HsmCapError::RightsMissing) => SyscallError::Denied.as_rax(),
        Err(_) => SyscallError::Internal.as_rax(),
    };

    // (5) stack cap 소거 — 모든 경로 (Pitfall 4)
    cap.zeroize();
    rax
}

pub fn handle_enumerate(ctx: &mut SyscallContext) -> u64 {
    let cap_ptr = ctx.rdi;
    let out_ptr = ctx.rsi;
    let count = ctx.rdx;

    // (1) cap 입력 sanity — 정확한 ABI 크기 보장
    let cap_size = core::mem::size_of::<HsmCapability>() as u64;
    if !is_user_address(cap_ptr) || !is_user_address(cap_ptr.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }

    // (2) cap 만 먼저 읽음 — 출력 버퍼는 cap 인증 통과 *후* 검증 (Pitfall 1)
    let mut cap = HsmCapability::invalid();
    // SAFETY: cap_ptr dual-check 통과; cap_size 바이트 (HsmCapability ABI)
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            cap_ptr as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (3) cap 인증 (CT). CR-01: registry 와 대조 — is_valid_for(cap.slot, ...) 은
    // user-supplied 필드끼리만 비교하는 tautology 이므로 사용 금지.
    // Pitfall 1: 실패 시 user 출력 버퍼 절대 미수정.
    // SAFETY: BSP single-core
    let auth_ok = unsafe { with_registry(|r| r.authenticate(&cap, HsmRights::ENUMERATE)) };
    if !auth_ok {
        cap.zeroize();
        return SyscallError::Denied.as_rax();
    }

    // (4) 출력 버퍼 sanity (cap 인증 이후)
    if count > HSM_MAX_SLOTS as u64 {
        cap.zeroize();
        return SyscallError::BadArg.as_rax();
    }
    let info_bytes = count.saturating_mul(core::mem::size_of::<HsmSlotInfo>() as u64);
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(info_bytes)) {
        cap.zeroize();
        return SyscallError::BadAddress.as_rax();
    }

    // (5) 스택 버퍼 채우기 — registry 읽기는 SMAP 윈도우 외부 (Pitfall 2)
    let mut info_buf: [HsmSlotInfo; HSM_MAX_SLOTS] = [HsmSlotInfo::empty(); HSM_MAX_SLOTS];
    let cap_elems = (count as usize).min(HSM_MAX_SLOTS);
    // SAFETY: BSP single-core
    let n = unsafe { with_registry(|r| r.enumerate(&mut info_buf[..cap_elems])) };

    // (6) SMAP write window — 단일 copy_nonoverlapping (Pitfall 2)
    let written_bytes = n.saturating_mul(core::mem::size_of::<HsmSlotInfo>());
    // SAFETY: out_ptr dual-check 통과; written_bytes ≤ HSM_MAX_SLOTS * 8
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            info_buf.as_ptr() as *const u8,
            out_ptr as *mut u8,
            written_bytes,
        );
        crate::cpu::clac();
    }

    cap.zeroize();
    n as u64
}
