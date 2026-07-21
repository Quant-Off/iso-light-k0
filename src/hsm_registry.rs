use constant_time::{Choice, CtEqOps, CtLess};
use mldsa::MLDSA44;
use zeroize::Zeroize;

use crate::bus::{BusDriver, BusInstance, BusKind, MAX_BUS_INIT_BLOB, WIRE_FRAME_MAX};
use crate::capability::{self, CapError};
use crate::syscall::{SyscallContext, SyscallError, is_user_address};

//
// 상수 / 컴파일-타임 불변식
//

pub const HSM_MAX_SLOTS: usize = 8;

// CHAN_MAX — sys_hsm_write / sys_hsm_relay 의 단일 호출 data 길이 한도 (D-13)  4 KiB BSS 풋프린트
pub const CHAN_MAX: usize = 4096; // PLANNER CHOICE Plan-02  ROADMAP SC #3 예시값  Phase 4 wire frame 도입 시 재검토
const _: () = assert!(CHAN_MAX > 0);
const _: () = assert!(CHAN_MAX <= 65536);

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
    pub const RELAY_SRC: Self = Self(1 << 3); // Phase 3 active (handle_attach 사용 개시)
    pub const RELAY_DST: Self = Self(1 << 4); // Phase 3 active (handle_attach 사용 개시)
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
    // Phase 2: bus.open(init_blob) 실패 (D-16 all-or-nothing).
    BadInit,
    // Phase 5 D-11 4 mldsa Error variants + Ok(false) 단일 collapse, syscall 경계 SyscallError Denied 로 변환
    AttestFailed,
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
    pub bus: BusInstance,
    // Phase 5 D-14 verify gate 결과 코드 0=Ok 1=AttestFailed 2..=255=reserved
    pub verify_result_code: u8,
    // Phase 5 D-14 BLAKE3(pk) 첫 4 옥텟 audit + enumerate 노출
    pub pk_hash_prefix: [u8; 4],
}

impl HsmSlot {
    pub const fn new() -> Self {
        Self {
            state: HsmSlotState::Empty,
            token: 0,
            rights: HsmRights::NONE,
            bus: BusInstance::new_empty(),
            verify_result_code: 0,
            pk_hash_prefix: [0u8; 4],
        }
    }
}

impl Zeroize for HsmSlot {
    fn zeroize(&mut self) {
        // 비밀(토큰) 먼저 소거 — 관찰자가 Detaching 상태에서 본문을 읽어도 키 자료는 이미 0
        self.token.zeroize();
        // Phase 2 cascade: BusInstance 의 활성 variant payload 를 비우고 Empty 로 reset (D-11).
        self.bus.zeroize();
        self.rights = HsmRights::NONE;
        // Phase 5 D-14 verify audit 흔적 0 으로 복귀 detach 후 재사용 시 잔재 차단
        self.verify_result_code = 0;
        self.pk_hash_prefix = [0u8; 4];
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

    // Phase 3 syscall 슬롯 bus 접근자  handle_write / handle_relay 가 USE / RELAY_SRC / RELAY_DST
    // 인증 통과 후 slot.bus.read / write 호출하기 위해 release 빌드에서도 활성.
    // Phase 2 boot smoke (T-02-03 observability) 진입점도 동일 메서드 공용.
    pub fn slot_bus_mut(&mut self, idx: usize) -> Option<&mut BusInstance> {
        if idx >= HSM_MAX_SLOTS {
            return None;
        }
        Some(&mut self.slots[idx].bus)
    }

    // SAFETY contract (D-09, D-12): BSP single-core; CAP_DRBG must be initialized
    // via capability::init_prng() before this is entered.
    // Phase 5 D-10 시그니처 확장 attest_payload Some 시 token gen 이전 verify gate atomicity 보장
    pub unsafe fn attach(
        &mut self,
        bus_kind: BusKind,
        init_blob: &[u8],
        attest_payload: Option<&[u8]>,
        rights: HsmRights,
    ) -> Result<HsmCapability, HsmCapError> {
        // Phase 5 D-10 verify gate token gen 이전 위치 RESEARCH 6.2 atomicity 슬롯 mutation 0
        // Some 분기만 verify None 은 Phase 2 3 4 smoke 우회 보존
        let attest_ok: Option<[u8; 4]> = if let Some(payload) = attest_payload {
            // Phase 5 D-05 정확 len 검사 cast 안전성 invariant
            if payload.len() != MLDSA44::PK_LEN + MLDSA44::SIG_LEN {
                return Err(HsmCapError::AttestFailed);
            }
            // SAFETY pk 는 payload 의 첫 PK_LEN 옥텟 sig 는 그 뒤 SIG_LEN 옥텟 len 검사 통과 시 정렬 0 cast 안전
            let pk: &[u8; MLDSA44::PK_LEN] = unsafe {
                &*(payload.as_ptr() as *const [u8; MLDSA44::PK_LEN])
            };
            let sig: &[u8; MLDSA44::SIG_LEN] = unsafe {
                &*(payload.as_ptr().add(MLDSA44::PK_LEN) as *const [u8; MLDSA44::SIG_LEN])
            };
            // Pitfall 7 AttestError 4 variants 모두 HsmCapError AttestFailed 로 collapse
            crate::hsm_attest::verify_attest(pk, bus_kind, sig)
                .map_err(|_| HsmCapError::AttestFailed)?;
            // verify 통과 시 audit 노출 prefix 산출 caller 가 commit 직전 슬롯에 기록
            Some(crate::hsm_attest::pk_hash_prefix(pk))
        } else {
            None
        };

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
                // D-16: 슬롯 mutation 전에 stack-local bus 생성 → bus.open() 실패 시 슬롯 변경 0 (all-or-nothing).
                let mut bus = BusInstance::new(bus_kind);
                // Pitfall 7: BusError 의 모든 variant 를 HsmCapError::BadInit 으로 collapse.
                match bus.open(init_blob) {
                    Ok(()) => {}
                    Err(_) => return Err(HsmCapError::BadInit),
                }
                // D-16 commit: bus → token → rights → state 순 (Phase 1 B-4 ordering 일관).
                slot.bus = bus;
                slot.token = token;
                slot.rights = rights;
                // Phase 5 D-14 verify gate 통과 시 audit 흔적 기록 None 분기는 default 유지
                if let Some(prefix) = attest_ok {
                    slot.verify_result_code = 0;
                    slot.pk_hash_prefix = prefix;
                }
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
        // D-17: bus.close() best-effort (결과 무시) — zeroize 가 어떤 경우라도 cascade 로 BusInstance 비움.
        let _ = slot.bus.close();
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
// RELAY_BUF — sys_hsm_relay / sys_hsm_write 의 단일 인스턴스 staging buffer (D-13)
//
// D-13: Option B per RESEARCH §Risk #1  raw [u8; CHAN_MAX] + 명시 zeroize
// Option B per RESEARCH §Open Q Risk #1  raw [u8; CHAN_MAX] + 명시 zeroize
// Reason  Secret<T> 의 Drop 은 static lifetime 으로 절대 호출되지 않으므로 명시 zeroize 가 유일 보장
// (zeroize::Zeroize for [u8; N] 는 volatile_write + memory_barrier 보장 — RESEARCH §zeroize)
// BSP single-core + FMASK 재진입 차단 가정  SMP 도입 시 per-core RELAY_BUF 또는 spinlock 필요
pub static mut RELAY_BUF: [u8; CHAN_MAX] = [0u8; CHAN_MAX];

/// RELAY_BUF 에 대한 안전 래퍼  진입+이탈 양면 zeroize 보장 (D-14)
///
/// # Safety
/// BSP single-core 진입점에서만 호출 가능  FMASK 재진입 차단으로 syscall dispatch 의 단일 진입을 invariant 로 가정
/// SMP 도입 시 per-core RELAY_BUF 또는 spinlock 필요 (Pitfall 6)
pub unsafe fn with_relay_buf<R>(f: impl FnOnce(&mut [u8; CHAN_MAX]) -> R) -> R {
    // SAFETY: BSP single-core; with_registry_mut 와 동일 invariant
    let buf = unsafe { &mut *(&raw mut RELAY_BUF) };
    // D-14 entry zeroize  이전 호출자 잔재 차단 (Pitfall 4 pre-entry)
    buf.zeroize();
    let r = f(buf);
    // D-14 exit zeroize  다음 호출자 진입 안전 + 본 호출 결과 청결
    buf.zeroize();
    r
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
                    // D-19: _reserved[0] = BusKind octet (HsmSlotInfo 8 바이트 ABI 불변).
                    // D-14: _reserved[1] = verify_result_code, _reserved[2..6] = pk_hash_prefix 4 octet
                    _reserved: {
                        let mut r = [0u8; 6];
                        r[0] = slot.bus.kind() as u8;
                        r[1] = slot.verify_result_code;
                        r[2..6].copy_from_slice(&slot.pk_hash_prefix);
                        r
                    },
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
pub unsafe fn attach_kernel_side(bus_kind: BusKind, init_blob: &[u8], rights: HsmRights) -> Result<HsmCapability, HsmCapError> {
    // SAFETY: BSP single-core; with_registry_mut 의 invariant 위임
    // Phase 5 D-10 None 전달 verify gate 우회 Phase 2 3 4 smoke 호환성 보존
    unsafe { with_registry_mut(|r| r.attach(bus_kind, init_blob, None, rights)) }
}

/// Phase 5 attestation gate 통과 후에만 슬롯에 부착하는 boot smoke 진입점
///
/// `attach_kernel_side` 의 None 분기 sibling Some(attest_payload) 전달로 verify gate 강제
/// Plan 05-04 host sibling test 와 향후 Phase 5 통합 smoke 가 호출
///
/// # Safety
/// BSP 단일 코어 capability init_prng 완료 가정 attest_payload 는 정확 3732 옥텟 pk 1312 sig 2420 직렬화
pub unsafe fn attach_kernel_side_with_attest(
    bus_kind: BusKind,
    init_blob: &[u8],
    attest_payload: &[u8],
    rights: HsmRights,
) -> Result<HsmCapability, HsmCapError> {
    // SAFETY BSP single-core with_registry_mut 의 invariant 위임 Some 전달로 attach 본문 verify gate 활성
    unsafe { with_registry_mut(|r| r.attach(bus_kind, init_blob, Some(attest_payload), rights)) }
}

//
// syscall 핸들러 — D-10 매핑 + Pitfall 1/2/3/4/7 강제
//

pub fn handle_attach(ctx: &mut SyscallContext) -> u64 {
    // Phase 0: D-15 register snapshot — rdi=BusKind, rsi=init_ptr, rdx=init_len, r8=out_ptr.
    let bus_kind_raw = ctx.arg0;
    let init_ptr = ctx.arg1;
    let init_len = ctx.arg2;
    let out_ptr = ctx.arg4;
    // Phase 5 D-04 attest payload register snapshot r10 ptr r9 len
    let attest_ptr = ctx.arg3;
    let attest_len = ctx.arg5;

    // Phase 1: T-02-04: Usb..SmartCard stub variants 거부 — BusInstance::new() 에 도달 0
    // Phase 6 GAP D-01 D-02 Network=6 cfg-split tls-external 분기 NETWORK_CAP_STATE Taken 검증
    // closed 분기 audit_enqueue + SyscallError::Denied 5 NetworkDenied 콜럐스 단일 RAX 잠금
    let bus_kind: BusKind = match bus_kind_raw {
        0 => BusKind::Software,
        1 => BusKind::Ring3Process,
        #[cfg(feature = "tls-external")]
        6 => {
            // Phase 6 D-02 NETWORK_ATTACH cap state-only 검증 (Open Q2 in-plan state-only 결정)
            // SAFETY BSP single-core init_network_cap 호출 완료 가정 NETWORK_CAP_STATE 단일 read
            let cap_taken = unsafe {
                (&raw const crate::air_gap::NETWORK_CAP_STATE).read()
                    == crate::air_gap::NetCapState::Taken
            };
            if !cap_taken {
                // 5 NetworkDenied 콜럐스 두번째 카테고리 cap-less 호출 (D-01)
                // slot_idx=0xFF 미할당 result=2 NetworkDenied bus_kind=6 Network pk=[0u8;4]
                crate::hsm_attest::audit_enqueue(0xFF, 2, 6, [0u8; 4]);
                return SyscallError::Denied.as_rax();
            }
            BusKind::Network
        }
        #[cfg(not(feature = "tls-external"))]
        6 => {
            // closed 빌드 거부 경로 (D-01 첫번째 카테고리 closed-build 우발 진입)
            // matchless `_` arm 대신 명시 6 arm Pitfall 7 일관 Denied collapse
            crate::hsm_attest::audit_enqueue(0xFF, 2, 6, [0u8; 4]);
            return SyscallError::Denied.as_rax();
        }
        2..=5 => return SyscallError::BadArg.as_rax(),
        _ => return SyscallError::BadArg.as_rax(),
    };

    // Phase 2: init_len sanity (Pitfall 6 — honest overflow).
    if init_len > MAX_BUS_INIT_BLOB as u64 {
        return SyscallError::BadArg.as_rax();
    }
    // Phase 5 D-05 attest_len 정확 3732 옥텟 sanity input 독립 early-return
    const ATTEST_EXACT: u64 = (MLDSA44::PK_LEN + MLDSA44::SIG_LEN) as u64;
    if attest_len != ATTEST_EXACT {
        return SyscallError::BadArg.as_rax();
    }

    // Phase 3: pointer dual range checks (Pitfall 3).
    // init_ptr: length-aware — init_len == 0 (SoftwareBus 빈 init_blob 허용 — D-10) 면 deref 0.
    if init_len > 0
        && (!is_user_address(init_ptr) || !is_user_address(init_ptr.saturating_add(init_len)))
    {
        return SyscallError::BadAddress.as_rax();
    }
    // out_ptr: unconditional (cap-sized).
    let cap_size = core::mem::size_of::<HsmCapability>() as u64;
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }
    // Phase 5 D-05 attest_ptr dual-range Pitfall 3 일관 attest_len 은 ATTEST_EXACT 로 고정
    if !is_user_address(attest_ptr) || !is_user_address(attest_ptr.saturating_add(attest_len)) {
        return SyscallError::BadAddress.as_rax();
    }

    // Phase 4: stack staging buffer (Pitfall 4: stack-local 32B 버퍼. 함수 종료 직전 zeroize).
    let mut init_kbuf = [0u8; MAX_BUS_INIT_BLOB];

    // Phase 5: SMAP-1 read window — init_blob copy 만 stac/clac 윈도우 안 (Pitfall 2).
    if init_len > 0 {
        // SAFETY: init_ptr / init_ptr+init_len 모두 user range 통과 (Phase 3); init_kbuf 는 stack-local.
        unsafe {
            crate::cpu::stac();
            core::ptr::copy_nonoverlapping(
                init_ptr as *const u8,
                init_kbuf.as_mut_ptr(),
                init_len as usize,
            );
            crate::cpu::clac();
        }
    }

    // Phase 5 SMAP-2 별개 윈도우 with_attest_buf closure 안 single stac clac
    // closure 가 SMAP-2 copy + attach 호출 + audit prefix 산출 모두 수행 borrow escape 방지
    // closure 반환은 (attach_result, pk_prefix) tuple closure 밖에서 RAX 매핑 + audit_enqueue
    let init_slice: &[u8] = &init_kbuf[..init_len as usize];
    let (attach_result, pk_prefix): (Result<HsmCapability, HsmCapError>, [u8; 4]) = unsafe {
        crate::hsm_attest::with_attest_buf(|abuf| {
            // SMAP-2 안 single copy attest_payload user -> ATTEST_BUF
            crate::cpu::stac();
            core::ptr::copy_nonoverlapping(
                attest_ptr as *const u8,
                abuf.as_mut_ptr(),
                attest_len as usize,
            );
            crate::cpu::clac();
            let payload_slice: &[u8] = &abuf[..attest_len as usize];
            // pk_prefix audit 노출 prefix attest_payload 의 첫 PK_LEN 옥텟 BLAKE3
            let pk_ref: &[u8; MLDSA44::PK_LEN] =
                &*(payload_slice.as_ptr() as *const [u8; MLDSA44::PK_LEN]);
            let prefix = crate::hsm_attest::pk_hash_prefix(pk_ref);
            // Phase 6 delegate D-10 Some(payload_slice) 전달로 verify gate 활성
            // SAFETY BSP single-core capability init_prng 완료 가정
            let result = with_registry_mut(|r| {
                r.attach(
                    bus_kind,
                    init_slice,
                    Some(payload_slice),
                    // Phase 3 Risk #7  RELAY_SRC/RELAY_DST 비트 활성화  Phase 1 D-03 reserved 비트 사용 개시
                    HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE | HsmRights::RELAY_SRC | HsmRights::RELAY_DST,
                )
            });
            (result, prefix)
        })
    };

    // Phase 6: D-16 all-or-nothing 분기 + D-13 audit_enqueue 성공 실패 모두 기록
    // Pitfall 7: BusError → HsmCapError → SyscallError 3 단계 collapse.
    let cap = match attach_result {
        Ok(c) => {
            // D-13 성공 audit slot_idx 정확 result 0 bus_kind octet pk_prefix
            crate::hsm_attest::audit_enqueue(c.slot.0, 0, bus_kind as u8, pk_prefix);
            c
        }
        Err(HsmCapError::AttestFailed) => {
            // D-13 실패 audit slot 0xFF 미할당 표시 result 1 Pitfall 4 stack zeroize 모든 경로
            crate::hsm_attest::audit_enqueue(0xFF, 1, bus_kind as u8, pk_prefix);
            init_kbuf.zeroize();
            // Pitfall 7 AttestFailed → Denied 단일 collapse mldsa Error variants 누설 0
            return SyscallError::Denied.as_rax();
        }
        Err(HsmCapError::Full) => {
            init_kbuf.zeroize();
            return SyscallError::BadArg.as_rax();
        }
        Err(HsmCapError::BadInit) => {
            init_kbuf.zeroize();
            return SyscallError::BadArg.as_rax();
        }
        Err(_) => {
            init_kbuf.zeroize();
            return SyscallError::Internal.as_rax();
        }
    };

    // Phase 7: SMAP write window — cap copy to out_ptr (별도 stac/clac, Pitfall 2).
    // SAFETY: out_ptr 는 사용자 주소 dual-check 통과 (Phase 3); copy 폭은 HsmCapability ABI 크기.
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            &cap as *const HsmCapability as *const u8,
            out_ptr as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // Phase 8: final zeroize (Pitfall 4 — happy path stack staging clean) + RAX=0 success.
    // ATTEST_BUF zeroize 는 with_attest_buf exit zeroize 가 자동 보장 본 phase 별도 wipe 0
    init_kbuf.zeroize();
    0
}

pub fn handle_detach(ctx: &mut SyscallContext) -> u64 {
    let in_ptr = ctx.arg0;
    let user_cap_size = ctx.arg2;

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
    let cap_ptr = ctx.arg0;
    let out_ptr = ctx.arg1;
    let count = ctx.arg2;

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

// handle_write — sys_hsm_write 핸들러 (D-02 / CHAN-01)  USE cap 검증 + user data SMAP copy → slot.bus.write
//
// ABI (D-02):  rdi = cap_ptr (16B HsmCapability)
//              rsi = data_ptr (user-space)
//              rdx = data_len (≤ CHAN_MAX, > 0)
//
// 6-step shape (handle_detach 미러):
//   (1) data_len CT 범위 (0 < data_len ≤ CHAN_MAX  CtLess::lt / CtEqOps::ne — Pitfall 2)
//   (2) (cap_ptr, 16B) + (data_ptr, data_len) dual-range (Pitfall 3)
//   (3) SMAP-1 cap copy (단일 stac/clac, Pitfall 2)
//   (4) authenticate(USE) (Pitfall 1) — 실패 시 cap.zeroize + Denied
//   (5) with_relay_buf 진입 → SMAP-2 data copy → slot.bus.write
//   (6) Pitfall 4 cap.zeroize  Pitfall 7 BusError → Internal collapse
pub fn handle_write(ctx: &mut SyscallContext) -> u64 {
    let cap_ptr_va = ctx.arg0;
    let data_ptr_va = ctx.arg1;
    let data_len = ctx.arg2 as usize;

    // (1) data_len ∈ (0, CHAN_MAX]  CT 분기 (CtLess::lt / CtEqOps::ne) — '<' / '==' direct 금지 (Pitfall 2 CT)
    //     상한은 CHAN_MAX 포함  D-13 4 KiB 정확 등호도 허용  CtLess::lt(&len, &(CHAN_MAX+1)) 로 ≤ CHAN_MAX 표현
    let lt_max: u8 = CtLess::lt(&data_len, &(CHAN_MAX + 1)).unwrap_u8();
    let nonzero: u8 = CtEqOps::ne(&data_len, &0usize).unwrap_u8();
    if (lt_max & nonzero) != 1 {
        return SyscallError::BadArg.as_rax();
    }

    // (2) user-pointer dual range check (Pitfall 3)  is_user_address 는 u64 인자
    let cap_size = core::mem::size_of::<HsmCapability>() as u64;
    if !is_user_address(cap_ptr_va) || !is_user_address(cap_ptr_va.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }
    if !is_user_address(data_ptr_va)
        || !is_user_address(data_ptr_va.saturating_add(data_len as u64))
    {
        return SyscallError::BadAddress.as_rax();
    }

    // (3) SMAP-1 cap copy — 단일 stac/clac 윈도우 (Pitfall 2)
    let mut cap = HsmCapability::invalid();
    // SAFETY: cap_ptr_va dual-range 검증 통과  copy 폭은 HsmCapability ABI 크기 (16B)
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            cap_ptr_va as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (4) USE 인증 (Pitfall 1)  실패 시 RELAY_BUF 미진입 + cap zeroize 후 Denied
    // SAFETY: BSP single-core
    let auth_ok = unsafe { with_registry(|r| r.authenticate(&cap, HsmRights::USE)) };
    if !auth_ok {
        cap.zeroize();
        return SyscallError::Denied.as_rax();
    }

    // (5) with_relay_buf 진입  SMAP-2 data copy → slot.bus.write
    //     RELAY_BUF 은 with_relay_buf 의 진입+이탈 양면 zeroize (D-14) 가 보장
    let slot_idx = cap.slot.0 as usize;
    // SAFETY: BSP single-core; with_relay_buf + with_registry_mut 는 disjoint static borrow
    let closure_result: Result<(), SyscallError> = unsafe {
        with_relay_buf(|buf| {
            // SMAP-2 — user data → RELAY_BUF (단일 stac/clac, Pitfall 2)
            // SAFETY: data_ptr_va dual-range 통과 + data_len ≤ CHAN_MAX
            crate::cpu::stac();
            core::ptr::copy_nonoverlapping(
                data_ptr_va as *const u8,
                buf.as_mut_ptr(),
                data_len,
            );
            crate::cpu::clac();
            // slot.bus.write 는 with_registry_mut 안에서 (PATTERNS A-2 borrow disjoint)
            with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
                Some(bus) => match bus.write(&buf[..data_len]) {
                    Ok(_n) => Ok(()),
                    // Pitfall 7  BusError 전 variant 를 Internal 로 collapse
                    Err(_) => Err(SyscallError::Internal),
                },
                None => Err(SyscallError::Internal),
            })
        })
    };

    // (6) cap zeroize (Pitfall 4) — 모든 경로 마지막 단계
    cap.zeroize();
    match closure_result {
        Ok(()) => 0u64,
        Err(SyscallError::Internal) => SyscallError::Internal.as_rax(),
        Err(_) => SyscallError::Internal.as_rax(),
    }
}

// handle_relay — sys_hsm_relay 핸들러 (D-03 / CHAN-01)  ZERO user data pointer  kernel-internal transfer 전용
//
// ABI (D-03):  rdi = src_cap_ptr (16B)
//              rsi = dst_cap_ptr (16B)
//              rdx = byte_len (≤ CHAN_MAX, > 0)
//
// 6-step shape:
//   (1) byte_len CT 범위 (0 < byte_len ≤ CHAN_MAX)
//   (2) (src_cap_ptr, 16B) + (dst_cap_ptr, 16B) dual-range (Pitfall 3)  data ptr 없음 (CHAN-01)
//   (3) SMAP-1 src_cap + SMAP-2 dst_cap (두 개 분리 윈도우, Pitfall 2)
//   (4) Dual authenticate  (src_ok as u8) & (dst_ok as u8)  bitand  Pitfall 1 (&& 절대 금지)
//   (5) with_relay_buf 진입 → src.read → dst.write atomic (D-20/D-21 CtEqOps::eq)
//   (6) src_cap + dst_cap zeroize (Pitfall 4) + Pitfall 7 collapse
pub fn handle_relay(ctx: &mut SyscallContext) -> u64 {
    let src_cap_ptr_va = ctx.arg0;
    let dst_cap_ptr_va = ctx.arg1;
    let byte_len = ctx.arg2 as usize;

    // (1) byte_len ∈ (0, CHAN_MAX]  CT 분기 (CtLess::lt / CtEqOps::ne)
    let lt_max: u8 = CtLess::lt(&byte_len, &(CHAN_MAX + 1)).unwrap_u8();
    let nonzero: u8 = CtEqOps::ne(&byte_len, &0usize).unwrap_u8();
    if (lt_max & nonzero) != 1 {
        return SyscallError::BadArg.as_rax();
    }

    // (2) 두 cap 포인터 dual-range (Pitfall 3)  data pointer 없음 (CHAN-01 핵심 보장)
    let cap_size = core::mem::size_of::<HsmCapability>() as u64;
    if !is_user_address(src_cap_ptr_va)
        || !is_user_address(src_cap_ptr_va.saturating_add(cap_size))
    {
        return SyscallError::BadAddress.as_rax();
    }
    if !is_user_address(dst_cap_ptr_va)
        || !is_user_address(dst_cap_ptr_va.saturating_add(cap_size))
    {
        return SyscallError::BadAddress.as_rax();
    }

    // (3) SMAP-1 src_cap + SMAP-2 dst_cap  두 분리 stac/clac 윈도우 (Pitfall 2)
    let mut src_cap = HsmCapability::invalid();
    let mut dst_cap = HsmCapability::invalid();
    // SAFETY: src_cap_ptr_va dual-range 통과  16B copy
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            src_cap_ptr_va as *const u8,
            &mut src_cap as *mut HsmCapability as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }
    // SAFETY: dst_cap_ptr_va dual-range 통과  16B copy
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            dst_cap_ptr_va as *const u8,
            &mut dst_cap as *mut HsmCapability as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (4) Dual-cap authenticate CT-AND  bitand 사용  short-circuit (&&) 금지
    //     양쪽 authenticate 가 무조건 실행되어야 D-18 변이 누설 0 유지
    // SAFETY: BSP single-core
    let src_ok = unsafe { with_registry(|r| r.authenticate(&src_cap, HsmRights::RELAY_SRC)) };
    // SAFETY: BSP single-core
    let dst_ok = unsafe { with_registry(|r| r.authenticate(&dst_cap, HsmRights::RELAY_DST)) };
    // 어느 한쪽 fail 도 Denied 단일 매핑 (D-18)  variant 누설 0
    let both_ok: u8 = (src_ok as u8) & (dst_ok as u8);
    if both_ok != 1 {
        src_cap.zeroize();
        dst_cap.zeroize();
        return SyscallError::Denied.as_rax();
    }

    // (5) with_relay_buf 진입 → src.read → dst.write atomic
    //     D-20/D-21  CtEqOps::eq 로 returned/accepted 가 byte_len 과 일치하지 않으면 Internal
    let src_slot = src_cap.slot.0 as usize;
    let dst_slot = dst_cap.slot.0 as usize;
    // SAFETY: BSP single-core; with_relay_buf + with_registry_mut 는 disjoint static borrow
    let closure_result: Result<(), SyscallError> = unsafe {
        with_relay_buf(|buf| {
            with_registry_mut(|r| {
                // src.read  destructive read of src.ring → buf[..byte_len]
                let n = match r.slot_bus_mut(src_slot) {
                    Some(bus) => match bus.read(&mut buf[..byte_len]) {
                        Ok(n) => n,
                        // Pitfall 7  BusError → Internal
                        Err(_) => return Err(SyscallError::Internal),
                    },
                    None => return Err(SyscallError::Internal),
                };
                // D-20  atomic relay  CtEqOps::eq 로 partial 거부
                if CtEqOps::eq(&n, &byte_len).unwrap_u8() != 1 {
                    return Err(SyscallError::Internal);
                }
                // dst.write  buf[..byte_len] → dst.ring
                let m = match r.slot_bus_mut(dst_slot) {
                    Some(bus) => match bus.write(&buf[..byte_len]) {
                        Ok(m) => m,
                        Err(_) => return Err(SyscallError::Internal),
                    },
                    None => return Err(SyscallError::Internal),
                };
                // D-21  atomic relay  CtEqOps::eq 로 accepted 가 byte_len 과 일치 보장
                if CtEqOps::eq(&m, &byte_len).unwrap_u8() != 1 {
                    return Err(SyscallError::Internal);
                }
                Ok(())
            })
        })
    };

    // (6) 두 cap zeroize (Pitfall 4) + Pitfall 7 variant collapse
    src_cap.zeroize();
    dst_cap.zeroize();
    match closure_result {
        Ok(()) => 0u64,
        Err(_) => SyscallError::Internal.as_rax(),
    }
}

/// sys_hsm_read syscall 핸들러 — USE cap 으로 Ring3ProcessBus 의 pending wire frame 회수 (D-06)
///
/// # ABI
/// `rdi` cap_ptr 16B HsmCapability
/// `rsi` out_ptr 사용자 공간 회수 버퍼
/// `rdx` out_len 16..=WIRE_FRAME_MAX
///
/// # Errors
/// `SyscallError::BadArg` out_len 범위 위반
/// `SyscallError::BadAddress` cap_ptr 또는 out_ptr 가 사용자 영역 외부
/// `SyscallError::Denied` authenticate USE 실패
/// `SyscallError::Internal` BusError 전 variant collapse (Pitfall 7)
///
/// 7-step shape (handle_detach SMAP-1 + handle_enumerate SMAP-2 + handle_write authenticate 합성):
///   (1) Argument 추출
///   (2) out_len CT 범위 검증 (16..=WIRE_FRAME_MAX, '<' / '==' 금지 — Pitfall 2 CT)
///   (3) dual range — cap_ptr + out_ptr 양쪽 16B / out_len 범위 (Pitfall 3)
///   (4) SMAP-1 cap copy (단일 stac/clac 윈도우, Pitfall 2)
///   (5) authenticate(USE) (Phase 1 CT-AND, Pitfall 1 early-return 없음)
///   (6) with_registry_mut → slot.bus.read(staging[..out_len]) — BusError 전 variant Internal collapse
///   (7) SMAP-2 staging → user out_ptr (별도 stac/clac 윈도우) + 모든 exit path zeroize
pub fn handle_read(ctx: &mut SyscallContext) -> u64 {
    // (1) Argument 추출
    let cap_ptr_va = ctx.arg0;
    let out_ptr_va = ctx.arg1;
    let out_len = ctx.arg2 as usize;

    // (2) out_len ∈ [16, WIRE_FRAME_MAX] CT 분기 — handle_write line 707-708 패턴 일관
    //     ge_min  CtLess::lt(&15, &out_len)  ↔  out_len > 15  ↔  out_len ≥ 16
    //     lt_max  CtLess::lt(&out_len, &(WIRE_FRAME_MAX + 1))  ↔  out_len ≤ WIRE_FRAME_MAX
    let lt_max: u8 = CtLess::lt(&out_len, &(WIRE_FRAME_MAX + 1)).unwrap_u8();
    let ge_min: u8 = CtLess::lt(&15usize, &out_len).unwrap_u8();
    if (lt_max & ge_min) != 1 {
        return SyscallError::BadArg.as_rax();
    }

    // (3) dual range — cap_ptr 16B + out_ptr 의 out_len byte 양쪽 (Pitfall 3)
    let cap_size = core::mem::size_of::<HsmCapability>() as u64;
    if !is_user_address(cap_ptr_va) || !is_user_address(cap_ptr_va.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }
    if !is_user_address(out_ptr_va) || !is_user_address(out_ptr_va.saturating_add(out_len as u64))
    {
        return SyscallError::BadAddress.as_rax();
    }

    // (4) SMAP-1 cap copy — 단일 stac/clac 윈도우 (Pitfall 2, handle_detach line 588-598 미러)
    let mut cap = HsmCapability::invalid();
    // SAFETY: cap_ptr_va dual-range 검증 통과  copy 폭은 HsmCapability ABI 크기 16B
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            cap_ptr_va as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            core::mem::size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (5) USE 인증 (Pitfall 1)  실패 시 user out 버퍼 미접근 + cap zeroize 후 Denied
    // SAFETY: BSP single-core
    let auth_ok = unsafe { with_registry(|r| r.authenticate(&cap, HsmRights::USE)) };
    if !auth_ok {
        cap.zeroize();
        return SyscallError::Denied.as_rax();
    }

    // (6) staging + slot.bus.read — stack-local [u8; WIRE_FRAME_MAX]
    //     RELAY_BUF 와 책임 분리 (RELAY_BUF 는 ingress write/relay 전용 D-13)
    //     out_len ≤ WIRE_FRAME_MAX 가 step 2 에서 보장됨
    let slot_idx = cap.slot.0 as usize;
    let mut staging = [0u8; WIRE_FRAME_MAX];
    // SAFETY: BSP single-core
    let read_result = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => bus.read(&mut staging[..out_len]),
            None => Err(crate::bus::BusError::Internal),
        })
    };
    let bytes_read = match read_result {
        Ok(n) => n,
        Err(_) => {
            // Pitfall 7  BusError 의 NotOpen / WireNotReady / BufferTooSmall / Internal 전 variant collapse
            cap.zeroize();
            staging.zeroize();
            return SyscallError::Internal.as_rax();
        }
    };

    // (7) SMAP-2 staging → user out_ptr  별도 stac/clac 윈도우 (Pitfall 2, handle_enumerate line 670-680 미러)
    // SAFETY: out_ptr_va dual-range 검증 통과 (step 3)  bytes_read ≤ out_len ≤ WIRE_FRAME_MAX
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(staging.as_ptr(), out_ptr_va as *mut u8, bytes_read);
        crate::cpu::clac();
    }

    // 모든 exit path zeroize (SH-3)  Ok path 도 cap + staging 명시 소거
    cap.zeroize();
    staging.zeroize();
    bytes_read as u64
}
