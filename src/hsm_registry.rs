use constant_time::Choice;
use constant_time::traits::{CtEqOps, CtLess};
use mldsa::MLDSA44;
use zeroize::Zeroize;

use crate::bus::{BusDriver, BusInstance, BusKind, MAX_BUS_INIT_BLOB, WIRE_FRAME_MAX};
use crate::capability::{self, CapError};
use crate::syscall::{SyscallContext, SyscallError, is_user_address};

//
// 상수 / 컴파일-타임 불변식
//

pub const HSM_MAX_SLOTS: usize = 8;

// CHAN_MAX 는 sys_hsm_write 와 sys_hsm_relay 의 단일 호출 data 길이 한도 4 KiB BSS 풋프린트
pub const CHAN_MAX: usize = 4096; // wire frame 도입 시 재검토 여지가 있는 예시값
const _: () = assert!(CHAN_MAX > 0);
const _: () = assert!(CHAN_MAX <= 65536);

// HsmCapability 의 ABI 정렬 크기는 16바이트 (u64 정렬 강제, `Capability` 와 동일)
// 16 옥텟 전부를 가시 필드로 채워 implicit padding 0 으로 Ring0 에서 Ring3 로의 info-leak 봉쇄
// 레이아웃 token(0..8) + slot(8) + _pad0(9) + rights(10..12) + _pad(12) + _pad1(13..16)
// `#[repr(C, packed)]` 미사용, 필드 참조 시 unaligned access 위험 회피
const _: () = assert!(size_of::<HsmCapability>() == 16);
const _: () = assert!(size_of::<HsmSlotState>() == 1);
const _: () = assert!(HSM_MAX_SLOTS == 8);

//
// HSM 슬롯 인덱스
//

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct HsmSlotIdx(pub u8);

impl HsmSlotIdx {
    pub const INVALID: Self = Self(0xFF);
}

//
// HSM 권한 비트 플래그 (비트 인덱스 0..5 잠금)
//

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct HsmRights(pub u16);

impl HsmRights {
    pub const NONE: Self = Self(0);
    pub const USE: Self = Self(1 << 0);
    pub const ENUMERATE: Self = Self(1 << 1);
    pub const REVOKE: Self = Self(1 << 2);
    pub const RELAY_SRC: Self = Self(1 << 3); // handle_attach 에서 사용
    pub const RELAY_DST: Self = Self(1 << 4); // handle_attach 에서 사용
    #[allow(dead_code)]
    pub const NETWORK_ATTACH: Self = Self(1 << 5); // 예약 비트
}

impl core::ops::BitOr for HsmRights {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        HsmRights(self.0 | rhs.0)
    }
}

//
// 슬롯 상태 머신 (재사용 가능한 3 state)
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HsmSlotState {
    Empty = 0,
    Attached = 1,
    Detaching = 2,
}

//
// 에러 종류 (gen_token_u64 표면용 TokenGen 포함)
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
    // bus.open(init_blob) 실패 (all-or-nothing)
    BadInit,
    // mldsa Error 4 variant 과 Ok(false) 를 단일 collapse, syscall 경계에서 SyscallError Denied 로 변환
    AttestFailed,
}

//
// HSM Capability 레이아웃
//

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct HsmCapability {
    pub token: u64,
    pub slot: HsmSlotIdx,
    // offset 9 의 align-pad 를 명시 필드로 흡수 (rights u16 정렬 보장)
    _pad0: u8,
    pub rights: HsmRights,
    _pad: u8,
    // trailing pad (offset 13..16) 를 명시 필드로 흡수, 16옥텟 전부 가시 필드
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

    // CT token-nonzero & slot-eq & rights-subset 를 single-branch 로 종료
    #[inline]
    pub fn is_valid_for(&self, slot: HsmSlotIdx, required: HsmRights) -> bool {
        let token_nonzero: Choice = CtEqOps::ct_ne(&self.token, &0u64);
        let slot_eq: Choice = CtEqOps::ct_eq(&self.slot.0, &slot.0);
        let masked: u16 = self.rights.0 & required.0;
        let rights_ok: Choice = CtEqOps::ct_eq(&masked, &required.0);

        (token_nonzero & slot_eq & rights_ok).unwrap_u8() == 1
    }

    #[inline]
    pub fn ct_token_eq(&self, other: &Self) -> Choice {
        CtEqOps::ct_eq(&self.token, &other.token)
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
// 슬롯 데이터 Drop 은 안전망이고 정상 detach 경로가 주 경로
//
// `Copy` 미파생, `Drop` 구현이 있으면 컴파일러가 E0184 로 거절함
// Drop 보장이 우선, 슬롯은 정적 풀 안에서만
// 존재하므로 값 복사 값 이동 요구가 없음 (배열 인덱싱 + &mut 만 사용)
pub struct HsmSlot {
    pub state: HsmSlotState,
    pub token: u64,
    pub rights: HsmRights,
    pub bus: BusInstance,
    // verify gate 결과 코드 0=Ok 1=AttestFailed 2..=255=reserved
    pub verify_result_code: u8,
    // BLAKE3(pk) 첫 4 옥텟, audit 와 enumerate 에 노출
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

impl Default for HsmSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for HsmSlot {
    fn zeroize(&mut self) {
        // 비밀(토큰) 먼저 소거, 관찰자가 Detaching 상태에서 본문을 읽어도 키 자료는 이미 0
        self.token.zeroize();
        // cascade BusInstance 의 활성 variant payload 를 비우고 Empty 로 reset
        self.bus.zeroize();
        self.rights = HsmRights::NONE;
        // verify audit 흔적 0 으로 복귀 detach 후 재사용 시 잔재 차단
        self.verify_result_code = 0;
        self.pk_hash_prefix = [0u8; 4];
        // 상태 전이는 가장 마지막
        self.state = HsmSlotState::Empty;
    }
}

impl Drop for HsmSlot {
    // SAFETY-net Drop 은 폴백이고 정상 detach 경로가 명시적으로 zeroize 를 먼저 호출함
    // panic = abort 환경에서는 unwind 가 Drop 을 트리거하지 않으므로 본 경로는 테스트
    // 및 향후 SMP 종료 시점 보호 목적
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// HSM 레지스트리 (static mut 와 안전 래퍼)
//

pub struct HsmRegistry {
    slots: [HsmSlot; HSM_MAX_SLOTS],
}

impl Default for HsmRegistry {
    fn default() -> Self {
        Self::new()
    }
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

    // syscall 슬롯 bus 접근자 handle_write 와 handle_relay 가 USE / RELAY_SRC / RELAY_DST
    // 인증 통과 후 slot.bus.read / write 호출하기 위해 release 빌드에서도 활성
    // boot smoke observability 진입점도 동일 메서드 공용
    pub fn slot_bus_mut(&mut self, idx: usize) -> Option<&mut BusInstance> {
        if idx >= HSM_MAX_SLOTS {
            return None;
        }
        Some(&mut self.slots[idx].bus)
    }

    /// HSM 슬롯에 bus 를 부착한다 attest_payload Some 시 token 생성 이전 verify gate 를 통과한다
    ///
    /// # Safety
    /// BSP single-core 에서만 호출 가능하다 `capability::init_prng` 완료를 호출자가
    /// 보장해야 한다 attest_payload Some 분기는 token gen 이전 verify gate atomicity 를 보장한다
    ///
    /// # Errors
    /// 어테스테이션 실패, 슬롯 부재, 토큰 생성 실패 시 `HsmCapError`
    pub unsafe fn attach(
        &mut self,
        bus_kind: BusKind,
        init_blob: &[u8],
        attest_payload: Option<&[u8]>,
        rights: HsmRights,
    ) -> Result<HsmCapability, HsmCapError> {
        // verify gate 를 token 생성 이전에 두어 atomicity 확보 슬롯 mutation 0
        // Some 분기만 verify None 분기는 smoke 우회 보존
        let attest_ok: Option<[u8; 4]> = if let Some(payload) = attest_payload {
            // 정확 len 검사 cast 안전성 invariant
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
            // AttestError 4 variant 모두 HsmCapError AttestFailed 로 collapse
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
                // before REGISTRY mutation entry. CAP_DRBG 는 단일 인스턴스
                let token = unsafe {
                    capability::gen_token_u64().map_err(|e| match e {
                        CapError::PrngNotInitialized => HsmCapError::TokenGen,
                        CapError::DrbgInit => HsmCapError::TokenGen,
                        CapError::NoEntropy => HsmCapError::TokenGen,
                        _ => HsmCapError::TokenGen,
                    })?
                };
                // 슬롯 mutation 전에 stack-local bus 생성 bus.open() 실패 시 슬롯 변경 0 (all-or-nothing)
                let mut bus = BusInstance::new(bus_kind);
                // BusError 의 모든 variant 를 HsmCapError::BadInit 으로 collapse
                match bus.open(init_blob) {
                    Ok(()) => {}
                    Err(_) => return Err(HsmCapError::BadInit),
                }
                // commit 순서 bus, token, rights, state (ordering 일관)
                slot.bus = bus;
                slot.token = token;
                slot.rights = rights;
                // verify gate 통과 시 audit 흔적 기록 None 분기는 default 유지
                if let Some(prefix) = attest_ok {
                    slot.verify_result_code = 0;
                    slot.pk_hash_prefix = prefix;
                }
                slot.state = HsmSlotState::Attached;
                // padding 까지 명시 0 (struct literal 이 모든 가시 필드 초기화)
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

    // cap 을 레지스트리와 대조 인증
    //
    // is_valid_for(cap.slot, ...) 은 user-supplied 필드끼리만 비교하므로 tautology 이고 본
    // 메서드만이 "슬롯에 저장된 진본 토큰 + 진본 rights" 와 비교, 세 검사를 CT-AND 로
    // 결합하여 early-return 없음 slot 인덱스 범위, slot 상태 Attached,
    // 토큰 일치, 저장된 rights ⊇ required, cap rights ⊇ required (둘 다 통과해야 함
    // 위조 cap 이 rights 비트를 임의로 세팅했더라도 슬롯이 발급한 권한을 넘지 못함)
    //
    // SAFETY: 호출자는 &self 만 빌려주므로 BSP single-core 가정만 충족하면 됨
    pub fn authenticate(&self, cap: &HsmCapability, required: HsmRights) -> bool {
        let idx = cap.slot.0 as usize;
        // slot index out of range 이면 cap 합성 자체가 의미 없음 단 CT 평면화를 위해 가짜
        // cap_in_slot 으로 비교는 끝까지 수행하고 마지막에 in_range 비트로 AND
        let in_range = idx < HSM_MAX_SLOTS;
        let safe_idx = if in_range { idx } else { 0 };
        let slot = &self.slots[safe_idx];

        let state_ok: Choice = CtEqOps::ct_eq(&(slot.state as u8), &(HsmSlotState::Attached as u8));

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
        let stored_rights_ok: Choice = CtEqOps::ct_eq(&stored_masked, &required.0);
        // cap rights ⊇ required (요청자가 명시한 권한이 부족하면 거부, REVOKE 비트 누락 차단)
        let cap_masked: u16 = cap.rights.0 & required.0;
        let cap_rights_ok: Choice = CtEqOps::ct_eq(&cap_masked, &required.0);
        // 토큰 != 0 (invalid cap 사전 차단)
        let token_nonzero: Choice = CtEqOps::ct_ne(&cap.token, &0u64);

        let all_ct = token_nonzero & state_ok & token_eq & stored_rights_ok & cap_rights_ok;
        // CT-AND 결과를 마지막에만 bool in_range 와 결합 (in_range 가 false 면 결과 false)
        (all_ct.unwrap_u8() == 1) & in_range
    }

    /// capability 인증 후 HSM 슬롯을 detach 하고 zeroize 한다
    ///
    /// # Safety
    /// BSP single-core 에서만 호출 가능하다 `required` rights 미보유 시 거부한다
    ///
    /// # Errors
    /// 인증 실패, 슬롯 범위 초과, 상태 불일치 시 `HsmCapError`
    pub unsafe fn detach(
        &mut self,
        cap: &HsmCapability,
        required: HsmRights,
    ) -> Result<(), HsmCapError> {
        // (1) CT 인증 슬롯에 저장된 진본 토큰과 저장된 rights, cap rights 동시 검증
        if !self.authenticate(cap, required) {
            // syscall 경계에서 Denied 로 collapse 되므로 어떤 실패 사유이든 InvalidToken 반환
            // (variant 노출 최소화) idx 가 범위 밖이면 별도 처리도 동일 매핑
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
        // (2) 인증 통과 Attached 상태 보장됨
        let idx = cap.slot.0 as usize;
        let slot = &mut self.slots[idx];
        // 명시적 Detaching 윈도우 in-flight 호출자가 stale token 으로
        // 본 슬롯을 다시 잡으면 Busy 거부됨
        slot.state = HsmSlotState::Detaching;
        // bus.close() best-effort (결과 무시) zeroize 가 어떤 경우라도 cascade 로 BusInstance 비움
        let _ = slot.bus.close();
        // 명시적 소거 (Drop 폴백이 아닌 주 경로) zeroize 가 state 를 Empty 로 되돌림
        slot.zeroize();
        Ok(())
    }
}

//
// 전역 싱글턴 (capability.rs 와 ipc.rs 패턴 일관)
//

pub static mut REGISTRY: HsmRegistry = HsmRegistry::new();

/// 전역 REGISTRY 에 대한 불변 참조로 클로저를 실행한다
///
/// # Safety
/// BSP single-core syscall dispatch 가 유일 진입점이며 FMASK 로 preempt 가 비활성이라고 가정한다
pub unsafe fn with_registry<R>(f: impl FnOnce(&HsmRegistry) -> R) -> R {
    // SAFETY: BSP single-core syscall dispatch is the only entry; preempt-disabled by FMASK
    let r = unsafe { &*(&raw const REGISTRY) };
    f(r)
}

/// 전역 REGISTRY 에 대한 가변 참조로 클로저를 실행한다
///
/// # Safety
/// BSP single-core `with_registry` 와 동일 invariant 동시 가변 별칭이 없어야 한다
pub unsafe fn with_registry_mut<R>(f: impl FnOnce(&mut HsmRegistry) -> R) -> R {
    // SAFETY: BSP single-core; same invariant as with_registry
    let r = unsafe { &mut *(&raw mut REGISTRY) };
    f(r)
}

//
// RELAY_BUF 은 sys_hsm_relay 와 sys_hsm_write 의 단일 인스턴스 staging buffer
//
// raw [u8; CHAN_MAX] 에 명시 zeroize 적용
// Secret<T> 의 Drop 은 static lifetime 으로 절대 호출되지 않으므로 명시 zeroize 가 유일 보장
// (zeroize::Zeroize for [u8; N] 는 volatile_write 와 memory_barrier 보장)
// BSP single-core 와 FMASK 재진입 차단 가정 SMP 도입 시 per-core RELAY_BUF 또는 spinlock 필요
pub static mut RELAY_BUF: [u8; CHAN_MAX] = [0u8; CHAN_MAX];

/// RELAY_BUF 에 대한 안전 래퍼 진입과 이탈 양면 zeroize 보장
///
/// # Safety
/// BSP single-core 진입점에서만 호출 가능  FMASK 재진입 차단으로 syscall dispatch 의 단일 진입을 invariant 로 가정
/// SMP 도입 시 per-core RELAY_BUF 또는 spinlock 필요
pub unsafe fn with_relay_buf<R>(f: impl FnOnce(&mut [u8; CHAN_MAX]) -> R) -> R {
    // SAFETY: BSP single-core; with_registry_mut 와 동일 invariant
    let buf = unsafe { &mut *(&raw mut RELAY_BUF) };
    // 진입 zeroize 이전 호출자 잔재 차단
    buf.zeroize();
    let r = f(buf);
    // 이탈 zeroize 다음 호출자 진입 안전과 본 호출 결과 청결
    buf.zeroize();
    r
}

//
// 슬롯 정보 ABI (enumerate 출력 8바이트, _reserved 는 확장 슬롯)
//

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HsmSlotInfo {
    pub slot: u8,
    pub state: u8,
    _reserved: [u8; 6],
}

const _: () = assert!(size_of::<HsmSlotInfo>() == 8);

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
                    // _reserved[0] = BusKind octet (HsmSlotInfo 8 바이트 ABI 불변)
                    // _reserved[1] = verify_result_code, _reserved[2..6] = pk_hash_prefix 4 octet
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

/// boot smoke 용 커널 측 부착 진입점 (Ring 3 ABI 우회 attach 는 비인증)
///
/// # Safety
/// BSP single-core 에서만 호출 가능하다 `capability::init_prng` 완료를 가정한다
///
/// # Errors
/// `with_registry_mut` 위임 결과 `HsmCapError`
pub unsafe fn attach_kernel_side(bus_kind: BusKind, init_blob: &[u8], rights: HsmRights) -> Result<HsmCapability, HsmCapError> {
    // SAFETY: BSP single-core; with_registry_mut 의 invariant 위임
    // None 전달로 verify gate 우회 smoke 호환성 보존
    unsafe { with_registry_mut(|r| r.attach(bus_kind, init_blob, None, rights)) }
}

/// attestation gate 통과 후에만 슬롯에 부착하는 boot smoke 진입점
///
/// `attach_kernel_side` 의 None 분기 sibling Some(attest_payload) 전달로 verify gate 강제
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
// syscall 핸들러
//

pub fn handle_attach(ctx: &mut SyscallContext) -> u64 {
    // 레지스터 스냅샷 rdi=BusKind, rsi=init_ptr, rdx=init_len, r8=out_ptr
    let bus_kind_raw = ctx.arg0;
    let init_ptr = ctx.arg1;
    let init_len = ctx.arg2;
    let out_ptr = ctx.arg4;
    // attest payload 레지스터 스냅샷 r10 ptr r9 len
    let attest_ptr = ctx.arg3;
    let attest_len = ctx.arg5;

    // Usb..SmartCard stub variant 거부 BusInstance::new() 에 도달 0
    // Network=6 은 cfg-split tls-external 분기에서 NETWORK_CAP_STATE Taken 검증
    // closed 분기는 audit_enqueue 와 Denied collapse 로 단일 RAX 잠금
    let bus_kind: BusKind = match bus_kind_raw {
        0 => BusKind::Software,
        1 => BusKind::Ring3Process,
        #[cfg(feature = "tls-external")]
        6 => {
            // NETWORK_ATTACH cap state-only 검증 (state-only 결정)
            // SAFETY BSP single-core init_network_cap 호출 완료 가정 NETWORK_CAP_STATE 단일 read
            let cap_taken = unsafe {
                (&raw const crate::air_gap::NETWORK_CAP_STATE).read()
                    == crate::air_gap::NetCapState::Taken
            };
            if !cap_taken {
                // NetworkDenied collapse 두번째 카테고리 cap-less 호출
                // slot_idx=0xFF 미할당 result=2 NetworkDenied bus_kind=6 Network pk=[0u8;4]
                crate::hsm_attest::audit_enqueue(0xFF, 2, 6, [0u8; 4]);
                return SyscallError::Denied.as_rax();
            }
            BusKind::Network
        }
        #[cfg(not(feature = "tls-external"))]
        6 => {
            // closed 빌드 거부 경로 (closed-build 우발 진입 차단)
            // matchless `_` arm 대신 명시 6 arm 으로 Denied collapse 일관
            crate::hsm_attest::audit_enqueue(0xFF, 2, 6, [0u8; 4]);
            return SyscallError::Denied.as_rax();
        }
        2..=5 => return SyscallError::BadArg.as_rax(),
        _ => return SyscallError::BadArg.as_rax(),
    };

    // init_len sanity (honest overflow)
    if init_len > MAX_BUS_INIT_BLOB as u64 {
        return SyscallError::BadArg.as_rax();
    }
    // attest_len 정확 3732 옥텟 sanity input 독립 early-return
    const ATTEST_EXACT: u64 = (MLDSA44::PK_LEN + MLDSA44::SIG_LEN) as u64;
    if attest_len != ATTEST_EXACT {
        return SyscallError::BadArg.as_rax();
    }

    // pointer dual range checks
    // init_ptr length-aware init_len == 0 (SoftwareBus 빈 init_blob 허용) 이면 deref 0
    if init_len > 0
        && (!is_user_address(init_ptr) || !is_user_address(init_ptr.saturating_add(init_len)))
    {
        return SyscallError::BadAddress.as_rax();
    }
    // out_ptr unconditional (cap-sized)
    let cap_size = size_of::<HsmCapability>() as u64;
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }
    // attest_ptr dual-range attest_len 은 ATTEST_EXACT 로 고정
    if !is_user_address(attest_ptr) || !is_user_address(attest_ptr.saturating_add(attest_len)) {
        return SyscallError::BadAddress.as_rax();
    }

    // stack staging buffer stack-local 32B 버퍼 함수 종료 직전 zeroize
    let mut init_kbuf = [0u8; MAX_BUS_INIT_BLOB];

    // SMAP-1 read window init_blob copy 만 stac/clac 윈도우 안
    if init_len > 0 {
        // SAFETY: init_ptr / init_ptr+init_len 모두 user range 통과; init_kbuf 는 stack-local
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

    // SMAP-2 별개 윈도우 with_attest_buf closure 안 single stac clac
    // closure 가 SMAP-2 copy + attach 호출 + audit prefix 산출 모두 수행 borrow escape 방지
    // closure 반환은 (attach_result, pk_prefix) tuple closure 밖에서 RAX 매핑 + audit_enqueue
    let init_slice: &[u8] = &init_kbuf[..init_len as usize];
    let (attach_result, pk_prefix): (Result<HsmCapability, HsmCapError>, [u8; 4]) = unsafe {
        crate::hsm_attest::with_attest_buf(|abuf| {
            // SMAP-2 안 single copy attest_payload user 에서 ATTEST_BUF 로
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
            // delegate Some(payload_slice) 전달로 verify gate 활성
            // SAFETY BSP single-core capability init_prng 완료 가정
            let result = with_registry_mut(|r| {
                r.attach(
                    bus_kind,
                    init_slice,
                    Some(payload_slice),
                    // RELAY_SRC 와 RELAY_DST 비트 활성화 reserved 비트 사용 개시
                    HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE | HsmRights::RELAY_SRC | HsmRights::RELAY_DST,
                )
            });
            (result, prefix)
        })
    };

    // all-or-nothing 분기 audit_enqueue 는 성공 실패 모두 기록
    // BusError 에서 HsmCapError 로 다시 SyscallError 로 3 단계 collapse
    let cap = match attach_result {
        Ok(c) => {
            // 성공 audit slot_idx 정확 result 0 bus_kind octet pk_prefix
            crate::hsm_attest::audit_enqueue(c.slot.0, 0, bus_kind as u8, pk_prefix);
            c
        }
        Err(HsmCapError::AttestFailed) => {
            // 실패 audit slot 0xFF 미할당 표시 result 1 모든 경로 stack zeroize
            crate::hsm_attest::audit_enqueue(0xFF, 1, bus_kind as u8, pk_prefix);
            init_kbuf.zeroize();
            // AttestFailed 를 Denied 로 단일 collapse mldsa Error variant 누설 0
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

    // SMAP write window cap 을 out_ptr 로 copy (별도 stac/clac)
    // SAFETY: out_ptr 는 사용자 주소 dual-check 통과; copy 폭은 HsmCapability ABI 크기
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            &cap as *const HsmCapability as *const u8,
            out_ptr as *mut u8,
            size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // final zeroize happy path stack staging clean 후 RAX=0 success
    // ATTEST_BUF zeroize 는 with_attest_buf exit zeroize 가 자동 보장 여기서 별도 wipe 0
    init_kbuf.zeroize();
    0
}

pub fn handle_detach(ctx: &mut SyscallContext) -> u64 {
    let in_ptr = ctx.arg0;
    let user_cap_size = ctx.arg2;

    // (1) 크기 sanity
    if user_cap_size != size_of::<HsmCapability>() as u64 {
        return SyscallError::BadArg.as_rax();
    }
    // (2) user-pointer dual range 검사
    if !is_user_address(in_ptr) || !is_user_address(in_ptr.saturating_add(user_cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }

    // (3) SMAP read window 단일 copy_nonoverlapping
    let mut cap = HsmCapability::invalid();
    // SAFETY: in_ptr dual-check 통과; copy 폭은 HsmCapability ABI 크기
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            in_ptr as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (4) detach registry 가 REVOKE 비트와 저장 토큰 일치 동시 인증
    // capability 거부 variant 전부 Denied 로 collapse
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

    // (5) stack cap 소거 모든 경로
    cap.zeroize();
    rax
}

pub fn handle_enumerate(ctx: &mut SyscallContext) -> u64 {
    let cap_ptr = ctx.arg0;
    let out_ptr = ctx.arg1;
    let count = ctx.arg2;

    // (1) cap 입력 sanity 정확한 ABI 크기 보장
    let cap_size = size_of::<HsmCapability>() as u64;
    if !is_user_address(cap_ptr) || !is_user_address(cap_ptr.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }

    // (2) cap 만 먼저 읽음 출력 버퍼는 cap 인증 통과 후 검증
    let mut cap = HsmCapability::invalid();
    // SAFETY: cap_ptr dual-check 통과; cap_size 바이트 (HsmCapability ABI)
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            cap_ptr as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (3) cap 인증 (CT) registry 와 대조 is_valid_for(cap.slot, ...) 은
    // user-supplied 필드끼리만 비교하는 tautology 이므로 사용 금지
    // 실패 시 user 출력 버퍼 절대 미수정
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
    let info_bytes = count.saturating_mul(size_of::<HsmSlotInfo>() as u64);
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(info_bytes)) {
        cap.zeroize();
        return SyscallError::BadAddress.as_rax();
    }

    // (5) 스택 버퍼 채우기 registry 읽기는 SMAP 윈도우 외부
    let mut info_buf: [HsmSlotInfo; HSM_MAX_SLOTS] = [HsmSlotInfo::empty(); HSM_MAX_SLOTS];
    let cap_elems = (count as usize).min(HSM_MAX_SLOTS);
    // SAFETY: BSP single-core
    let n = unsafe { with_registry(|r| r.enumerate(&mut info_buf[..cap_elems])) };

    // (6) SMAP write window 단일 copy_nonoverlapping
    let written_bytes = n.saturating_mul(size_of::<HsmSlotInfo>());
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

// handle_write sys_hsm_write 핸들러 USE cap 검증 후 user data SMAP copy 로 slot.bus.write
//
// ABI  rdi = cap_ptr (16B HsmCapability)
//      rsi = data_ptr (user-space)
//      rdx = data_len (≤ CHAN_MAX, > 0)
//
// handle_detach 와 동일 6-step 구조
//   (1) data_len CT 범위 (0 < data_len ≤ CHAN_MAX, CtLess::lt / CtEqOps::ne)
//   (2) (cap_ptr, 16B) 과 (data_ptr, data_len) dual-range
//   (3) SMAP-1 cap copy (단일 stac/clac)
//   (4) authenticate(USE) 실패 시 cap.zeroize 후 Denied
//   (5) with_relay_buf 진입 후 SMAP-2 data copy 로 slot.bus.write
//   (6) cap.zeroize 와 BusError 의 Internal collapse
pub fn handle_write(ctx: &mut SyscallContext) -> u64 {
    let cap_ptr_va = ctx.arg0;
    let data_ptr_va = ctx.arg1;
    let data_len = ctx.arg2 as usize;

    // (1) data_len ∈ (0, CHAN_MAX] CT 분기 (CtLess::lt / CtEqOps::ne), '<' 와 '==' direct 비교 금지
    //     상한 CHAN_MAX 포함 4 KiB 정확 등호 허용, CtLess::ct_lt(&len, &(CHAN_MAX+1)) 로 ≤ CHAN_MAX 표현
    let lt_max: u8 = CtLess::ct_lt(&data_len, &(CHAN_MAX + 1)).unwrap_u8();
    let nonzero: u8 = CtEqOps::ct_ne(&data_len, &0usize).unwrap_u8();
    if (lt_max & nonzero) != 1 {
        return SyscallError::BadArg.as_rax();
    }

    // (2) user-pointer dual range 검사, is_user_address 는 u64 인자
    let cap_size = size_of::<HsmCapability>() as u64;
    if !is_user_address(cap_ptr_va) || !is_user_address(cap_ptr_va.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }
    if !is_user_address(data_ptr_va)
        || !is_user_address(data_ptr_va.saturating_add(data_len as u64))
    {
        return SyscallError::BadAddress.as_rax();
    }

    // (3) SMAP-1 cap copy, 단일 stac/clac 윈도우
    let mut cap = HsmCapability::invalid();
    // SAFETY: cap_ptr_va dual-range 검증 통과  copy 폭은 HsmCapability ABI 크기 (16B)
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            cap_ptr_va as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (4) USE 인증 실패 시 RELAY_BUF 미진입, cap zeroize 후 Denied
    // SAFETY: BSP single-core
    let auth_ok = unsafe { with_registry(|r| r.authenticate(&cap, HsmRights::USE)) };
    if !auth_ok {
        cap.zeroize();
        return SyscallError::Denied.as_rax();
    }

    // (5) with_relay_buf 진입 후 SMAP-2 data copy 로 slot.bus.write
    //     RELAY_BUF 은 with_relay_buf 의 진입 이탈 양면 zeroize 로 보장
    let slot_idx = cap.slot.0 as usize;
    // SAFETY: BSP single-core; with_relay_buf + with_registry_mut 는 disjoint static borrow
    let closure_result: Result<(), SyscallError> = unsafe {
        with_relay_buf(|buf| {
            // SMAP-2 user data 를 RELAY_BUF 로 (단일 stac/clac)
            // SAFETY: data_ptr_va dual-range 통과 + data_len ≤ CHAN_MAX
            crate::cpu::stac();
            core::ptr::copy_nonoverlapping(
                data_ptr_va as *const u8,
                buf.as_mut_ptr(),
                data_len,
            );
            crate::cpu::clac();
            // slot.bus.write 는 with_registry_mut 안에서 실행, borrow 분리 유지
            with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
                Some(bus) => match bus.write(&buf[..data_len]) {
                    Ok(_n) => Ok(()),
                    // BusError 전 variant 를 Internal 로 collapse
                    Err(_) => Err(SyscallError::Internal),
                },
                None => Err(SyscallError::Internal),
            })
        })
    };

    // (6) cap zeroize, 모든 경로 마지막 단계
    cap.zeroize();
    match closure_result {
        Ok(()) => 0u64,
        Err(SyscallError::Internal) => SyscallError::Internal.as_rax(),
        Err(_) => SyscallError::Internal.as_rax(),
    }
}

// handle_relay sys_hsm_relay 핸들러 user data pointer 부재 kernel-internal transfer 전용
//
// ABI  rdi = src_cap_ptr (16B)
//      rsi = dst_cap_ptr (16B)
//      rdx = byte_len (≤ CHAN_MAX, > 0)
//
// 6-step 구조
//   (1) byte_len CT 범위 (0 < byte_len ≤ CHAN_MAX)
//   (2) (src_cap_ptr, 16B) 과 (dst_cap_ptr, 16B) dual-range, user data ptr 부재
//   (3) SMAP-1 src_cap 과 SMAP-2 dst_cap 두 분리 윈도우
//   (4) dual authenticate (src_ok as u8) & (dst_ok as u8) bitand, short-circuit (&&) 금지
//   (5) with_relay_buf 진입 후 src.read 로 dst.write atomic (CtEqOps::eq)
//   (6) src_cap 과 dst_cap zeroize, BusError 의 Internal collapse
pub fn handle_relay(ctx: &mut SyscallContext) -> u64 {
    let src_cap_ptr_va = ctx.arg0;
    let dst_cap_ptr_va = ctx.arg1;
    let byte_len = ctx.arg2 as usize;

    // (1) byte_len ∈ (0, CHAN_MAX]  CT 분기 (CtLess::lt / CtEqOps::ne)
    let lt_max: u8 = CtLess::ct_lt(&byte_len, &(CHAN_MAX + 1)).unwrap_u8();
    let nonzero: u8 = CtEqOps::ct_ne(&byte_len, &0usize).unwrap_u8();
    if (lt_max & nonzero) != 1 {
        return SyscallError::BadArg.as_rax();
    }

    // (2) 두 cap 포인터 dual-range, user data pointer 부재 (핵심 보장)
    let cap_size = size_of::<HsmCapability>() as u64;
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

    // (3) SMAP-1 src_cap 과 SMAP-2 dst_cap 두 분리 stac/clac 윈도우
    let mut src_cap = HsmCapability::invalid();
    let mut dst_cap = HsmCapability::invalid();
    // SAFETY: src_cap_ptr_va dual-range 통과  16B copy
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            src_cap_ptr_va as *const u8,
            &mut src_cap as *mut HsmCapability as *mut u8,
            size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }
    // SAFETY: dst_cap_ptr_va dual-range 통과  16B copy
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            dst_cap_ptr_va as *const u8,
            &mut dst_cap as *mut HsmCapability as *mut u8,
            size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (4) Dual-cap authenticate CT-AND  bitand 사용  short-circuit (&&) 금지
    //     양쪽 authenticate 무조건 실행으로 변이 누설 0 유지
    // SAFETY: BSP single-core
    let src_ok = unsafe { with_registry(|r| r.authenticate(&src_cap, HsmRights::RELAY_SRC)) };
    // SAFETY: BSP single-core
    let dst_ok = unsafe { with_registry(|r| r.authenticate(&dst_cap, HsmRights::RELAY_DST)) };
    // 어느 한쪽 fail 도 Denied 단일 매핑, variant 누설 0
    let both_ok: u8 = (src_ok as u8) & (dst_ok as u8);
    if both_ok != 1 {
        src_cap.zeroize();
        dst_cap.zeroize();
        return SyscallError::Denied.as_rax();
    }

    // (5) with_relay_buf 진입 후 src.read 로 dst.write atomic
    //     CtEqOps::eq 로 returned accepted 가 byte_len 과 불일치 시 Internal
    let src_slot = src_cap.slot.0 as usize;
    let dst_slot = dst_cap.slot.0 as usize;
    // SAFETY: BSP single-core; with_relay_buf + with_registry_mut 는 disjoint static borrow
    let closure_result: Result<(), SyscallError> = unsafe {
        with_relay_buf(|buf| {
            with_registry_mut(|r| {
                // src.read src.ring 의 destructive read 로 buf[..byte_len]
                let n = match r.slot_bus_mut(src_slot) {
                    Some(bus) => match bus.read(&mut buf[..byte_len]) {
                        Ok(n) => n,
                        // BusError 를 Internal 로 collapse
                        Err(_) => return Err(SyscallError::Internal),
                    },
                    None => return Err(SyscallError::Internal),
                };
                // atomic relay, CtEqOps::eq 로 partial 거부
                if CtEqOps::ct_eq(&n, &byte_len).unwrap_u8() != 1 {
                    return Err(SyscallError::Internal);
                }
                // dst.write buf[..byte_len] 를 dst.ring 으로
                let m = match r.slot_bus_mut(dst_slot) {
                    Some(bus) => match bus.write(&buf[..byte_len]) {
                        Ok(m) => m,
                        Err(_) => return Err(SyscallError::Internal),
                    },
                    None => return Err(SyscallError::Internal),
                };
                // atomic relay, CtEqOps::eq 로 accepted 가 byte_len 과 일치 보장
                if CtEqOps::ct_eq(&m, &byte_len).unwrap_u8() != 1 {
                    return Err(SyscallError::Internal);
                }
                Ok(())
            })
        })
    };

    // (6) 두 cap zeroize 와 BusError variant collapse
    src_cap.zeroize();
    dst_cap.zeroize();
    match closure_result {
        Ok(()) => 0u64,
        Err(_) => SyscallError::Internal.as_rax(),
    }
}

/// sys_hsm_read syscall 핸들러, USE cap 으로 Ring3ProcessBus 의 pending wire frame 회수
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
/// `SyscallError::Internal` BusError 전 variant collapse
///
/// 7-step 구조 (handle_detach SMAP-1, handle_enumerate SMAP-2, handle_write authenticate 합성)
///   (1) Argument 추출
///   (2) out_len CT 범위 검증 (16..=WIRE_FRAME_MAX, '<' 와 '==' 금지)
///   (3) dual range, cap_ptr 과 out_ptr 양쪽 16B, out_len 범위
///   (4) SMAP-1 cap copy (단일 stac/clac 윈도우)
///   (5) authenticate(USE) CT-AND, early-return 없음
///   (6) with_registry_mut 로 slot.bus.read(staging[..out_len]), BusError 전 variant Internal collapse
///   (7) SMAP-2 staging 을 user out_ptr 로 (별도 stac/clac 윈도우), 모든 exit path zeroize
pub fn handle_read(ctx: &mut SyscallContext) -> u64 {
    // (1) Argument 추출
    let cap_ptr_va = ctx.arg0;
    let out_ptr_va = ctx.arg1;
    let out_len = ctx.arg2 as usize;

    // (2) out_len ∈ [16, WIRE_FRAME_MAX] CT 분기, handle_write 와 동일 패턴
    //     ge_min  CtLess::ct_lt(&15, &out_len) 즉 out_len > 15 즉 out_len ≥ 16
    //     lt_max  CtLess::ct_lt(&out_len, &(WIRE_FRAME_MAX + 1)) 즉 out_len ≤ WIRE_FRAME_MAX
    let lt_max: u8 = CtLess::ct_lt(&out_len, &(WIRE_FRAME_MAX + 1)).unwrap_u8();
    let ge_min: u8 = CtLess::ct_lt(&15usize, &out_len).unwrap_u8();
    if (lt_max & ge_min) != 1 {
        return SyscallError::BadArg.as_rax();
    }

    // (3) dual range, cap_ptr 16B 와 out_ptr 의 out_len byte 양쪽
    let cap_size = size_of::<HsmCapability>() as u64;
    if !is_user_address(cap_ptr_va) || !is_user_address(cap_ptr_va.saturating_add(cap_size)) {
        return SyscallError::BadAddress.as_rax();
    }
    if !is_user_address(out_ptr_va) || !is_user_address(out_ptr_va.saturating_add(out_len as u64))
    {
        return SyscallError::BadAddress.as_rax();
    }

    // (4) SMAP-1 cap copy, 단일 stac/clac 윈도우 (handle_detach 미러)
    let mut cap = HsmCapability::invalid();
    // SAFETY: cap_ptr_va dual-range 검증 통과  copy 폭은 HsmCapability ABI 크기 16B
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            cap_ptr_va as *const u8,
            &mut cap as *mut HsmCapability as *mut u8,
            size_of::<HsmCapability>(),
        );
        crate::cpu::clac();
    }

    // (5) USE 인증 실패 시 user out 버퍼 미접근, cap zeroize 후 Denied
    // SAFETY: BSP single-core
    let auth_ok = unsafe { with_registry(|r| r.authenticate(&cap, HsmRights::USE)) };
    if !auth_ok {
        cap.zeroize();
        return SyscallError::Denied.as_rax();
    }

    // (6) staging 과 slot.bus.read, stack-local [u8; WIRE_FRAME_MAX]
    //     RELAY_BUF 와 책임 분리 (RELAY_BUF 는 ingress write relay 전용)
    //     out_len ≤ WIRE_FRAME_MAX 가 step 2 에서 보장
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
            // BusError 의 NotOpen / WireNotReady / BufferTooSmall / Internal 전 variant collapse
            cap.zeroize();
            staging.zeroize();
            return SyscallError::Internal.as_rax();
        }
    };

    // (7) SMAP-2 staging 을 user out_ptr 로, 별도 stac/clac 윈도우 (handle_enumerate 미러)
    // SAFETY: out_ptr_va dual-range 검증 통과 (step 3)  bytes_read ≤ out_len ≤ WIRE_FRAME_MAX
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(staging.as_ptr(), out_ptr_va as *mut u8, bytes_read);
        crate::cpu::clac();
    }

    // 모든 exit path zeroize, Ok path 도 cap 과 staging 명시 소거
    cap.zeroize();
    staging.zeroize();
    bytes_read as u64
}
