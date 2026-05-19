//! Air-gap 이중 게이트 표면 + 감사 query syscall + 2 층 self-check 모듈
//!
//! # Features
//! Phase 6 GAP-01 ~ GAP-04 의 핵심 신규 모듈
//! tls-external feature 게이트 안 NETWORK_ATTACH_CAP one-shot mint + take + handle_attach Network arm 연계
//! 양 프로필 공통 AUDIT_READ_CAP one-shot mint + take + sys_hsm_status 456 옥텟 atomic 응답
//! 양 프로필 공통 gap_self_check boot-time fail-stop (closed 빌드 심볼 부재 invariant 검증)
//!
//! # 책임 경계
//! - 본 모듈은 air-gap 정책 표면만 제공 AUDIT_RING 자체는 hsm_attest 모듈 책임 (audit_enqueue 호출자)
//! - take_*_cap 의 SMAP 윈도우는 단일 stac/clac (Pitfall 2)
//! - cap 비교는 모두 CtEqOps eq (Pitfall 1 early-return 금지)
//! - state 전이는 SMAP clac 이후에만 수행 (Pitfall 1 cap take race 회피)
//! - handle_status 본 호출은 AUDIT_RING 미기록 (D-05 audit-of-audit 회피)

use zeroize::Zeroize;

use crate::bus::BusKind;
use crate::capability;
use crate::hsm_attest::{AUDIT_RING_CAPACITY, EnrollEvent, audit_enqueue, audit_snapshot};
use crate::hsm_registry::{HsmCapability, HsmSlotInfo, with_registry};
use crate::syscall::{SyscallContext, SyscallError, is_user_address};

//
// NetCapState FSM Provisioned 0 Taken 1 단방향 (D-03)
//

/// one-shot cap take FSM 상태
///
/// 부팅 시 BSS default 가 Provisioned take 호출 시 Taken 으로 단방향 전이
/// v2 에서 회전 도입 시 Revoked / Reprovisioned variant 추가 예정
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NetCapState {
    Provisioned = 0,
    Taken = 1,
}

//
// NETWORK_SYM_PRESENT 컴파일 시점 cfg const (D-07 Layer 2 self-check 의 Option a)
//
// closed 빌드에서 false 컴파일 시점 fold 로 NETWORK_* 심볼 부재 invariant 강제
// tls-external 빌드에서 true 본 const 가 분기 결정자로 사용

/// closed 빌드 false tls-external 빌드 true 컴파일 시점 cfg const fold
#[cfg(feature = "tls-external")]
pub const NETWORK_SYM_PRESENT: bool = true;
#[cfg(not(feature = "tls-external"))]
pub const NETWORK_SYM_PRESENT: bool = false;

//
// AUDIT_READ_CAP 양 프로필 공통 BSS singleton (D-06)
//

/// AUDIT_READ cap 양 프로필 공통 sys_hsm_status 호출 시 caller 가 token 제시
#[used]
pub static mut AUDIT_READ_CAP: HsmCapability = HsmCapability::invalid();

/// AUDIT_READ cap one-shot FSM 상태 부팅 시 Provisioned default
#[used]
pub static mut AUDIT_CAP_STATE: NetCapState = NetCapState::Provisioned;

//
// NETWORK_ATTACH_CAP tls-external 게이트 BSS singleton (D-02)
//

/// NETWORK_ATTACH cap tls-external 빌드 한정 handle_attach Network arm 진입 게이트
#[cfg(feature = "tls-external")]
#[used]
pub static mut NETWORK_ATTACH_CAP: HsmCapability = HsmCapability::invalid();

/// NETWORK_ATTACH cap one-shot FSM 상태 부팅 시 Provisioned default
#[cfg(feature = "tls-external")]
#[used]
pub static mut NETWORK_CAP_STATE: NetCapState = NetCapState::Provisioned;

//
// GAP_STATUS_* ABI 잠금 (D-05 sys_hsm_status 456 옥텟 layout Shared-6)
//
// header 8 + StatusEntry 64 (= 8 * 8) + EnrollEvent 384 (= 32 * 12) = 456 옥텟
// Plan 06-01 sibling test 의 byte-exact 일치 잠금 대상

/// sys_hsm_status 응답 헤더 8 옥텟 slot_count u16 + audit_written u16 + audit_total u32
pub const GAP_STATUS_HEADER_LEN: usize = 8;
/// sys_hsm_status 응답 StatusEntry array 64 옥텟 8 슬롯 x 8 옥텟
pub const GAP_STATUS_ENTRIES_LEN: usize = 64;
/// sys_hsm_status 응답 EnrollEvent array 384 옥텟 32 events x 12 옥텟
pub const GAP_STATUS_AUDIT_LEN: usize = 384;
/// sys_hsm_status 응답 총 456 옥텟 ABI 잠금
pub const GAP_STATUS_LEN: usize = 456;

/// sys_hsm_status 응답 StatusEntry 8 옥텟 ABI 잠금
///
/// `slot_idx` 슬롯 인덱스 0..8 또는 0xFF (미할당)
/// `bus_kind` BusKind octet (Phase 2 D-19)
/// `attest_result` verify_result_code (Phase 5 D-14)
/// `_pad` align fill 항상 0 (Pitfall 6)
/// `pk_hash_prefix` BLAKE3 prefix 4 옥텟 (Phase 5 D-14)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct StatusEntry {
    pub slot_idx: u8,
    pub bus_kind: u8,
    pub attest_result: u8,
    pub _pad: u8,
    pub pk_hash_prefix: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<StatusEntry>() == 8);
const _: () = assert!(
    GAP_STATUS_LEN == GAP_STATUS_HEADER_LEN + GAP_STATUS_ENTRIES_LEN + GAP_STATUS_AUDIT_LEN
);
const _: () = assert!(GAP_STATUS_LEN == 456);
const _: () = assert!(core::mem::size_of::<HsmCapability>() == 16);

//
// init_audit_read_cap 부팅 시 1 회 호출 (D-06)
//

/// AUDIT_READ_CAP 부팅 시 1 회 초기화 capability gen_token_u64 2 회 호출 token 합성
///
/// # Safety
/// 부팅 시 단일 코어에서 1 회만 호출 호출자가 capability init_prng 완료를 보장해야 함
/// 본 함수가 AUDIT_READ_CAP token 필드의 단일 진입 갱신을 수행 (BSP single-core invariant)
pub unsafe fn init_audit_read_cap() {
    // gen_token_u64 2 회 호출 첫 번째 만 token 으로 사용 두 번째는 DRBG entropy hop
    // SAFETY 호출자가 capability init_prng 완료를 보장
    let t0 = unsafe { capability::gen_token_u64().unwrap_or(0) };
    let _t1 = unsafe { capability::gen_token_u64().unwrap_or(0) };
    // SAFETY 단일 코어 부팅 초기 AUDIT_READ_CAP 의 단일 진입 갱신
    // rights 와 slot 은 invalid 잠금 Ring 3 측 검증은 token only (D-06)
    // state 는 Provisioned 가 BSS default 이므로 별도 write 불필요
    unsafe {
        let cap_ref = &mut *(&raw mut AUDIT_READ_CAP);
        cap_ref.token = t0;
    }
}

//
// init_network_cap 부팅 시 1 회 호출 tls-external 한정 (D-02)
//

/// NETWORK_ATTACH_CAP 부팅 시 1 회 초기화 capability gen_token_u64 2 회 호출 token 합성
///
/// # Safety
/// 부팅 시 단일 코어에서 1 회만 호출 호출자가 capability init_prng 완료를 보장해야 함
/// 본 함수가 NETWORK_ATTACH_CAP token 필드의 단일 진입 갱신을 수행 (BSP single-core invariant)
#[cfg(feature = "tls-external")]
pub unsafe fn init_network_cap() {
    // SAFETY 호출자가 capability init_prng 완료를 보장
    let t0 = unsafe { capability::gen_token_u64().unwrap_or(0) };
    let _t1 = unsafe { capability::gen_token_u64().unwrap_or(0) };
    // SAFETY 단일 코어 부팅 초기 NETWORK_ATTACH_CAP 의 단일 진입 갱신
    unsafe {
        let cap_ref = &mut *(&raw mut NETWORK_ATTACH_CAP);
        cap_ref.token = t0;
    }
}

//
// gap_self_check 2 층 자체 점검 (D-07 RESEARCH 3.4 Pattern 2 Option a)
//

/// 부팅 마지막 단계 air-gap 표면 무결성 자체 점검 fail-stop
///
/// # Safety
/// kernel_main 의 모든 init_* 호출 및 syscall dispatcher 등록 완료 *이후* 단일 호출
/// tls-external 빌드 시 NETWORK_ATTACH_CAP token 미초기화 detect
/// 양 프로필 공통 AUDIT_READ_CAP token 미초기화 detect 양 케이스 모두 panic = abort fail-stop
pub unsafe fn gap_self_check() {
    // Layer 2-a tls-external 빌드 한정 NETWORK_ATTACH_CAP sanity
    #[cfg(feature = "tls-external")]
    {
        // SAFETY BSP single-core init_network_cap 호출 완료 가정
        let cap_token = unsafe { (&raw const NETWORK_ATTACH_CAP).read().token };
        if cap_token == 0 {
            audit_enqueue(0xFC, 4, BusKind::Network as u8, [0u8; 4]);
            panic!("gap_self_check NETWORK_ATTACH_CAP not initialized in tls-external build");
        }
    }
    // Layer 2-b closed 빌드 한정 NETWORK_SYM_PRESENT false 컴파일 시점 fold
    #[cfg(not(feature = "tls-external"))]
    {
        const _: () = assert!(!NETWORK_SYM_PRESENT);
    }
    // Layer 2-c 양 프로필 공통 AUDIT_READ_CAP sanity
    // SAFETY BSP single-core init_audit_read_cap 호출 완료 가정
    let audit_cap_token = unsafe { (&raw const AUDIT_READ_CAP).read().token };
    if audit_cap_token == 0 {
        audit_enqueue(0xFC, 4, BusKind::Software as u8, [0u8; 4]);
        panic!("gap_self_check AUDIT_READ_CAP not initialized");
    }
}

//
// syscall handler stub Task 2 가 본문 채움
//
// Task 1 commit 시점에 cargo check 통과를 위한 todo!() placeholder
// Task 2 가 take_network_cap / take_audit_read_cap / handle_status 본문을 교체

/// sys_network_cap_take Ring 3 캡 인도 syscall handler (D-03 GAP-02)
///
/// tls-external 빌드 한정 closed 빌드 cfg-out
/// 본 stub 은 Task 2 가 본문 교체
#[cfg(feature = "tls-external")]
pub fn take_network_cap(_ctx: &mut SyscallContext) -> u64 {
    todo!("Task 2 take_network_cap 본문 채움")
}

/// sys_audit_cap_take Ring 3 캡 인도 syscall handler (D-06 GAP-02)
///
/// 양 프로필 공통 본 stub 은 Task 2 가 본문 교체
pub fn take_audit_read_cap(_ctx: &mut SyscallContext) -> u64 {
    todo!("Task 2 take_audit_read_cap 본문 채움")
}

/// sys_hsm_status atomic 456 옥텟 응답 syscall handler (D-05 GAP-04)
///
/// 양 프로필 공통 본 stub 은 Task 2 가 본문 교체
pub fn handle_status(_ctx: &mut SyscallContext) -> u64 {
    todo!("Task 2 handle_status 본문 채움")
}
