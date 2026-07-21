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
// syscall handler 본문 (D-03 / D-05 / D-06)
//
// 3 fn 모두 PATTERNS C/D 의 7-Phase 패턴 mirror
// take_*_cap one-shot 16 B out + FSM Provisioned → Taken
// handle_status atomic 456 B out cap-fail 만 AUDIT 기록

/// sys_network_cap_take Ring 3 NETWORK_ATTACH 캡 인도 syscall handler (D-03 GAP-02)
///
/// tls-external 빌드 한정 closed 빌드 cfg-out
/// out_ptr rdi 16 옥텟 HsmCapability 응답 first-caller-wins after-take Denied 콜럐스
#[cfg(feature = "tls-external")]
pub fn take_network_cap(ctx: &mut SyscallContext) -> u64 {
    // Phase 0 register snapshot D-15 단일 인자 out only
    let out_ptr = ctx.arg0;

    // Phase 1 dual-range Shared-3 BadAddress 도 Denied 콜럐스 Shared-5
    let cap_size = core::mem::size_of::<HsmCapability>() as u64; // = 16
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(cap_size)) {
        return SyscallError::Denied.as_rax();
    }

    // Phase 2 FSM 상태 검증 Provisioned 만 통과 Taken 재호출 시 5 NetworkDenied 콜럐스 첫 케이스
    // SAFETY BSP single-core + FMASK 재진입 차단
    let current_state = unsafe { (&raw const NETWORK_CAP_STATE).read() };
    if current_state != NetCapState::Provisioned {
        // D-04 result 2 NetworkDenied + slot 0xFE NETWORK 식별자 + bus_kind Network 6
        audit_enqueue(0xFE, 2, BusKind::Network as u8, [0u8; 4]);
        return SyscallError::Denied.as_rax();
    }

    // Phase 3 stack-local cap copy Shared-1 raw read
    // SAFETY BSP single-core NETWORK_ATTACH_CAP 의 단일 read
    let mut staging_cap = unsafe { (&raw const NETWORK_ATTACH_CAP).read() };

    // Phase 4 SMAP 단일 윈도우 Shared-2 stac copy clac
    // SAFETY out_ptr dual-range 통과 copy 폭 HsmCapability ABI 16 옥텟
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            (&raw const staging_cap) as *const u8,
            out_ptr as *mut u8,
            cap_size as usize,
        );
        crate::cpu::clac();
    }

    // Phase 5 FSM 전이 Provisioned → Taken clac 이후 atomic 일관성 Pitfall 1 race 회피
    // SAFETY BSP single-core NETWORK_CAP_STATE 의 단일 진입 갱신
    unsafe {
        (&raw mut NETWORK_CAP_STATE).write(NetCapState::Taken);
    }

    // Phase 6 D-04 AUDIT result 3 NetworkCapTaken
    audit_enqueue(0xFE, 3, BusKind::Network as u8, [0u8; 4]);

    // Phase 7 stack-local zeroize Shared-4
    staging_cap.zeroize();
    0
}

/// sys_audit_cap_take Ring 3 AUDIT_READ 캡 인도 syscall handler (D-06 GAP-02)
///
/// 양 프로필 공통 out_ptr rdi 16 옥텟 응답 first-caller-wins after-take Denied
/// take_network_cap 의 정확한 클론 NETWORK_* AUDIT_* slot 0xFE 0xFD bus_kind Network Software
pub fn take_audit_read_cap(ctx: &mut SyscallContext) -> u64 {
    // Phase 0 register snapshot
    let out_ptr = ctx.arg0;

    // Phase 1 dual-range BadAddress 도 Denied 콜럐스
    let cap_size = core::mem::size_of::<HsmCapability>() as u64; // = 16
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(cap_size)) {
        return SyscallError::Denied.as_rax();
    }

    // Phase 2 FSM 상태 검증
    // SAFETY BSP single-core + FMASK 재진입 차단
    let current_state = unsafe { (&raw const AUDIT_CAP_STATE).read() };
    if current_state != NetCapState::Provisioned {
        // D-04 result 2 + slot 0xFD AUDIT_READ 식별자 + bus_kind Software 0 도용 Pitfall 3
        audit_enqueue(0xFD, 2, BusKind::Software as u8, [0u8; 4]);
        return SyscallError::Denied.as_rax();
    }

    // Phase 3 stack-local cap copy
    // SAFETY BSP single-core AUDIT_READ_CAP 의 단일 read
    let mut staging_cap = unsafe { (&raw const AUDIT_READ_CAP).read() };

    // Phase 4 SMAP 단일 윈도우
    // SAFETY out_ptr dual-range 통과 copy 폭 HsmCapability ABI 16 옥텟
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            (&raw const staging_cap) as *const u8,
            out_ptr as *mut u8,
            cap_size as usize,
        );
        crate::cpu::clac();
    }

    // Phase 5 FSM 전이 clac 이후 atomic 일관성
    // SAFETY BSP single-core AUDIT_CAP_STATE 의 단일 진입 갱신
    unsafe {
        (&raw mut AUDIT_CAP_STATE).write(NetCapState::Taken);
    }

    // Phase 6 D-04 AUDIT result 3 AuditCapTaken bus_kind Software 도용
    audit_enqueue(0xFD, 3, BusKind::Software as u8, [0u8; 4]);

    // Phase 7 stack-local zeroize
    staging_cap.zeroize();
    0
}

/// sys_hsm_status atomic 456 옥텟 응답 syscall handler (D-05 GAP-04)
///
/// 양 프로필 공통 AUDIT_READ cap 보유자만 진입
/// out_ptr rdi out_len rsi caller_cap_token rdx ABI 잠금
/// 호출 자체는 AUDIT_RING 미기록 D-05 audit-of-audit 회피 cap-fail 만 result 2 기록
pub fn handle_status(ctx: &mut SyscallContext) -> u64 {
    // Phase 0 register snapshot
    let out_ptr = ctx.arg0;
    let out_len = ctx.arg1;
    let caller_cap_token = ctx.arg2;

    // Phase 1 out_len 정합성 BufferTooSmall = Denied 콜럐스 Pitfall 2 AUDIT 미기록
    // SMAP 윈도우 진입 *이전* + AUDIT 미기록 → caller-side 정보만 사용 정수 < 비교 충분
    if out_len < GAP_STATUS_LEN as u64 {
        return SyscallError::Denied.as_rax();
    }

    // Phase 2 cap ct_eq Pitfall 1 early-return 금지 일관 CtEqOps unwrap_u8 한 번에 결정
    let cap_eq = unsafe {
        let stored = (&raw const AUDIT_READ_CAP).read();
        use constant_time::CtEqOps;
        CtEqOps::eq(&stored.token, &caller_cap_token).unwrap_u8() == 1
    };
    if !cap_eq {
        // D-04 result 2 + slot 0xFF sys_hsm_status cap-fail 식별자 + bus_kind Software 0
        audit_enqueue(0xFF, 2, BusKind::Software as u8, [0u8; 4]);
        return SyscallError::Denied.as_rax();
    }

    // Phase 3 dual-range Shared-3 out_ptr length-aware BadAddress 는 Denied 와 분리
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(out_len)) {
        return SyscallError::BadAddress.as_rax();
    }

    // Phase 4 stack staging Pitfall 4 456 옥텟
    let mut staging = [0u8; GAP_STATUS_LEN];

    // Phase 5 데이터 수집 SMAP 윈도우 *밖* Pitfall 2 정신
    // (a) StatusEntry 8 슬롯 채움 _reserved layout Phase 5 D-12 mirror
    let mut slot_infos = [HsmSlotInfo::empty(); 8];
    // SAFETY BSP single-core REGISTRY 의 단일 read
    let _slot_count = unsafe { with_registry(|r| r.enumerate(&mut slot_infos)) };
    for i in 0..8 {
        let off = GAP_STATUS_HEADER_LEN + i * 8;
        // _reserved 는 private 이므로 enumerate 가 채운 raw bytes 를 그대로 직렬화
        // HsmSlotInfo 8 옥텟 ABI 잠금 slot + state + _reserved[6] 그대로 카피하면 정확히 8 옥텟
        // sibling test 의 StatusEntry layout (slot_idx, bus_kind, attest_result, _pad, pk_hash[4]) 와
        // byte-exact 일치하려면 HsmSlotInfo._reserved[0]=bus_kind _reserved[1]=verify_result _reserved[2..6]=pk_hash 가
        // 정확히 StatusEntry 의 bus_kind / attest_result / pk_hash_prefix 자리에 매핑되어야 함
        // HsmSlotInfo 의 메모리 layout 자체가 그 매핑 그대로 (slot=offset0 state=offset1 _reserved[0..6]=offset2..8)
        // 단 StatusEntry 는 (slot_idx=0 bus_kind=1 attest_result=2 _pad=3 pk_hash[4..8])
        // → slot_infos[i] 의 raw bytes 를 staging[off..off+8] 로 copy 시 'state' octet 이 'bus_kind' 자리에 가지 못함
        // → 본 plan PATTERNS §3 Phase 5(a) 의 명시 field-by-field 직렬화 적용
        let info_bytes: [u8; 8] = unsafe {
            core::mem::transmute::<HsmSlotInfo, [u8; 8]>(slot_infos[i])
        };
        // info_bytes 레이아웃 [slot, state, _reserved[0..6]]
        // _reserved[0] = bus_kind (Phase 2 D-19) _reserved[1] = verify_result_code (Phase 5 D-14)
        // _reserved[2..6] = pk_hash_prefix (Phase 5 D-14)
        staging[off] = info_bytes[0]; // slot_idx (0xFF 미할당 시)
        staging[off + 1] = info_bytes[2]; // bus_kind octet = _reserved[0]
        staging[off + 2] = info_bytes[3]; // attest_result = _reserved[1]
        staging[off + 3] = 0; // _pad 잠금 Pitfall 6
        staging[off + 4..off + 8].copy_from_slice(&info_bytes[4..8]); // pk_hash_prefix = _reserved[2..6]
    }

    // (b) AUDIT_RING snapshot
    let mut events_local = [EnrollEvent::default(); AUDIT_RING_CAPACITY];
    let (audit_written, audit_total) = audit_snapshot(&mut events_local);

    // (c) 헤더 채움 offset 0..8 little-endian
    staging[0..2].copy_from_slice(&(_slot_count as u16).to_le_bytes());
    staging[2..4].copy_from_slice(&(audit_written as u16).to_le_bytes());
    staging[4..8].copy_from_slice(&audit_total.to_le_bytes());

    // (d) EnrollEvent written 개 raw 12 옥텟 직렬화 Phase 5.1 bus.rs wire mirror byte-exact
    for i in 0..audit_written {
        let off = GAP_STATUS_HEADER_LEN + GAP_STATUS_ENTRIES_LEN + i * 12;
        staging[off..off + 4].copy_from_slice(&events_local[i].seq.to_le_bytes());
        staging[off + 4] = events_local[i].slot_idx;
        staging[off + 5] = events_local[i].result;
        staging[off + 6] = events_local[i].bus_kind;
        staging[off + 7] = events_local[i]._pad;
        staging[off + 8..off + 12].copy_from_slice(&events_local[i].pk_hash_prefix);
    }

    // Phase 6 SMAP 단일 윈도우 Shared-2 stac copy clac 456 옥텟
    // SAFETY out_ptr dual-range 통과 copy 폭 GAP_STATUS_LEN 옥텟
    unsafe {
        crate::cpu::stac();
        core::ptr::copy_nonoverlapping(
            staging.as_ptr(),
            out_ptr as *mut u8,
            GAP_STATUS_LEN,
        );
        crate::cpu::clac();
    }

    // Phase 7 stack-local zeroize Shared-4 양면 staging + events_local
    staging.zeroize();
    for ev in events_local.iter_mut() {
        ev.seq = 0;
        ev.slot_idx = 0;
        ev.result = 0;
        ev.bus_kind = 0;
        ev._pad = 0;
        ev.pk_hash_prefix = [0; 4];
    }
    // 호출 자체는 AUDIT_RING 미기록 D-05 audit-of-audit 회피
    0
}
