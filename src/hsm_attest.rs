//! ML-DSA-44 어테스테이션 verifier 와 신뢰 루트 dual-path 와 정적 audit ring buffer 모듈
//!
//! # Features
//! Phase 5 ENROLL-01 ~ ENROLL-04 와 CAP-02 의 핵심 신규 모듈
//! attach-time 게이트 verify_attest 와 부팅 시 1 회 init_trust_root, Phase 6 가 읽어갈 AUDIT_RING 모두 본 모듈에 응집
//!
//! # 책임 경계
//! - 본 모듈은 attestation 검증 표면만 제공하고 syscall 본문이나 슬롯 mutation 은 다른 모듈 (`hsm_registry`) 책임
//! - `verify_attest` 는 `MLDSA44::verify` 의 4 variant + Ok(false) 모두 단일 `AttestError::AttestFailed` 로 collapse 하여 호출자에게 noop-return 형태 노출
//! - `with_attest_buf` 는 RELAY_BUF 와 동일 패턴이지만 별도 인스턴스 책임 경계와 호출 시점 분리
//! - `init_trust_root` 는 부팅 시 1 회만 호출, 런타임 회전 경로 부재

use blake::{BLAKE3_OUT_LEN, Blake3};
use mldsa::MLDSA44;
use zeroize::Zeroize;

use crate::bus::BusKind;
use crate::capability;

//
// HSM_TRUST_ROOT_PK_CONST 컴파일-타임 임베드 (D-01 dual-path 의 const 폴백)
//
// `include_bytes!` 가 keys/trust_root.pk44 의 1312 옥텟을 binary 에 직접 박음
// 본 const 는 init_trust_root 에서 keystore override 가 없을 때 ACTIVE_TRUST_ROOT_PK 로 복사됨

pub const HSM_TRUST_ROOT_PK_CONST: [u8; MLDSA44::PK_LEN] =
    *include_bytes!("../keys/trust_root.pk44");

const _: () = assert!(HSM_TRUST_ROOT_PK_CONST.len() == 1312);
const _: () = assert!(MLDSA44::PK_LEN == 1312);
const _: () = assert!(MLDSA44::SIG_LEN == 2420);

//
// 4 BSS singleton statics (D-01 / D-06 / D-09 / D-13)
//

/// 활성 신뢰 루트 ML-DSA-44 공개키 1312 옥텟
///
/// `init_trust_root` 가 부팅 시 1 회만 채움, 이후 `verify_attest` 가 `&raw const` 로만 접근
pub static mut ACTIVE_TRUST_ROOT_PK: [u8; MLDSA44::PK_LEN] = [0u8; MLDSA44::PK_LEN];

/// 부팅 세션 단위 challenge 32 옥텟 (D-09)
///
/// `capability::gen_token_u64` 4 회 호출 결과의 big-endian 연쇄로 채움
/// 부팅 마다 새로 생성되어 cross-boot replay 차단
pub static mut BOOT_CHALLENGE: [u8; 32] = [0u8; 32];

/// attestation staging buffer 한도 (D-06 RELAY_BUF 와 동일 크기, 책임 경계 분리)
pub const ATTEST_BUF_MAX: usize = 4096;

/// attestation SMAP staging buffer 4096 옥텟 (D-06)
///
/// PK_LEN_44 (1312) + SIG_LEN_44 (2420) = 3732 옥텟 + 364 옥텟 forward-reserve
/// 단일 syscall 안에서 `with_attest_buf` 안전 래퍼 진입 시 + 이탈 시 양면 zeroize
pub static mut ATTEST_BUF: [u8; ATTEST_BUF_MAX] = [0u8; ATTEST_BUF_MAX];

/// AUDIT_RING 의 정적 capacity (D-13)
pub const AUDIT_RING_CAPACITY: usize = 32;

//
// EnrollEvent 12 옥텟 ABI 잠금 (D-13)
//
// audit 목적 잔존 필요로 Zeroize derive 미적용 (D-13)
// _pad 1 옥텟이 8-옥텟 정렬 채움, pk_hash_prefix 가 BLAKE3(pk)[0..4] 시각 ID

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EnrollEvent {
    pub seq: u32,
    pub slot_idx: u8,
    pub result: u8,
    pub bus_kind: u8,
    pub _pad: u8,
    pub pk_hash_prefix: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<EnrollEvent>() == 12);

//
// AuditRing 헤더 (D-13)
//
// events 32 옥텟 슬롯 + head u8 monotonic mod 32 + total u32 누적 카운터
// 풋프린트 12*32 + 1 + 4 + alignment = 392 옥텟 BSS

#[repr(C)]
pub struct AuditRing {
    pub events: [EnrollEvent; AUDIT_RING_CAPACITY],
    pub head: u8,
    pub total: u32,
}

/// 단일 AUDIT_RING BSS singleton (D-13)
pub static mut AUDIT_RING: AuditRing = AuditRing {
    events: [EnrollEvent {
        seq: 0,
        slot_idx: 0,
        result: 0,
        bus_kind: 0,
        _pad: 0,
        pk_hash_prefix: [0u8; 4],
    }; AUDIT_RING_CAPACITY],
    head: 0,
    total: 0,
};

//
// AttestError single-variant collapse (D-11 / Pitfall 7)
//
// mldsa::Error 의 4 variant + verify Ok(false) 모두 단일 AttestFailed 로 매핑
// syscall 경계에서 호출자 측이 본 enum 을 SyscallError::Denied 로 추가 collapse 가정

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestError {
    AttestFailed,
}

//
// with_attest_buf RELAY_BUF 패턴 직접 mirror (D-06 / D-14)
//

/// ATTEST_BUF 에 대한 안전 래퍼 진입 이탈 양면 zeroize 보장
///
/// # Safety
/// BSP single-core 진입점에서만 호출 가능 FMASK 재진입 차단으로 syscall dispatch 의 단일 진입을 invariant 로 가정
/// SMP 도입 시 per-core ATTEST_BUF 또는 spinlock 필요
pub unsafe fn with_attest_buf<R>(f: impl FnOnce(&mut [u8; ATTEST_BUF_MAX]) -> R) -> R {
    // SAFETY BSP single-core; RELAY_BUF 와 동일 invariant
    let buf = unsafe { &mut *(&raw mut ATTEST_BUF) };
    // 진입 zeroize 이전 호출자 잔재 차단 (Pitfall 4 pre-entry)
    buf.zeroize();
    let r = f(buf);
    // 이탈 zeroize 다음 호출자 진입 안전 + 본 호출 결과 청결
    buf.zeroize();
    r
}

//
// init_trust_root 부팅 시 1 회 호출 init pattern (D-01 / D-09)
//
// (1) keystore override 경로 stub RESEARCH §14.2 Option (iii) compile-pass-only
// (2) const 폴백 → ACTIVE_TRUST_ROOT_PK 채움
// (3) BOOT_CHALLENGE = 4 회 gen_token_u64 의 big-endian 연쇄

/// 신뢰 루트 dual-path 초기화 + BOOT_CHALLENGE 생성
///
/// # Safety
/// 부팅 시 단일 코어에서 1 회만 호출 호출자가 `capability::init_prng` 완료를 보장해야 함
/// 본 함수가 ACTIVE_TRUST_ROOT_PK 와 BOOT_CHALLENGE 두 static 의 비원자적 갱신을 단일 진입으로 수행
pub unsafe fn init_trust_root() {
    // (1) keystore override 경로 RESEARCH §14.2 Option (iii) 채택 시 단순 false
    let from_keystore = false;

    // (2) const 폴백 → ACTIVE_TRUST_ROOT_PK 채움
    let pk_src: &[u8; MLDSA44::PK_LEN] = if from_keystore {
        unreachable!("§14.2 (iii) stub")
    } else {
        &HSM_TRUST_ROOT_PK_CONST
    };
    // SAFETY 단일 코어 부팅 초기 + ACTIVE_TRUST_ROOT_PK 의 단일 진입 갱신
    unsafe {
        (&mut *(&raw mut ACTIVE_TRUST_ROOT_PK)).copy_from_slice(pk_src);
    }

    // (3) BOOT_CHALLENGE 32 옥텟 채움 4 회 gen_token_u64 의 big-endian 연쇄
    let mut challenge = [0u8; 32];
    for i in 0..4 {
        // SAFETY 호출자가 capability::init_prng 완료를 보장
        let token = unsafe { capability::gen_token_u64().unwrap_or(0) };
        challenge[i * 8..(i + 1) * 8].copy_from_slice(&token.to_be_bytes());
    }
    // SAFETY 단일 코어 부팅 초기 + BOOT_CHALLENGE 의 단일 진입 갱신
    unsafe {
        (&mut *(&raw mut BOOT_CHALLENGE)).copy_from_slice(&challenge);
    }
    // stack-local challenge 잔재 zeroize
    challenge.zeroize();
}

//
// audit_enqueue ring-write singleton (D-13 / PATTERNS L283-294)
//

/// AUDIT_RING 에 단일 EnrollEvent 추가 ring-overwrite 정책
///
/// # Arguments
/// `slot_idx` 부착 슬롯 인덱스 또는 0xFF (실패 시)
/// `result` 0=Ok 1=AttestFailed 2=Full 3=BadInit 4=Other (D-13)
/// `bus_kind` BusKind 의 옥텟 표현
/// `pk_hash_prefix` BLAKE3(pk)[0..4] 4 옥텟 시각 ID
pub fn audit_enqueue(slot_idx: u8, result: u8, bus_kind: u8, pk_hash_prefix: [u8; 4]) {
    // SAFETY BSP single-core + FMASK 재진입 차단 가정 syscall dispatch 단일 진입
    unsafe {
        let r = &mut *(&raw mut AUDIT_RING);
        let i = (r.head as usize) % AUDIT_RING_CAPACITY;
        r.events[i] = EnrollEvent {
            seq: r.total,
            slot_idx,
            result,
            bus_kind,
            _pad: 0,
            pk_hash_prefix,
        };
        r.head = ((r.head as usize + 1) % AUDIT_RING_CAPACITY) as u8;
        r.total = r.total.wrapping_add(1);
    }
}

//
// audit_snapshot caller-provided slice + chronological copy (D-13 / PATTERNS L318-331)
//

/// AUDIT_RING 의 oldest-first 스냅샷을 caller-provided slice 에 복사
///
/// # Arguments
/// `out` Phase 6 GAP-04 sys_hsm_status 가 제공할 buffer (clamp 적용)
///
/// # Returns
/// `(written, total)` 실제로 채운 event 수 + 누적 enqueue 카운터 (loss 감지 hint)
pub fn audit_snapshot(out: &mut [EnrollEvent]) -> (usize, u32) {
    // SAFETY BSP single-core 진입 + AUDIT_RING 의 단일 진입 read
    unsafe {
        let r = &*(&raw const AUDIT_RING);
        let cap = out.len().min(AUDIT_RING_CAPACITY);
        let valid = (r.total as usize).min(AUDIT_RING_CAPACITY);
        // wrap 발생 후에는 r.head 가 oldest 위치, 미발생 시 0 부터 시작
        let start = if r.total as usize > AUDIT_RING_CAPACITY {
            r.head as usize
        } else {
            0
        };
        let n = valid.min(cap);
        for i in 0..n {
            out[i] = r.events[(start + i) % AUDIT_RING_CAPACITY];
        }
        (n, r.total)
    }
}

//
// pk_hash_prefix 헬퍼 BLAKE3(pk)[0..4] 4 옥텟 추출 (D-14 / Plan 05-03 가 audit_enqueue 호출 시 사용)
//

/// 공개키의 BLAKE3 해시 첫 4 옥텟을 시각 ID 로 추출
///
/// # Errors
/// 본 함수는 Blake3::finalize 실패 시 모든 0 옥텟을 반환 audit 목적이므로 noop fallback 채택
pub fn pk_hash_prefix(pk: &[u8; MLDSA44::PK_LEN]) -> [u8; 4] {
    let mut hasher = Blake3::new();
    hasher.update(pk);
    match hasher.finalize() {
        Ok(digest) => {
            let mut prefix = [0u8; 4];
            prefix.copy_from_slice(&digest.as_slice()[..4]);
            // BLAKE3_OUT_LEN 회귀 가드
            debug_assert_eq!(digest.as_slice().len(), BLAKE3_OUT_LEN);
            prefix
        }
        Err(_) => [0u8; 4],
    }
}
