//! ML-DSA-44 어테스테이션 verifier 와 신뢰 루트 dual-path 와 정적 audit ring buffer 모듈
//!
//! # Features
//! 커널 부착 시점 어테스테이션 검증을 담당하는 핵심 모듈
//! attach-time 게이트 verify_attest 와 부팅 시 1 회 init_trust_root, AUDIT_RING 이 모두 본 모듈에 응집
//!
//! # 책임 경계
//! - 본 모듈은 attestation 검증 표면만 제공하고 syscall 본문이나 슬롯 mutation 은 다른 모듈 (`hsm_registry`) 책임
//! - `verify_attest` 는 `MLDSA44::verify` 의 4 variant + Ok(false) 모두 단일 `AttestError::AttestFailed` 로 collapse 하여 호출자에게 noop-return 형태 노출
//! - `with_attest_buf` 는 RELAY_BUF 와 동일 패턴이지만 별도 인스턴스 책임 경계와 호출 시점 분리
//! - `init_trust_root` 는 부팅 시 1 회만 호출, 런타임 회전 경로 부재

use blake::{BLAKE3_OUT_LEN, Blake3};
use mldsa::MLDSA44;
use zeroize::Zeroize;

// host lib 표면에서는 kernel 전용 의존 모듈 참조를 제외
#[cfg(target_os = "none")]
use crate::bus::BusKind;
#[cfg(target_os = "none")]
use crate::capability;

//
// HSM_TRUST_ROOT_PK_CONST 컴파일-타임 임베드 (dual-path 의 const 폴백)
//
// keystore cfg 활성 (K0_TRUST_ROOT_KEYSTORE 지정) 시 build.rs 가 검증하고 staging 한
// 프로덕션 PK 만 임베드하며 dev 상수는 바이너리에서 완전히 부재, cfg 비활성
// (closed/dev) 시 keys/trust_root.pk44 의 1312 옥텟 dev 키 임베드
// 본 const 는 init_trust_root 의 keystore 폴백 및 verify 경로에서 사용됨

#[cfg(k0_trust_root_keystore)]
pub const HSM_TRUST_ROOT_PK_CONST: [u8; MLDSA44::PK_LEN] = crate::keystore::KEYSTORE_TRUST_ROOT_PK;

#[cfg(not(k0_trust_root_keystore))]
pub const HSM_TRUST_ROOT_PK_CONST: [u8; MLDSA44::PK_LEN] =
    *include_bytes!("../keys/trust_root.pk44");

const _: () = assert!(HSM_TRUST_ROOT_PK_CONST.len() == 1312);
const _: () = assert!(MLDSA44::PK_LEN == 1312);
const _: () = assert!(MLDSA44::SIG_LEN == 2420);

//
// 4 BSS singleton statics
//

/// 활성 신뢰 루트 ML-DSA-44 공개키 1312 옥텟
///
/// `init_trust_root` 가 부팅 시 1 회만 채움, 이후 `verify_attest` 가 `&raw const` 로만 접근
#[used]
pub static mut ACTIVE_TRUST_ROOT_PK: [u8; MLDSA44::PK_LEN] = [0u8; MLDSA44::PK_LEN];

/// 부팅 세션 단위 challenge 32 옥텟
///
/// `capability::gen_token_u64` 4 회 호출 결과의 big-endian 연쇄로 채움
/// 부팅 마다 새로 생성되어 cross-boot replay 차단
#[used]
pub static mut BOOT_CHALLENGE: [u8; 32] = [0u8; 32];

/// attestation staging buffer 한도 (RELAY_BUF 와 동일 크기, 책임 경계 분리)
pub const ATTEST_BUF_MAX: usize = 4096;

/// attestation SMAP staging buffer 4096 옥텟
///
/// PK_LEN_44 (1312) + SIG_LEN_44 (2420) = 3732 옥텟 + 364 옥텟 forward-reserve
/// 단일 syscall 안에서 `with_attest_buf` 안전 래퍼 진입 시 + 이탈 시 양면 zeroize
#[used]
pub static mut ATTEST_BUF: [u8; ATTEST_BUF_MAX] = [0u8; ATTEST_BUF_MAX];

/// AUDIT_RING 의 정적 capacity
pub const AUDIT_RING_CAPACITY: usize = 32;

//
// EnrollEvent 12 옥텟 ABI 잠금
//
// audit 목적 잔존 필요로 Zeroize derive 미적용
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
// AuditRing 헤더
//
// events 32 옥텟 슬롯 + head u8 monotonic mod 32 + total u32 누적 카운터
// 풋프린트 12*32 + 1 + 4 + alignment = 392 옥텟 BSS

#[repr(C)]
pub struct AuditRing {
    pub events: [EnrollEvent; AUDIT_RING_CAPACITY],
    pub head: u8,
    pub total: u32,
}

/// 단일 AUDIT_RING BSS singleton
#[used]
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
// AttestError single-variant collapse
//
// mldsa::Error 의 4 variant + verify Ok(false) 모두 단일 AttestFailed 로 매핑
// syscall 경계에서 호출자 측이 본 enum 을 SyscallError::Denied 로 추가 collapse 가정

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestError {
    AttestFailed,
}

//
// with_attest_buf 는 RELAY_BUF 패턴 직접 mirror
//

/// ATTEST_BUF 에 대한 안전 래퍼 진입 이탈 양면 zeroize 보장
///
/// # Safety
/// BSP single-core 진입점에서만 호출 가능 FMASK 재진입 차단으로 syscall dispatch 의 단일 진입을 invariant 로 가정
/// SMP 도입 시 per-core ATTEST_BUF 또는 spinlock 필요
pub unsafe fn with_attest_buf<R>(f: impl FnOnce(&mut [u8; ATTEST_BUF_MAX]) -> R) -> R {
    // SAFETY BSP single-core; RELAY_BUF 와 동일 invariant
    let buf = unsafe { &mut *(&raw mut ATTEST_BUF) };
    // 진입 zeroize 이전 호출자 잔재 차단
    buf.zeroize();
    let r = f(buf);
    // 이탈 zeroize 다음 호출자 진입 안전 + 본 호출 결과 청결
    buf.zeroize();
    r
}

//
// init_trust_root 부팅 시 1 회 호출 init pattern
//
// (1) keystore override 경로 stub compile-pass-only
// (2) const 폴백으로 ACTIVE_TRUST_ROOT_PK 채움
// (3) BOOT_CHALLENGE = 4 회 gen_token_u64 의 big-endian 연쇄

/// 신뢰 루트 dual-path 초기화 + BOOT_CHALLENGE 생성
///
/// # Safety
/// 부팅 시 단일 코어에서 1 회만 호출 호출자가 `capability::init_prng` 완료를 보장해야 함
/// 본 함수가 ACTIVE_TRUST_ROOT_PK 와 BOOT_CHALLENGE 두 static 의 비원자적 갱신을 단일 진입으로 수행
#[cfg(target_os = "none")]
pub unsafe fn init_trust_root() {
    // (1) dual-path K0_TRUST_ROOT_KEYSTORE cfg 분기
    //
    // cfg 활성 (build.rs 가 K0_TRUST_ROOT_KEYSTORE=1|true|yes 인식)
    //   keystore slot 0xFE 의 raw 1312-옥텟 PK 로드 시도 None 폴백 시 const + audit_enqueue 경고
    // cfg 비활성 (closed 기본)
    //   HSM_TRUST_ROOT_PK_CONST 컴파일타임 임베드 직접 사용
    //
    // 두 분기 모두 cargo build 통과 미선택 경로 unreachable!() 0 회 hit
    #[cfg(k0_trust_root_keystore)]
    let pk_owned: [u8; MLDSA44::PK_LEN] = {
        // 빌드 임베드 프로덕션 PK 를 keystore slot 으로 공급 (provision 실사용 경로)
        // SAFETY BSP single-core 부팅 초기
        if unsafe { crate::keystore::provision_embedded_trust_root() }.is_err() {
            // 임베드 키가 무효(all-zero) result code = 9 (reserved 7..=255 활용)
            audit_enqueue(0xFE, 9u8, 0u8, [0u8; 4]);
        }
        match crate::keystore::read_trust_root_pk() {
            Some(pk) => pk,
            None => {
                // slot 미공급 폴백 이 경우 const 도 프로덕션 PK 임 (dev 상수 부재)
                // result code = 8 (TrustRootKeystoreMissing reserved 7..=255 활용)
                audit_enqueue(0xFE, 8u8, 0u8, [0u8; 4]);
                HSM_TRUST_ROOT_PK_CONST
            }
        }
    };
    #[cfg(k0_trust_root_keystore)]
    let pk_src: &[u8; MLDSA44::PK_LEN] = &pk_owned;
    #[cfg(not(k0_trust_root_keystore))]
    let pk_src: &[u8; MLDSA44::PK_LEN] = &HSM_TRUST_ROOT_PK_CONST;

    // (2) ACTIVE_TRUST_ROOT_PK copy (양 분기 공통)
    // SAFETY 단일 코어 부팅 초기 + ACTIVE_TRUST_ROOT_PK 의 단일 진입 갱신
    unsafe {
        (&mut *(&raw mut ACTIVE_TRUST_ROOT_PK)).copy_from_slice(pk_src);
    }

    // (3) BOOT_CHALLENGE 32 옥텟 채움 4 회 gen_token_u64 의 big-endian 연쇄
    let mut challenge = [0u8; 32];
    for i in 0..4 {
        // 엔트로피 실패 시 fail-open(unwrap_or(0)) 금지
        // 챌린지 생성 불가 = 어테스테이션 신선도 무효이므로 즉시 부팅 중단(fail-closed)
        // SAFETY 호출자가 capability::init_prng 완료를 보장
        let token = match unsafe { capability::gen_token_u64() } {
            Ok(t) => t,
            Err(_) => {
                challenge.zeroize();
                panic!("BOOT_CHALLENGE entropy unavailable (DRBG failure)");
            }
        };
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
// audit_enqueue ring-write singleton
//

/// AUDIT_RING 에 단일 EnrollEvent 추가 ring-overwrite 정책
///
/// # Arguments
/// `slot_idx` 부착 슬롯 인덱스 또는 0xFF (실패 시)
/// `result` 0=Ok 1=AttestFailed 2=Full 3=BadInit 4=Other
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
// audit_snapshot caller-provided slice 와 chronological copy
//

/// AUDIT_RING 의 oldest-first 스냅샷을 caller-provided slice 에 복사
///
/// # Arguments
/// `out` sys_hsm_status 가 제공할 buffer (clamp 적용)
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
        for (i, slot) in out.iter_mut().enumerate().take(n) {
            *slot = r.events[(start + i) % AUDIT_RING_CAPACITY];
        }
        (n, r.total)
    }
}

//
// verify_attest ML-DSA-44 어테스테이션 검증
//
// 서명 평문 = BLAKE3(pk(1312) || bus_kind(1) || BOOT_CHALLENGE(32)) 32 옥텟
// MLDSA44::verify 의 m_prime[1024] 한도 안에서 안전 (2 + ctx(16) + msg(32) = 50)
// 4 mldsa::Error variant + Ok(false) 모두 단일 AttestError::AttestFailed 로 collapse

/// ML-DSA-44 어테스테이션 서명을 신뢰 루트로 검증
///
/// # Arguments
/// `hsm_pk` HSM 자체의 ML-DSA-44 공개키 1312 옥텟
/// `bus_kind` HSM 부착 transport 분류 BUS_KIND_OCTET 으로 메시지에 포함
/// `sig` HSM 의 ML-DSA-44 서명 2420 옥텟
///
/// # Errors
/// `AttestError::AttestFailed` 4 mldsa::Error variant + verify Ok(false) 모두 단일 collapse
///
/// # Security Note
/// 메시지 재구성 + SMAP copy 는 입력값 독립 분기 verify 결과만 input-dependent
/// 모든 경로 (Ok 또는 Err) 에서 stack-local pre 와 digest 가 zeroize 되어 잔존 0
#[cfg(target_os = "none")]
pub fn verify_attest(
    hsm_pk: &[u8; MLDSA44::PK_LEN],
    bus_kind: BusKind,
    sig: &[u8; MLDSA44::SIG_LEN],
) -> Result<(), AttestError> {
    // (1) Pre-image 재구성 byte-exact copy 순서 고정 input-독립
    // layout pk(1312) || bus_kind_octet(1) || BOOT_CHALLENGE(32) = 1345 옥텟
    let mut pre = [0u8; MLDSA44::PK_LEN + 1 + 32];
    pre[0..MLDSA44::PK_LEN].copy_from_slice(hsm_pk);
    pre[MLDSA44::PK_LEN] = bus_kind as u8;
    // SAFETY BSP single-core BOOT_CHALLENGE 의 단일 진입 read
    unsafe {
        pre[MLDSA44::PK_LEN + 1..]
            .copy_from_slice(&*(&raw const BOOT_CHALLENGE));
    }

    // (2) BLAKE3 digest 산출
    // 서명 평문 = digest(32) 1024 옥텟 m_prime 한도 안에서 안전
    // BLAKE3 충돌저항 2^256 이 pk / bus / challenge substitution + replay 차단을 그대로 유지
    let mut digest = [0u8; 32];
    {
        let mut hasher = Blake3::new();
        hasher.update(&pre);
        match hasher.finalize() {
            Ok(d) => {
                digest.copy_from_slice(&d.as_slice()[..32]);
                debug_assert_eq!(d.as_slice().len(), BLAKE3_OUT_LEN);
            }
            Err(_) => {
                // BLAKE3 finalize 실패는 본 경계에서 검증 실패와 동일 collapse
                pre.zeroize();
                digest.zeroize();
                return Err(AttestError::AttestFailed);
            }
        }
    }

    // (3) ML-DSA-44 verify (ctx 16 옥텟 도메인 분리)
    // SAFETY BSP single-core ACTIVE_TRUST_ROOT_PK 의 단일 진입 read
    let trust_root = unsafe { &*(&raw const ACTIVE_TRUST_ROOT_PK) };
    let result = MLDSA44::verify(trust_root, &digest, sig, b"ISO-K0-ENROLL-V1");

    // (4) 4 mldsa::Error variant + Ok(false) 를 단일 AttestFailed 로 collapse
    // single match expression 분기 분리 X (CT 일관)
    let outcome = match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(AttestError::AttestFailed),
        Err(_) => Err(AttestError::AttestFailed),
    };

    // (5) 모든 경로 stack-local zeroize
    pre.zeroize();
    digest.zeroize();
    outcome
}

//
// pk_hash_prefix 헬퍼 BLAKE3(pk)[0..4] 4 옥텟 추출
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
