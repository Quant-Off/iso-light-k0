//! TLS 1.3 (PSK-only) 커널 서비스를 수행하는 모듈입니다.
//!
//! 본 모듈은 RFC 8446 의 TLS 1.3 PSK 핸드셰이크(`psk_dhe_ke` /
//! `psk_pq_hybrid_ke`) 만 구현합니다.
//!
//! 범위 및 위협 모델:
//!   - 인증: 사전 분배 PSK 만 (X.509 / 인증서 체인 미포함)
//!   - PFS:  X25519 또는 X25519+ML-KEM-768 으로 항상 보장 (no `psk_ke`)
//!   - AEAD: AES-256-GCM-SHA256 / ChaCha20-Poly1305-SHA256
//!   - 0-RTT 미지원 (replay 공격 표면 차단)
//!   - Renegotiation 미지원 (TLS 1.3 자체 미지원)
//!
//! 프로파일:
//!   - `Profile::Closed`   : 폐쇄망 전용 (default, `tls-external` 무관).
//!   - `Profile::External` : 외부망 (`tls-external` Cargo feature 필요).
//!     컴파일 게이팅과 런타임 별도 Capability 로 이중 보호함.
//!
//! KEX 정책:
//!   - `KexPolicy::Hybrid`    : X25519 + ML-KEM-768 (양자 안전, 권장)
//!   - `KexPolicy::Classical` : X25519 단독 (레거시 호환 허용)
//!
//! 메모리/할당:
//!   - 모든 키/시크릿/평문 중간값은 `Secret<>` 으로 래핑되어 자동 소거됨
//!   - 동적 할당 없음 (커넥션 풀 정적)
//!   - Finished/binder MAC 비교는 constant-time

pub mod handshake;
pub mod keyschedule;
pub mod record;
pub mod transcript;

use zeroize::Secret;
use zeroize::volatile::secure_zero;

use crate::crypto_service::SHA256_OUTPUT_SIZE;
use crate::hsm::{HsmError, PskId};
use crate::keystore::KeystoreError;

//
// 정적 풀 / 상수
//

/// 동시 활성 TLS 커넥션 최대 수.
/// `static mut` 풀로 관리되며, SMP 도입 시 spinlock 보호 필요.
pub const MAX_TLS_CONNS: usize = 4;

/// 트랜스크립트 버퍼 최대 길이 (PQ-hybrid CH/SH 의 ML-KEM share 수용).
pub const TRANSCRIPT_BUF_LEN: usize = 4096;

/// AEAD 키 / IV / 태그 크기 (suite 무관 — 본 커널 정책상 고정).
pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_IV_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

// ML-KEM-768 (FIPS 203) 정수 — elib-k0-nt 내부 상수와 동일하나
// 그쪽이 pub(crate) 이므로 여기서 별도 선언
pub const TLS_MLKEM768_PK_LEN: usize = 1184;
pub const TLS_MLKEM768_CT_LEN: usize = 1088;

// X25519 (RFC 7748) 공개키 / 공유비밀 길이
pub const TLS_X25519_PK_LEN: usize = 32;
pub const TLS_KEM_SS_LEN: usize = 32;

// PSK / 키 스케줄 출력은 모두 32바이트 (HKDF-SHA-256 단일화)
pub const TLS_HASH_LEN: usize = SHA256_OUTPUT_SIZE; // 32

//
// 프로파일 / 정책 / 슈트
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// 폐쇄망 — 사전 분배 PSK 기반, 본 커널 기본.
    Closed,
    /// 외부망 — `tls-external` Cargo feature + 런타임 Capability 가 모두 있을 때만.
    #[cfg(feature = "tls-external")]
    External,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexPolicy {
    /// X25519 + ML-KEM-768 hybrid (양자 안전, 본 커널 기본 권장).
    Hybrid,
    /// X25519 단독 — 레거시 시스템 호환 (옵트인).
    Classical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherSuite {
    /// AES-256-GCM + HKDF-SHA-256 (본 커널 정의 — IANA 미등록).
    Aes256GcmSha256 = 0x01,
    /// ChaCha20-Poly1305 + HKDF-SHA-256 (RFC 8446 §B.4 의 SHA-256 변형).
    ChaCha20Poly1305Sha256 = 0x02,
}

impl CipherSuite {
    /// 모든 슈트가 동일 키/IV 길이를 사용하므로 단일 함수로 충분.
    pub const fn key_len(&self) -> usize {
        AEAD_KEY_LEN
    }
    pub const fn iv_len(&self) -> usize {
        AEAD_IV_LEN
    }
    pub const fn tag_len(&self) -> usize {
        AEAD_TAG_LEN
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

//
// 에러
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsError {
    /// 풀에 빈 슬롯 없음.
    PoolFull,
    /// 잘못된 핸들 또는 사용 종료된 커넥션.
    InvalidHandle,
    /// 트랜스크립트 버퍼 한계 초과 (잘못된/악의적 메시지 입력)
    TranscriptOverflow,
    /// 메시지 길이 / 형식 검증 실패.
    BadMessage,
    /// 핸드셰이크 상태 머신 위반 (잘못된 순서로 진입).
    UnexpectedState,
    /// PSK 식별자가 등록되어 있지 않음 / 일치하지 않음.
    UnknownPsk,
    /// 본 환경에서 외부망 프로파일이 비활성화되어 있음.
    ProfileDisabled,
    /// HSM/Keystore 호출 실패.
    HsmFailure,
    /// AEAD 인증 실패 (변조 또는 키 불일치)
    AuthenticationFailed,
    /// Finished MAC 검증 실패.
    FinishedMismatch,
    /// 시퀀스 번호 한계 초과 (rekey 필요).
    SequenceExhausted,
    /// 평문 / 암호문 길이가 슬롯 capacity 초과.
    BufferTooSmall,
    /// 본 컨텍스트에서 허용되지 않는 KEX 정책.
    KexPolicyMismatch,
    /// 내부 일관성 위반.
    Internal,
}

impl From<HsmError> for TlsError {
    fn from(e: HsmError) -> Self {
        match e {
            HsmError::PskNotFound => TlsError::UnknownPsk,
            _ => TlsError::HsmFailure,
        }
    }
}

impl From<KeystoreError> for TlsError {
    fn from(_: KeystoreError) -> Self {
        TlsError::HsmFailure
    }
}

//
// 트래픽 키 (양 방향)
//

/// 한 방향(읽기/쓰기) 의 AEAD 키/IV + 시퀀스 카운터.
///
/// `Secret<>` 으로 보호되며 Drop 시 자동 소거.
pub struct DirectionalKeys {
    pub key: Secret<[u8; AEAD_KEY_LEN]>,
    pub iv: Secret<[u8; AEAD_IV_LEN]>,
    pub seq: u64,
}

impl DirectionalKeys {
    pub fn empty() -> Self {
        Self {
            key: Secret::new([0u8; AEAD_KEY_LEN]),
            iv: Secret::new([0u8; AEAD_IV_LEN]),
            seq: 0,
        }
    }

    /// 강제 소거 (커넥션 종료 시 호출).
    pub fn wipe(&mut self) {
        // SAFETY: Secret 내부 버퍼는 유효한 고정 크기 메모리
        unsafe {
            secure_zero(self.key.expose_mut().as_mut_ptr(), AEAD_KEY_LEN);
            secure_zero(self.iv.expose_mut().as_mut_ptr(), AEAD_IV_LEN);
        }
        self.seq = 0;
    }
}

//
// 커넥션 상태
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnState {
    /// 슬롯 미할당 / 폐기됨.
    Free,
    /// 핸드셰이크 진행 중.
    Handshaking,
    /// 핸드셰이크 완료 (application_data 송수신 가능)
    Connected,
    /// 정상 종료 또는 실패 후 키 자료 소거됨 (재사용 불가)
    Closed,
}

/// TLS 커넥션 슬롯.
///
/// 크기 분석 (대략): transcript 4 KiB + record buffer 등 << 8 KiB.
/// 풀 전체 = MAX_TLS_CONNS x 8 KiB ~= 32 KiB (커널 정적 영역).
pub struct TlsConnection {
    pub state: ConnState,
    pub side: Side,
    pub profile: Profile,
    pub policy: KexPolicy,
    pub suite: CipherSuite,
    pub psk_id: PskId,
    pub transcript: transcript::Transcript,
    /// 핸드셰이크 종료 직후 application 트래픽 키.
    pub app_write: DirectionalKeys,
    pub app_read: DirectionalKeys,
}

impl TlsConnection {
    pub fn empty() -> Self {
        Self {
            state: ConnState::Free,
            side: Side::Client,
            profile: Profile::Closed,
            policy: KexPolicy::Hybrid,
            suite: CipherSuite::Aes256GcmSha256,
            psk_id: PskId::ZERO,
            transcript: transcript::Transcript::new(),
            app_write: DirectionalKeys::empty(),
            app_read: DirectionalKeys::empty(),
        }
    }

    /// 모든 키 자료 소거 + Closed 상태 전이.
    pub fn close_and_wipe(&mut self) {
        self.app_write.wipe();
        self.app_read.wipe();
        self.transcript.wipe();
        self.state = ConnState::Closed;
    }
}

/// 슬롯 핸들 (외부 노출).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ConnHandle(pub u8);

//
// 정적 커넥션 풀
//
// `Secret::new` 가 const fn 이 아니므로 슬롯은 `Option<TlsConnection>` 으로
// 시작하여 alloc 시점에 lazy 하게 인스턴스화됨. close 시 `None` 으로 되돌리며
// `Drop` 으로 모든 `Secret<>` 필드가 volatile-write 로 소거됨
static mut TLS_POOL: [Option<TlsConnection>; MAX_TLS_CONNS] = [None, None, None, None];

/// # Safety
/// 단일 코어 / 외부 동기화가 보장된 상태에서만 호출.
#[allow(clippy::mut_from_ref)]
unsafe fn pool_mut() -> &'static mut [Option<TlsConnection>; MAX_TLS_CONNS] {
    // SAFETY: 호출자 보장
    unsafe { &mut *(&raw mut TLS_POOL) }
}

pub(crate) fn alloc_slot() -> Result<ConnHandle, TlsError> {
    // SAFETY: 단일 코어 부팅 초기 가정
    let pool = unsafe { pool_mut() };
    for (i, opt) in pool.iter_mut().enumerate() {
        if opt.is_none() {
            *opt = Some(TlsConnection::empty());
            return Ok(ConnHandle(i as u8));
        }
    }
    Err(TlsError::PoolFull)
}

pub(crate) fn slot(h: ConnHandle) -> Result<&'static mut TlsConnection, TlsError> {
    let pool = unsafe { pool_mut() };
    pool.get_mut(h.0 as usize)
        .and_then(|o| o.as_mut())
        .ok_or(TlsError::InvalidHandle)
}

//
// 외부 공개 API
//

/// TLS 커넥션 종료. 모든 키 자료를 즉시 소거하고 슬롯을 회수함.
pub fn close(h: ConnHandle) -> Result<(), TlsError> {
    let pool = unsafe { pool_mut() };
    let opt = pool.get_mut(h.0 as usize).ok_or(TlsError::InvalidHandle)?;
    if let Some(c) = opt.as_mut() {
        c.close_and_wipe();
    }
    // `Drop` 으로 모든 Secret<> 자동 소거 + 슬롯 비움
    *opt = None;
    Ok(())
}

/// 풀 전체 강제 소거 (시스템 종료 / 비상 시).
///
/// # Safety
/// 단일 코어 / 외부 동기화 보장 상태에서만 호출.
pub unsafe fn wipe_all() {
    let pool = unsafe { pool_mut() };
    for opt in pool.iter_mut() {
        if let Some(c) = opt.as_mut() {
            c.close_and_wipe();
        }
        *opt = None;
    }
}
