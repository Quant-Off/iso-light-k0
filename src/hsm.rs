//! HSM(Hardware Security Module) 의 추상 인터페이스를 제공하는 모듈입니다.
//!
//! CLAUDE.md 의 "HSM 연동을 위한 드라이버 인터페이스는 항상 추상화된 트레이트
//! (Trait) 사용" 원칙에 따라, 본 트레이트는 장기 비밀(PSK) 에 대한 접근만을
//! 추상화합니다.
//!
//! HSM 보유 환경에서는 PSK 자체가 HSM 외부로 절대 유출되지 않으며,
//! HKDF-Extract 도 HSM 내부 HMAC 엔진으로 수행됩니다. HSM 부재 환경에서는
//! 동일 트레이트를 구현한 소프트웨어 키저장소(`crate::keystore::SoftKeystore`)
//! 가 메모리 상의 `Secret<>` 으로 PSK 를 보관하고 동등한 의미의 출력을
//! 반환합니다.
//!
//! TLS 키 스케줄(`tls::keyschedule`) 은 본 트레이트만 의존하므로 HSM 유무가
//! 상위 코드 경로에 노출되지 않습니다 (투명한 폴백).
//!
//! v1 한정: 임시 KEX 키(X25519, ML-KEM-768) 는 항상 소프트웨어에서 생성됩니다.
//! HSM 기반 임시 키 보호는 향후 본 트레이트의 확장 메소드로 추가될 예정입니다.

use constant_time::Choice;

use crate::crypto_service::SHA256_OUTPUT_SIZE;

/// PSK 식별자. TLS 1.3 의 `PskIdentity.identity` 필드와 동등한 16바이트 토큰.
///
/// 사이드채널 보호를 위해 등록된 식별자 비교는 constant-time 으로만 수행.
/// 식별자 자체는 비밀이 아니지만, 등록 여부 누설을 줄이기 위해 본 컨벤션 유지.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PskId(pub [u8; 16]);

impl PskId {
    pub const ZERO: Self = Self([0u8; 16]);

    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// HSM 드라이버 호출 실패 사유.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsmError {
    /// PSK 식별자가 등록되어 있지 않거나 등록 슬롯이 만료/소거됨.
    PskNotFound,
    /// HSM 이 본 환경에 없음 (NullHsm 의 모든 호출).
    NotProvisioned,
    /// 내부 일관성 위반(키 길이 불일치 등). 정상 환경에서는 발생하지 않음.
    Internal,
}

/// 장기 비밀(PSK) 에 대한 추상 인터페이스.
///
/// 폐쇄망에서 사전 분배된 PSK 를 통한 TLS 1.3 PSK 핸드셰이크가 본 트레이트만
/// 의존하므로, 동일 코드 경로가 HSM 환경 / 소프트 폴백을 모두 지원함.
///
/// # 보안 불변식
/// 1. PSK 자체는 본 트레이트의 어떤 메소드를 통해서도 외부로 반환되지 않음.
/// 2. `psk_hkdf_extract` 의 출력 PRK 는 호출자가 즉시 `Secret<>` 으로 감싸서
///    소거 책임을 보장해야 함.
/// 3. `psk_exists` 는 constant-time 결과를 반환해야 하며, 시간 사이드채널로
///    PSK 등록 여부가 누설되지 않아야 함 (구현체 의무).
/// 4. `psk_destroy` 는 호출 즉시 키 자료를 메모리에서 volatile-write 로 소거.
pub trait HsmDriver {
    /// 주어진 PSK 식별자가 사용 가능한 키 자료에 매핑되는지 constant-time 검사.
    ///
    /// 반환값 `Choice(1)` = 등록됨, `Choice(0)` = 미등록 또는 만료.
    fn psk_exists(&self, id: &PskId) -> Choice;

    /// HKDF-Extract(salt, PSK) 로 32바이트 PRK 를 출력.
    ///
    /// HSM 환경에서는 HMAC 연산이 HSM 내부 엔진으로 수행되어 PSK 가 메모리에
    /// 노출되지 않음. 소프트 폴백에서는 `Secret<PSK>` 를 임시 노출하여
    /// HMAC-SHA-256 을 실행한 뒤 즉시 스코프 종료로 소거함.
    ///
    /// # Errors
    /// - `PskNotFound`: 식별자가 미등록.
    /// - `Internal`: 키 자료 길이가 0 등 비정상.
    fn psk_hkdf_extract(
        &self,
        id: &PskId,
        salt: &[u8],
        prk_out: &mut [u8; SHA256_OUTPUT_SIZE],
    ) -> Result<(), HsmError>;

    /// 등록된 PSK 슬롯을 즉시 소거(volatile-write) 함.
    ///
    /// 미등록 슬롯에 대한 호출은 idempotent 이며 에러 없이 종료되어야 함.
    fn psk_destroy(&mut self, id: &PskId) -> Result<(), HsmError>;
}

//
// NullHsm: HSM 부재 환경
//

/// HSM 이 없는 환경의 기본 구현체.
///
/// 모든 PSK 조회는 `NotProvisioned` 를 반환하므로, 실제 PSK 가 필요한 경우
/// 사용자는 [`crate::keystore::SoftKeystore`] 를 명시적으로 인스턴스화해야 함.
/// 이 분기는 "HSM 없음 + PSK 미공급" 상태에서 TLS 핸드셰이크가 즉시 실패하도록
/// 하여 잘못된 운영 구성을 부팅 단계에서 차단하는 역할을 함.
pub struct NullHsm;

#[allow(clippy::new_without_default)]
impl NullHsm {
    pub const fn new() -> Self {
        Self
    }
}

impl HsmDriver for NullHsm {
    #[inline]
    fn psk_exists(&self, _id: &PskId) -> Choice {
        Choice::from_u8(0)
    }

    fn psk_hkdf_extract(
        &self,
        _id: &PskId,
        _salt: &[u8],
        _prk_out: &mut [u8; SHA256_OUTPUT_SIZE],
    ) -> Result<(), HsmError> {
        Err(HsmError::NotProvisioned)
    }

    fn psk_destroy(&mut self, _id: &PskId) -> Result<(), HsmError> {
        // 등록된 키가 없으므로 idempotent
        Ok(())
    }
}
