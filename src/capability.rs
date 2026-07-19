//! Capability-based Access Control(CBAC) 을 수행하는 모듈입니다.
//!
//! Capability 는 "특정 엔드포인트에 특정 권한으로 접근할 수 있다" 는 위조 불가
//! 토큰이며, 토큰 없이는 IPC 엔드포인트에 접근할 수 없습니다.
//!
//! 토큰은 `elib-k0-nt` 의 `rng::HashDRBGSHA256` (NIST SP 800-90A Rev.1) 으로
//! 생성되며 시드는 x86 RDSEED(우선) / RDRAND(폴백) 의 CPU 하드웨어 엔트로피로
//! 채웁니다. 2^48 회 이후 자동 재시드되며 매 재시드마다 RDSEED 엔트로피를
//! 재수집합니다.
//!
//! Capability 위임(GRANT) 은 부모가 보유한 권한의 부분집합만 허용하는 축소
//! 원칙을 따르고, 원본이 철회되면 위임받은 Capability 도 자동 무효화되어야
//! 합니다 (TODO).
//!
//! 토큰 비교는 `CtEqOps` 의 constant-time 비교로 타이밍 사이드채널을
//! 차단하며, 사용이 끝난 Capability 는 `Zeroize` 로 토큰 값이 즉시 소거됩니다.

use constant_time::{Choice, CtEqOps};
use rng::{DrbgError, HashDRBGSHA256};
use zeroize::Zeroize;

//
// 권한 비트마스크
//

/// IPC 엔드포인트에 대한 접근 권한 집합.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Rights(pub u32);

impl Rights {
    /// 권한 없음
    pub const NONE: Self = Self(0);
    /// 메시지 전송 (단방향)
    pub const SEND: Self = Self(1 << 0);
    /// 메시지 수신 (서버측)
    pub const RECV: Self = Self(1 << 1);
    /// 동기 호출 = SEND + RECV (클라이언트 call)
    pub const CALL: Self = Self(1 << 2);
    /// 다른 주체에게 Capability 위임 가능
    pub const GRANT: Self = Self(1 << 3);
    /// 모든 권한
    pub const ALL: Self = Self(0x0F);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// 축소 위임: self ∩ subset만 허용 (부모 권한을 초과할 수 없음)
    #[inline]
    pub const fn restrict(self, subset: Self) -> Self {
        Self(self.0 & subset.0)
    }
}

//
// 엔드포인트 식별자
//

/// IPC 엔드포인트 고유 식별자 (0xFFFF = 무효).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct EndpointId(pub u16);

impl EndpointId {
    pub const INVALID: Self = Self(0xFFFF);
}

/// 잘 알려진(well-known) 커널 서비스 엔드포인트 ID.
pub const EP_SYSTEM: EndpointId = EndpointId(0x0000); // 커널 시스템 콜
pub const EP_CRYPTO: EndpointId = EndpointId(0x0001); // 암호화 서비스
pub const EP_SIGN: EndpointId = EndpointId(0x0002);   // ML-DSA PQ 서명 서비스
pub const EP_LUMEN_WIRE: EndpointId = EndpointId(0x0003); // Phase 4 Ring 3 lumen wire endpoint (D-13)

//
// Capability 토큰
//

/// 위조 불가 Capability 토큰 (16 bytes).
///
/// 64비트 난수 + 엔드포인트 ID + 권한으로 구성됨.
/// 토큰 값 없이는 `is_valid_for()`를 통과할 수 없으므로
/// 추측에 의한 권한 상승이 불가능함.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Capability {
    /// 위조 방지용 난수값 (0 = 무효 토큰)
    pub token: u64,
    /// 접근 대상 엔드포인트
    pub endpoint_id: EndpointId,
    /// 허용 권한 집합
    pub rights: Rights,
    _pad: u16,
}

impl Capability {
    /// 항상 거부되는 Null Capability.
    pub const fn null() -> Self {
        Self {
            token: 0,
            endpoint_id: EndpointId::INVALID,
            rights: Rights::NONE,
            _pad: 0,
        }
    }

    /// 이 Capability가 `endpoint_id`에 대해 `required` 권한을 보유하는지
    /// 상수-시간으로 검증함.
    ///
    /// 검증 조건:
    ///   1. 토큰이 0이 아님 (무효 토큰 거부)       (CT)
    ///   2. 대상 엔드포인트 일치                   (CT)
    ///   3. 요구 권한이 허용 권한에 포함됨         (분기 없음, 비트마스크)
    ///
    /// # Security Note
    /// 토큰 비교는 `CtEqOps`를 사용하여 조기 종료(early-exit) 없는 비교를
    /// 수행함. 최종 AND 결과를 `unwrap_u8() == 1` 로 변환하는 시점에서만
    /// 외부 관찰 가능한 분기가 발생하며, 이는 검증 결과 자체(allow/deny)를
    /// 노출하는 의도된 경로임.
    #[inline]
    pub fn is_valid_for(&self, endpoint_id: EndpointId, required: Rights) -> bool {
        // 토큰 != 0
        let token_nonzero: Choice = CtEqOps::ne(&self.token, &0u64);
        // 대상 엔드포인트 일치
        let ep_eq: Choice = CtEqOps::eq(&self.endpoint_id.0, &endpoint_id.0);
        // 요구 권한이 보유 권한의 부분집합인지 (비트마스크 AND 는 값/인덱스
        // 의존 분기가 없어 본질적으로 상수-시간)
        let masked: u32 = self.rights.0 & required.0;
        let rights_ok: Choice = CtEqOps::eq(&masked, &required.0);

        (token_nonzero & ep_eq & rights_ok).unwrap_u8() == 1
    }

    /// 두 Capability 토큰을 상수-시간으로 비교함.
    ///
    /// 슬롯 조회/위조 탐지 등에서 토큰 일치 여부를 판단할 때 사용.
    #[inline]
    pub fn ct_token_eq(&self, other: &Self) -> Choice {
        CtEqOps::eq(&self.token, &other.token)
    }

    /// 권한을 축소하여 새 Capability를 생성 (위임용, GRANT 권한 필요).
    ///
    /// 반환된 Capability는 self의 권한 부분집합만 가짐 (축소 원칙 적용).
    pub fn derive(&self, subset_rights: Rights) -> Result<Self, CapError> {
        if !self.rights.contains(Rights::GRANT) {
            return Err(CapError::NoGrantRight);
        }
        Ok(Self {
            token: self.token,
            endpoint_id: self.endpoint_id,
            rights: self.rights.restrict(subset_rights),
            _pad: 0,
        })
    }
}

impl Zeroize for Capability {
    fn zeroize(&mut self) {
        self.token.zeroize();
        self.rights = Rights::NONE;
        self.endpoint_id = EndpointId::INVALID;
    }
}

//
// 하드웨어 엔트로피 수집
//

/// `buf` 를 하드웨어 엔트로피로 채움 (RDSEED 우선, RDRAND 폴백).
///
/// RDSEED/RDRAND inline-asm 본문은 `arch::x86_64::entropy::hw` 로 lossless
/// move 되었으며 본 함수는 그 어댑터로의 bridge 표면만 유지함.
///
/// # Errors
/// `CapError::NoEntropy` — CPU에 RDSEED/RDRAND 가 없거나 재시도 한도 내에
/// 충분한 엔트로피를 수집하지 못한 경우.
///
/// # Safety
/// 단일 코어 부팅 초기 혹은 적절한 동기화 이후에 호출되어야 함.
/// CPU 기능 탐지(`cpu::enable_simd_fpu`)가 먼저 수행되어야 함.
unsafe fn fill_hw_entropy(buf: &mut [u8]) -> Result<(), CapError> {
    use crate::arch::common::entropy::{EntropyError, QuorumEntropy};

    // ENTR-06 단일점 최종 교체 arch-중립 QuorumEntropy 진입점 D-05 60sec 폴링
    // SAFETY: capability::init_prng 또는 reseed_drbg 호출자가 단일 코어 + cpu::features() 완료 보장
    match unsafe { QuorumEntropy::collect_with_retry(buf, 60_000) } {
        Ok(()) => Ok(()),
        Err(EntropyError::QuorumFailed) => Err(CapError::NoEntropy),
        Err(EntropyError::SourceUnavailable) => Err(CapError::NoEntropy),
        Err(EntropyError::HealthTestFailed) => Err(CapError::NoEntropy),
    }
}

//
// DRBG 기반 PRNG
//

/// 시드/nonce/개인화 문자열의 최대 크기 (HashDRBGSHA256 기준).
///
/// HashDRBGSHA256: security_strength = 128 bits (= 16 bytes).
///   entropy_input = 32 bytes (2 × security_strength)
///   nonce         = 16 bytes (security_strength, 독립 수집)
const ENTROPY_LEN: usize = 32;
const NONCE_LEN: usize = 16;

/// Capability 토큰 발급용 DRBG 상태.
///
/// # Safety
/// - 단일 코어 부팅 초기에만 Option이 None일 수 있음.
/// - `init_prng()` 이후에는 SMP 전환 시 spinlock 으로 보호해야 함 (TODO).
static mut CAP_DRBG: Option<HashDRBGSHA256> = None;

/// 부트 시점 개인화 바이트열 (DRBG 인스턴스 유일성 확보).
///
/// 동일 하드웨어라도 다른 부트 인스턴스가 동일 DRBG 상태로 수렴하지 않도록
/// 부트마다 달라지는 값을 혼합함 (RDSEED 기반).
const PERSONALIZATION_TAG: &[u8] = b"iso-light-k0:cap-drbg:v1";

/// 부팅 초기 단일 코어에서 Capability DRBG를 초기화함.
///
/// # Errors
/// - `CapError::NoEntropy`: CPU RDSEED/RDRAND 미지원 또는 수집 실패
/// - `CapError::DrbgInit`:  DRBG 내부 초기화 실패 (비정상적)
///
/// # Safety
/// - `cpu::enable_simd_fpu()` 이후 호출해야 함 (CPU 기능 탐지 완료 전제)
/// - 단일 코어 부팅 초기에서만 호출
pub unsafe fn init_prng() -> Result<(), CapError> {
    // 독립 수집: entropy_input 과 nonce 를 서로 다른 HW RNG 호출 시퀀스로 분리
    let mut entropy = [0u8; ENTROPY_LEN];
    let mut nonce = [0u8; NONCE_LEN];

    // SAFETY: 호출자가 단일 코어 + CPU 기능 탐지 완료를 보장
    unsafe {
        fill_hw_entropy(&mut entropy)?;
        fill_hw_entropy(&mut nonce)?;
    }

    // SAFETY: 위 문서화된 안전 조건대로 호출자는 호출자가 강한 엔트로피 주입 책임
    let drbg = unsafe {
        HashDRBGSHA256::new_from_entropy(&entropy, &nonce, Some(PERSONALIZATION_TAG))
            .map_err(|_| CapError::DrbgInit)?
    };

    // 엔트로피 스택 버퍼 즉시 소거
    entropy.zeroize();
    nonce.zeroize();

    // SAFETY: 단일 코어 부팅 초기
    unsafe {
        *(&raw mut CAP_DRBG) = Some(drbg);
    }
    Ok(())
}

/// DRBG 재시드 (2^48 회 생성 초과 시 필요).
///
/// # Safety
/// 단일 코어 혹은 외부 동기화 보장 상태에서만 호출.
unsafe fn reseed_drbg(drbg: &mut HashDRBGSHA256) -> Result<(), CapError> {
    let mut entropy = [0u8; ENTROPY_LEN];
    // SAFETY: 호출자가 단일 코어 보장
    unsafe {
        fill_hw_entropy(&mut entropy)?;
    }

    let r = drbg.reseed(&entropy, None).map_err(|_| CapError::DrbgInit);
    entropy.zeroize();
    r
}

//
// Capability 생성
//

/// 지정 엔드포인트와 권한으로 새 Capability를 생성함.
///
/// NIST SP 800-90A Rev.1 HashDRBGSHA256 출력에서 64비트 토큰을 추출.
/// 극저확률(2^-64)로 0 이 출력되는 경우 재시도.
///
/// # Errors
/// - `CapError::PrngNotInitialized`: `init_prng()` 미호출
/// - `CapError::DrbgInit`: 재시드 실패
/// - `CapError::NoEntropy`: 재시드 엔트로피 수집 실패
///
/// # Safety
/// 단일 코어 부팅 초기에서만 호출해야 함 (DRBG 상태 비원자적 갱신).
/// SMP 이후에는 spinlock 보호가 필요함.
pub unsafe fn generate_capability(
    endpoint_id: EndpointId,
    rights: Rights,
) -> Result<Capability, CapError> {
    // SAFETY: gen_token_u64 의 안전 계약을 호출자가 그대로 만족 (단일 코어 부팅 초기)
    let token = unsafe { gen_token_u64()? };
    Ok(Capability { token, endpoint_id, rights, _pad: 0 })
}

//
// DRBG 일반 난수 추출기
//

/// 커널 DRBG(Hash-DRBG-SHA-256) 에서 임의 길이의 난수를 출력함.
///
/// TLS 임시 키, Capability 토큰 외 일반 난수가 필요한 모든 커널 서비스가
/// 본 함수를 통해서만 엔트로피에 접근하도록 단일 진입점을 둠.
/// `ReseedRequired` 시 자동으로 하드웨어 엔트로피로 재시드.
///
/// # Errors
/// `init_prng()` 미호출 / 재시드 실패 시 `CapError`.
///
/// # Safety
/// 단일 코어 부팅 초기 호출만 안전 (DRBG 상태 비원자적). SMP 이후 spinlock 필요.
pub unsafe fn rand_bytes(buf: &mut [u8]) -> Result<(), CapError> {
    // SAFETY: 단일 코어 부팅 초기 접근
    let drbg_slot = unsafe { &mut *(&raw mut CAP_DRBG) };
    let drbg = drbg_slot.as_mut().ok_or(CapError::PrngNotInitialized)?;

    // RESEED_INTERVAL 까지의 한 호출당 안전 한계는 elib-k0-nt 가 강제하므로
    // 단일 generate() 호출로 충분. ReseedRequired 시 재시드 후 재시도
    loop {
        match drbg.generate(buf, None) {
            Ok(()) => return Ok(()),
            Err(DrbgError::ReseedRequired) => {
                // SAFETY: 호출자가 단일 코어 보장
                unsafe {
                    reseed_drbg(drbg)?;
                }
                continue;
            }
            Err(_) => {
                // 출력 버퍼는 부분적으로 채워졌을 수 있으므로 즉시 소거
                // SAFETY: buf 는 호출자가 보장한 유효한 슬라이스
                unsafe {
                    zeroize::volatile::secure_zero(buf.as_mut_ptr(), buf.len());
                }
                return Err(CapError::DrbgInit);
            }
        }
    }
}

pub unsafe fn gen_token_u64() -> Result<u64, CapError> {
    // SAFETY: 단일 코어 부팅 초기 접근 (CAP_DRBG 비원자적 갱신)
    let drbg_slot = unsafe { &mut *(&raw mut CAP_DRBG) };
    let drbg = drbg_slot.as_mut().ok_or(CapError::PrngNotInitialized)?;

    // 토큰 생성 루프 (0 출력 회피 + ReseedRequired 자동 재시드)
    let mut token_bytes = [0u8; 8];
    loop {
        match drbg.generate(&mut token_bytes, None) {
            Ok(()) => {
                // NIST 출력은 big-endian 스트림으로 해석 (little-endian 이어도 균일성 유지)
                let token = u64::from_be_bytes(token_bytes);
                token_bytes.zeroize();
                if token != 0 {
                    return Ok(token);
                }
                // 0 출력은 무효 토큰 규약과 충돌 -> 재시도 (확률 2^-64)
                continue;
            }
            Err(DrbgError::ReseedRequired) => {
                // SAFETY: 호출자가 단일 코어 보장 (DRBG 재시드 안전)
                unsafe {
                    reseed_drbg(drbg)?;
                }
                continue;
            }
            Err(_) => {
                token_bytes.zeroize();
                return Err(CapError::DrbgInit);
            }
        }
    }
}

//
// Capability 공간
//

/// 프로세스당 Capability 슬롯 최대 수.
pub const MAX_CAPS_PER_SPACE: usize = 32;

/// 프로세스별 Capability 보관 공간.
///
/// 각 프로세스는 고유한 `CapabilitySpace`를 가지며,
/// 커널은 이 공간의 슬롯 인덱스를 핸들로 노출함.
pub struct CapabilitySpace {
    slots: [Option<Capability>; MAX_CAPS_PER_SPACE],
    count: usize,
}

impl CapabilitySpace {
    pub const fn empty() -> Self {
        Self {
            slots: [None; MAX_CAPS_PER_SPACE],
            count: 0,
        }
    }

    /// Capability를 슬롯에 삽입하고 슬롯 인덱스를 반환.
    pub fn insert(&mut self, cap: Capability) -> Option<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(cap);
                self.count += 1;
                return Some(i);
            }
        }
        None // 슬롯 부족
    }

    /// 슬롯 인덱스로 Capability를 조회.
    pub fn get(&self, idx: usize) -> Option<&Capability> {
        self.slots.get(idx)?.as_ref()
    }

    /// 상수-시간 토큰 비교로 보유 Capability 슬롯을 탐색.
    ///
    /// 전 슬롯을 순회하여 모든 슬롯에 대해 동일한 시간만큼 비교를 수행함.
    /// (조기 종료 없음 -> 타이밍 사이드채널 차단)
    pub fn find_by_token(&self, token: u64) -> Option<usize> {
        let mut found_idx: isize = -1;
        let query = Capability {
            token,
            endpoint_id: EndpointId::INVALID,
            rights: Rights::NONE,
            _pad: 0,
        };
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(cap) = slot {
                let m = cap.ct_token_eq(&query);
                // 조기 종료 없이 선택적 대입 (value != 0 인 첫 일치 유지)
                if m.unwrap_u8() == 1 && cap.token != 0 && found_idx < 0 {
                    found_idx = i as isize;
                    // 계속 순회하여 타이밍 평탄화
                }
            }
        }
        if found_idx >= 0 {
            Some(found_idx as usize)
        } else {
            None
        }
    }

    /// 슬롯의 Capability를 철회(revoke)하고 토큰을 소거함.
    pub fn revoke(&mut self, idx: usize) -> Result<(), CapError> {
        let slot = self.slots.get_mut(idx).ok_or(CapError::InvalidSlot)?;
        if let Some(cap) = slot {
            cap.zeroize(); // 토큰 값 즉시 소거
        }
        *slot = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }
}

//
// 에러 타입
//

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    /// 슬롯 인덱스가 범위를 벗어남
    InvalidSlot,
    /// GRANT 권한이 없어 위임 불가
    NoGrantRight,
    /// 슬롯 공간 부족
    SlotsFull,
    /// DRBG 가 아직 초기화되지 않음 (`init_prng()` 미호출)
    PrngNotInitialized,
    /// CPU 에 RDSEED/RDRAND 가 없거나 하드웨어 엔트로피 수집 실패
    NoEntropy,
    /// DRBG 내부 초기화 / 재시드 실패
    DrbgInit,
}
