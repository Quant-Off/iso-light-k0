//! HSM 부재 환경의 보안 폴백으로 동작하는 소프트웨어 PSK 키 저장소를
//! 제공하는 모듈입니다.
//!
//! HSM 이 없는 환경에서 사전 분배된 PSK 를 안전하게 보관하기 위한 설계
//! 원칙은 다음과 같습니다.
//!   1. 슬롯은 정적 고정 풀 (`alloc` 금지).
//!   2. 모든 키 자료는 `Secret<[u8; MAX_PSK_LEN]>` 으로 래핑하여 슬롯 Drop
//!      시 volatile-write + 메모리 배리어로 자동 소거.
//!   3. 슬롯 lifecycle 은 `Empty` 에서 `Provisioned` 로, 다시 `Wiped` 로 진행하며 `Wiped` 는
//!      단방향(재사용 금지) 으로, 누설된 메타데이터 식별자 자체를 재공급에
//!      재사용할 수 없도록 차단.
//!   4. PSK 길이는 슬롯별 가변(16..=64) 으로 TLS 1.3 PSK 식별자/키 길이의
//!      다양성을 수용.
//!   5. 식별자 검색은 메타데이터 단계의 일반 비교(식별자는 공개정보) 이나,
//!      키 자료를 메모리에 복사해 처리할 때마다 즉시 소거 책임을 짐.
//!
//! 본 모듈은 [`crate::hsm::HsmDriver`] 를 구현하여 TLS 키 스케줄에 HSM 환경과
//! 동일한 인터페이스를 노출합니다.

use constant_time::Choice;
use constant_time::traits::CtEqOps;
use zeroize::Secret;
use zeroize::volatile::secure_zero;

use crate::crypto_service::{SHA256_OUTPUT_SIZE, hkdf_extract};
use crate::hsm::{HsmDriver, HsmError, PskId};

/// 단일 풀당 최대 PSK 슬롯 수.
pub const MAX_PSK_SLOTS: usize = 8;

/// PSK 키 자료의 슬롯 내 최대 길이 (bytes).
///
/// TLS 1.3 PSK 권장 강도(≥ 32B)와 광범위 호환성(≤ 64B) 을 모두 수용.
/// 더 긴 PSK 가 필요하면 본 풀과 분리된 별도 풀을 추가하여 대응.
pub const MAX_PSK_LEN: usize = 64;

// 신뢰 루트 PSK slot 네임스페이스 예약
// 아직 쓰이지 않으며 향후 keystore provisioning 을 위한 자리만 잡음
#[allow(dead_code)]
pub const TRUST_ROOT_PSK_SLOT: u8 = 0xFE;

// 신뢰 루트 ML-DSA-44 PK 의 raw 1312-옥텟 슬롯
//
// `k0_trust_root_keystore` cfg 활성 빌드에서만 부팅 시 채워질 수 있음
// closed 빌드는 본 정적 자료와 helper 가 cfg-out 되어 binary 심볼 0
//
// MAX_PSK_LEN = 64 와 별개의 raw 1312 옥텟 슬롯 책임 경계 분리
#[cfg(k0_trust_root_keystore)]
static mut TRUST_ROOT_PK_SLOT: Option<[u8; 1312]> = None;

// 빌드 타임 임베드 프로덕션 신뢰 루트 (K0_TRUST_ROOT_KEYSTORE 경로 지정 빌드 전용)
//
// build.rs 가 지정 파일을 검증(길이 1312, 비 all-zero, 비 dev 지문)한 뒤 OUT_DIR 로
// staging 하고 그 절대 경로를 K0_TRUST_ROOT_KEYSTORE_PATH 로 노출하고, 본 const 는
// 그 프로덕션 PK 만 바이너리에 임베드하므로 dev 상수는 keystore 빌드에서 완전히 부재
#[cfg(k0_trust_root_keystore)]
pub const KEYSTORE_TRUST_ROOT_PK: [u8; 1312] =
    *include_bytes!(env!("K0_TRUST_ROOT_KEYSTORE_PATH"));

/// trust root 1312-옥텟 PK 를 raw 복사로 반환
///
/// # Safety
/// BSP single-core 부팅 초기에만 호출 SMP 시 spinlock 필요
/// 본 helper 는 ACTIVE_TRUST_ROOT_PK 의 staging buffer 역할 단일 read
#[cfg(k0_trust_root_keystore)]
pub fn read_trust_root_pk() -> Option<[u8; 1312]> {
    // SAFETY BSP single-core 부팅 초기 + 단일 read
    unsafe { (*(&raw const TRUST_ROOT_PK_SLOT)).clone() }
}

/// trust root 1312-옥텟 PK 를 keystore 슬롯에 provision 한다 (production 진입점)
///
/// 공급 자료가 all-zero (미초기화, 무효 키 자료) 이면 거부한다. 길이는 타입으로 이미
/// 1312 옥텟이 강제된다. 유효하면 슬롯을 채우고 이후 `read_trust_root_pk` 가 반환한다.
///
/// # Safety
/// 호출자가 BSP single-core 부팅 초기 invariant 를 보장해야 한다 SMP 시 spinlock 필요
///
/// # Errors
/// `pk` 가 all-zero 이면 `KeystoreError::InvalidLength`
#[cfg(k0_trust_root_keystore)]
pub unsafe fn provision_trust_root_pk(pk: &[u8; 1312]) -> Result<(), KeystoreError> {
    // all-zero (미초기화, 무효) 공개키 자료 거부
    if pk.iter().all(|&b| b == 0) {
        return Err(KeystoreError::InvalidLength);
    }
    // SAFETY 호출자가 invariant 보장 본 함수는 BSP single-core 가정
    unsafe {
        let slot = &mut *(&raw mut TRUST_ROOT_PK_SLOT);
        *slot = Some(*pk);
    }
    Ok(())
}

/// 빌드 임베드 프로덕션 신뢰 루트로 keystore 슬롯을 채운다 (부팅 진입점)
///
/// `init_trust_root` 가 부팅 시 1 회 호출해 `KEYSTORE_TRUST_ROOT_PK` 를
/// `provision_trust_root_pk` 로 공급한다. 이로써 provision 경로가 실제 호출자를 갖고
/// dev 상수 폴백이 완전히 대체된다
///
/// # Safety
/// 호출자가 BSP single-core 부팅 초기 invariant 를 보장해야 한다
///
/// # Errors
/// 임베드 키가 all-zero 이면 `KeystoreError::InvalidLength`
#[cfg(k0_trust_root_keystore)]
pub unsafe fn provision_embedded_trust_root() -> Result<(), KeystoreError> {
    // SAFETY 호출자가 BSP single-core 부팅 초기 invariant 보장
    unsafe { provision_trust_root_pk(&KEYSTORE_TRUST_ROOT_PK) }
}

/// 슬롯 lifecycle.
///
/// `Wiped` 는 단방향 종착 상태로, 같은 슬롯에 새 키를 다시 공급할 수 없음.
/// 이는 식별자 재사용 공격 / 운영 실수 모두를 차단함.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum SlotState {
    Empty = 0,
    Provisioned = 1,
    Wiped = 2,
}

/// 키 저장소 운영 에러.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystoreError {
    /// 키 자료 길이가 0 또는 `MAX_PSK_LEN` 초과.
    InvalidLength,
    /// 풀에 빈 슬롯 없음.
    Full,
    /// 동일 식별자가 이미 등록되어 있음.
    Duplicate,
    /// 식별자에 해당하는 살아있는 슬롯 없음 (Empty 또는 Wiped).
    NotFound,
}

/// PSK 슬롯.
///
/// `Secret<[u8; MAX_PSK_LEN]>` 으로 키 자료를 보호하며, Drop 시 볼라타일 소거.
/// 길이는 슬롯이 `Provisioned` 상태일 때만 의미가 있음.
struct PskSlot {
    id: PskId,
    state: SlotState,
    material: Secret<[u8; MAX_PSK_LEN]>,
    material_len: usize,
}

impl PskSlot {
    fn empty() -> Self {
        Self {
            id: PskId::ZERO,
            state: SlotState::Empty,
            material: Secret::new([0u8; MAX_PSK_LEN]),
            material_len: 0,
        }
    }
}

/// 정적 고정 풀 PSK 키 저장소.
///
/// `static mut` 인스턴스로 선언하여 부팅 시점에 초기화하고 시스템 capability 를
/// 보유한 호출자만 PSK 를 공급/소거할 수 있도록 운영함.
pub struct SoftKeystore {
    slots: [PskSlot; MAX_PSK_SLOTS],
}

#[allow(clippy::new_without_default)]
impl SoftKeystore {
    pub fn new() -> Self {
        Self {
            slots: [
                PskSlot::empty(),
                PskSlot::empty(),
                PskSlot::empty(),
                PskSlot::empty(),
                PskSlot::empty(),
                PskSlot::empty(),
                PskSlot::empty(),
                PskSlot::empty(),
            ],
        }
    }

    //
    // PSK 라이프사이클 관리
    //

    /// 식별자에 해당하는 슬롯을 찾아 인덱스 반환 (Provisioned 상태에 한함).
    ///
    /// 식별자 자체는 비밀이 아니므로 일반 루프 사용. 키 자료 비교가 아니므로
    /// 시간 사이드채널 영향 없음.
    fn find_provisioned(&self, id: &PskId) -> Option<usize> {
        for (i, s) in self.slots.iter().enumerate() {
            if s.state == SlotState::Provisioned && s.id == *id {
                return Some(i);
            }
        }
        None
    }

    fn find_any_with_id(&self, id: &PskId) -> Option<usize> {
        for (i, s) in self.slots.iter().enumerate() {
            if s.state != SlotState::Empty && s.id == *id {
                return Some(i);
            }
        }
        None
    }

    /// 새 PSK 를 등록함.
    ///
    /// 같은 식별자가 이미 `Provisioned` 또는 `Wiped` 인 경우 식별자 재사용
    /// 공격을 차단하기 위해 거부함. 빈 슬롯이 없으면 `Full`.
    ///
    /// # Errors
    /// `InvalidLength` / `Duplicate` / `Full`.
    ///
    /// # Security Note
    /// 입력 `material` 슬라이스는 호출자가 보유한 임시 버퍼이며, 본 함수는
    /// 슬롯에 복사한 즉시 호출자 측 buffer 의 소거를 권고함 (호출 측 책임).
    pub fn provision(&mut self, id: PskId, material: &[u8]) -> Result<(), KeystoreError> {
        if material.is_empty() || material.len() > MAX_PSK_LEN {
            return Err(KeystoreError::InvalidLength);
        }
        if self.find_any_with_id(&id).is_some() {
            return Err(KeystoreError::Duplicate);
        }

        for slot in self.slots.iter_mut() {
            if slot.state == SlotState::Empty {
                let buf = slot.material.expose_mut();
                // 키 자료 복사 + 나머지 0 유지(정보 유출 방지)
                buf[..material.len()].copy_from_slice(material);
                // SAFETY: buf 는 MAX_PSK_LEN 바이트 유효 메모리
                unsafe {
                    secure_zero(
                        buf[material.len()..].as_mut_ptr(),
                        MAX_PSK_LEN - material.len(),
                    );
                }
                slot.id = id;
                slot.material_len = material.len();
                slot.state = SlotState::Provisioned;
                return Ok(());
            }
        }
        Err(KeystoreError::Full)
    }

    /// 모든 슬롯을 즉시 소거. 시스템 종료 / 위협 감지 시 호출.
    pub fn wipe_all(&mut self) {
        for slot in self.slots.iter_mut() {
            // SAFETY: material 은 Secret<[u8; MAX_PSK_LEN]> 의 내부 버퍼
            unsafe {
                secure_zero(slot.material.expose_mut().as_mut_ptr(), MAX_PSK_LEN);
            }
            slot.id = PskId::ZERO;
            slot.material_len = 0;
            slot.state = SlotState::Wiped;
        }
    }

    //
    // 내부 검증 / 디버그 (non-secret)
    //

    /// 현재 `Provisioned` 슬롯 개수.
    pub fn provisioned_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == SlotState::Provisioned)
            .count()
    }
}

//
// HsmDriver 구현
//

impl HsmDriver for SoftKeystore {
    fn psk_exists(&self, id: &PskId) -> Choice {
        // 풀의 모든 슬롯에 대해 constant-time 누산
        // 슬롯 상태 비교는 일반 분기지만, 식별자 비교는 ct
        let mut acc = Choice::from_u8(0);
        for slot in self.slots.iter() {
            if slot.state == SlotState::Provisioned {
                let mut eq = Choice::from_u8(1);
                for (a, b) in slot.id.0.iter().zip(id.0.iter()) {
                    eq &= CtEqOps::ct_eq(a, b);
                }
                acc |= eq;
            }
        }
        acc
    }

    fn psk_hkdf_extract(
        &self,
        id: &PskId,
        salt: &[u8],
        prk_out: &mut [u8; SHA256_OUTPUT_SIZE],
    ) -> Result<(), HsmError> {
        let idx = self.find_provisioned(id).ok_or(HsmError::PskNotFound)?;
        let slot = &self.slots[idx];
        if slot.material_len == 0 {
            return Err(HsmError::Internal);
        }
        let psk = &slot.material.expose()[..slot.material_len];
        // PRK = HMAC-SHA256(salt, PSK)
        hkdf_extract(salt, psk, prk_out);
        Ok(())
    }

    fn psk_destroy(&mut self, id: &PskId) -> Result<(), HsmError> {
        if let Some(idx) = self.find_any_with_id(id) {
            let slot = &mut self.slots[idx];
            // SAFETY: material 은 MAX_PSK_LEN 바이트 유효 메모리
            unsafe {
                secure_zero(slot.material.expose_mut().as_mut_ptr(), MAX_PSK_LEN);
            }
            slot.id = PskId::ZERO;
            slot.material_len = 0;
            slot.state = SlotState::Wiped;
        }
        // 미존재는 idempotent 이므로 Ok 반환
        Ok(())
    }
}

//
// 커널 전역 SoftKeystore (옵션)
//
// `Secret::new` 가 const fn 이 아니므로 `Option<SoftKeystore>` 로 시작하여
// 첫 접근 시 lazy init 하며 SMP 이전 단일 코어 환경 가정
static mut SOFT_KEYSTORE: Option<SoftKeystore> = None;

/// 전역 키 저장소에 대한 mut 참조. 첫 호출 시 lazy 초기화.
///
/// # Safety
/// 단일 코어 / 외부 동기화가 보장된 상태에서만 호출 가능.
pub unsafe fn global_mut() -> &'static mut SoftKeystore {
    // SAFETY: 호출자가 단일 코어 보장
    let slot = unsafe { &mut *(&raw mut SOFT_KEYSTORE) };
    if slot.is_none() {
        *slot = Some(SoftKeystore::new());
    }
    slot.as_mut()
        .expect("just-initialized SoftKeystore is Some")
}

/// 전역 키 저장소에 대한 immut 참조. 미초기화 상태에서는 새 빈 저장소 보임.
///
/// # Safety
/// 단일 코어 환경 가정. 동시 변경자가 없을 때만 호출. 일반적으로 본 함수
/// 호출 전에 `global_mut()` 한 번 호출되어 초기화되어 있어야 함.
pub unsafe fn global() -> &'static SoftKeystore {
    // SAFETY: 호출자가 단일 코어 + 변경자 부재 보장
    let slot = unsafe { &*(&raw const SOFT_KEYSTORE) };
    slot.as_ref().expect("SoftKeystore not initialized")
}
