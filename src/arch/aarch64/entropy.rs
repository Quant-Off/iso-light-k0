//! 본 모듈은 aarch64 하드웨어 엔트로피 소스(FEAT_RNG RNDR/RNDRRS)와 quorum 위임을 배선합니다
//!
//! # Features
//! x86_64 `entropy/hw.rs` 의 RDSEED/RDRAND 어댑터에 1:1 대응하는 aarch64 구현을
//! 제공합니다. hw 소스는 `mrs rndr`(고갈 시 `mrs rndrrs` 폴백) 실행 후 PSTATE.NZCV
//! 의 Z 비트로 성공을 판정하며(성공 시 NZCV=0b0000 실패 시 0b0100, x86 `setc` 대응)
//! FEAT_RNG 는 ID_AA64ISAR0_EL1.RNDR(bits[63:60]) 런타임 탐지로 게이트합니다.
//! cortex-a72(ARMv8.0-A)는 FEAT_RNG 부재라 RNDR 이 항상 SourceUnavailable 로
//! 강등되고, QEMU `-cpu max` cell 은 FEAT_RNG 를 TCG 에뮬레이션하여 hw 소스가
//! 살아납니다. arch-중립 `QuorumEntropy::collect` 는 hw(RNDR) + virtio-mmio +
//! jitter 3 소스 2-of-3 quorum 을 강제하며, source-0(hw)은 quorum.rs 가 본 모듈의
//! `collect_hw_into` 를 target_arch 분기로 호출하고, source-1(virtio)은 본 모듈의
//! `probe_virtio_rng`(virtio-mmio window scan)를 `init_virtio_rng_instance` 가 배선하며,
//! source-2(jitter)는 CNTVCT_EL0 기반 arch-중립 `jitter.rs` 를 재사용합니다.
//! QEMU virt `-cpu max` + `-device virtio-rng-device` 에서 ENTROPY_SOURCES_AVAILABLE=2
//! 로 2-of-3 quorum 이 성립함을 런타임 실증했습니다.

use crate::arch::common::entropy::EntropyError;
use zeroize::Zeroize;

/// 하드웨어 엔트로피 수집에 필요한 최대 재시도 횟수
///
/// RNDR 은 엔트로피 큐 소진 시 실패 플래그를 반환하므로 다음 폴백 소스로 전환하기
/// 전 충분히 재시도해야 유효값을 얻음
const HW_RNG_MAX_RETRIES: u32 = 1024;

/// FEAT_RNG(ARMv8.5 RNG extension) 구현 여부를 런타임 탐지함
///
/// `ID_AA64ISAR0_EL1.RNDR`(bits[63:60]) 이 0 이 아니면 구현으로 판정하며 x86
/// `features().rdseed/rdrand` 게이트에 대응함. cortex-a72 는 미구현이라 false 를
/// 반환하므로 RNDR/RNDRRS 를 실행하지 않음
#[allow(dead_code)]
fn feat_rng_supported() -> bool {
    let isar0: u64;
    // SAFETY ID_AA64ISAR0_EL1 은 EL1 읽기 전용 식별 레지스터로 부작용 없음
    unsafe {
        core::arch::asm!(
            "mrs {v}, id_aa64isar0_el1",
            v = out(reg) isar0,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((isar0 >> 60) & 0xF) != 0
}

/// RNDR 명령으로 64비트 엔트로피를 시도함
///
/// # Safety
/// `feat_rng_supported() == true` 인 경우에만 호출 가능
#[allow(dead_code)]
#[inline]
unsafe fn rndr64() -> Option<u64> {
    let value: u64;
    let ok: u64;
    // SAFETY RNDR 은 EL1 에서 안전하며 성공 시 NZCV=0b0000(Z clear) 실패 시 0b0100
    //        (Z set)을 세팅하므로 cset ne 로 성공(Z clear)을 즉시 판정함(x86 setc 대응)
    unsafe {
        core::arch::asm!(
            ".arch_extension rng",
            "mrs {v}, rndr",
            "cset {c}, ne",
            v = out(reg) value,
            c = out(reg) ok,
            options(nomem, nostack),
        );
    }
    if ok == 1 { Some(value) } else { None }
}

/// RNDRRS 명령으로 재시드된 64비트 엔트로피를 시도함(RNDR 고갈 시 폴백)
///
/// # Safety
/// `feat_rng_supported() == true` 인 경우에만 호출 가능
#[allow(dead_code)]
#[inline]
unsafe fn rndrrs64() -> Option<u64> {
    let value: u64;
    let ok: u64;
    // SAFETY RNDRRS 는 RNDR 과 동일 계약이며 재시드 보증만 강함 동일 NZCV.Z 판정
    unsafe {
        core::arch::asm!(
            ".arch_extension rng",
            "mrs {v}, rndrrs",
            "cset {c}, ne",
            v = out(reg) value,
            c = out(reg) ok,
            options(nomem, nostack),
        );
    }
    if ok == 1 { Some(value) } else { None }
}

/// `buf` 를 하드웨어 엔트로피로 채움(RNDR 우선 RNDRRS 폴백)
///
/// quorum source-0(hw) 어댑터로 arch-중립 quorum 이 소비하도록 배선될 표면이며
/// FEAT_RNG 부재 시 SourceUnavailable 을 반환하여 quorum 이 degrade 를 흡수함
///
/// # Errors
/// `EntropyError::SourceUnavailable` FEAT_RNG 부재이거나 재시도 한도 내에 충분한
/// 엔트로피를 수집하지 못한 경우
///
/// # Safety
/// 단일 코어 부팅 초기 혹은 적절한 동기화 이후에 호출되어야 함
pub unsafe fn collect_hw_into(buf: &mut [u8]) -> Result<(), EntropyError> {
    if !feat_rng_supported() {
        return Err(EntropyError::SourceUnavailable);
    }

    let mut offset = 0usize;
    while offset < buf.len() {
        // RNDR 우선 시도 고갈 시 RNDRRS 폴백
        let mut value: Option<u64> = None;
        for _ in 0..HW_RNG_MAX_RETRIES {
            // SAFETY feat_rng_supported 확인 완료
            if let Some(v) = unsafe { rndr64() } {
                value = Some(v);
                break;
            }
            core::hint::spin_loop();
        }
        if value.is_none() {
            for _ in 0..HW_RNG_MAX_RETRIES {
                // SAFETY RNDR 고갈 시 RNDRRS 폴백 feat 확인 완료
                if let Some(v) = unsafe { rndrrs64() } {
                    value = Some(v);
                    break;
                }
                core::hint::spin_loop();
            }
        }

        let v = value.ok_or(EntropyError::SourceUnavailable)?;
        let bytes = v.to_le_bytes();
        let chunk = core::cmp::min(8, buf.len() - offset);
        buf[offset..offset + chunk].copy_from_slice(&bytes[..chunk]);
        offset += chunk;

        // 임시 스택 변수 소거 (콜드부트 공격 대비)
        let mut tmp = bytes;
        tmp.zeroize();
    }
    Ok(())
}

/// aarch64 엔트로피를 arch-중립 `QuorumEntropy::collect` 로 수집함
///
/// hw(RNDR)/virtio-rng/jitter 3 소스 2-of-3 quorum 을 그대로 위임하며 FEAT_RNG
/// 부재 시 hw 소스가 SourceUnavailable 로 강등되어 virtio-rng + jitter 로 quorum
/// 이 성립함(정상 degrade). quorum.rs 본문은 무변경임(host 표면 보호)
///
/// # Errors
/// `EntropyError` quorum 미달 또는 health test 실패 시 fail-closed 로 전파됨
///
/// # Safety
/// BSP 단일 코어 부팅 시퀀스에서 각 소스 BSS singleton 단일 진입 가정
pub unsafe fn collect(buf: &mut [u8]) -> Result<(), EntropyError> {
    // SAFETY 호출자가 Entropy::collect 단일 진입 계약을 승계 quorum 위임
    unsafe { crate::arch::common::entropy::QuorumEntropy::collect(buf) }
}

/// QEMU virt virtio-mmio window 를 순차 probe 하여 virtio-rng(EntropySource) 디바이스를 탐지함
///
/// x86_64 `entropy::virtio_transport::probe_virtio_rng` 의 PCI ECAM scan 에 대응하는
/// aarch64 MMIO transport 판입니다. `VIRTIO_MMIO_COUNT` 슬롯을 순회해 device_type 이
/// EntropySource 인 슬롯의 `MmioTransport` 를 `VirtIORng` 로 감쌉니다. 디바이스 부재 시
/// None 을 반환해 arch-중립 quorum 이 virtio 소스를 SourceUnavailable 로 강등 흡수합니다
///
/// # Safety
/// BSP single-core 부팅 시점 + virtio-mmio window 가 stage1 Device 매핑(identity)에
/// 포함되어 있다고 가정합니다
#[cfg(target_os = "none")]
pub unsafe fn probe_virtio_rng() -> Option<
    virtio_drivers::device::rng::VirtIORng<
        crate::arch::common::entropy::virtio_rng::KernelHal,
        virtio_drivers::transport::mmio::MmioTransport<'static>,
    >,
> {
    use core::ptr::NonNull;
    use virtio_drivers::device::rng::VirtIORng;
    use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
    use virtio_drivers::transport::{DeviceType, Transport};

    use crate::arch::aarch64::mmu::{VIRTIO_MMIO_COUNT, VIRTIO_MMIO_PHYS, VIRTIO_MMIO_STRIDE};

    let mut slot = 0u64;
    while slot < VIRTIO_MMIO_COUNT {
        let base = VIRTIO_MMIO_PHYS + slot * VIRTIO_MMIO_STRIDE;
        slot += 1;
        let Some(header) = NonNull::new(base as *mut VirtIOHeader) else {
            continue;
        };
        // SAFETY base 는 stage1 이 Device 매핑한 유효 virtio-mmio 슬롯 (슬롯 window 0x200)
        let transport = match unsafe { MmioTransport::new(header, VIRTIO_MMIO_STRIDE as usize) } {
            Ok(t) => t,
            // 빈 슬롯(magic 불일치)이나 미지원 버전은 조용히 다음 슬롯으로 진행
            Err(_) => continue,
        };
        if transport.device_type() == DeviceType::EntropySource {
            return VirtIORng::new(transport).ok();
        }
    }
    None
}
