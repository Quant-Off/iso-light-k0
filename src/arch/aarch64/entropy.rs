//! 본 모듈은 aarch64 하드웨어 엔트로피 소스(FEAT_RNG RNDR/RNDRRS)와 quorum 위임을 배선합니다
//!
//! # Features
//! x86_64 `entropy/hw.rs` 의 RDSEED/RDRAND 어댑터에 1:1 대응하는 aarch64 구현을
//! 제공합니다. hw 소스는 `mrs rndr`(고갈 시 `mrs rndrrs` 폴백) 실행 후 PSTATE.NZCV
//! 의 Z 비트로 성공을 판정하며(성공 시 NZCV=0b0000 실패 시 0b0100, x86 `setc` 대응)
//! FEAT_RNG 는 ID_AA64ISAR0_EL1.RNDR(bits[63:60]) 런타임 탐지로 게이트합니다.
//! cortex-a72(ARMv8.0-A)는 FEAT_RNG 부재라 RNDR 이 항상 SourceUnavailable 로
//! 강등되고 arch-중립 `QuorumEntropy::collect` 가 virtio-rng + jitter 2-of-3
//! quorum 으로 degrade 를 정상 흡수합니다(Phase 8 정책 재사용). jitter 소스는
//! CNTVCT_EL0 기반 arch-중립 `jitter.rs` 를, virtio-rng 소스는 arch-중립
//! `virtio_rng.rs` 를 그대로 재사용하며 본 모듈은 quorum.rs 를 변경하지 않습니다
//! (host 표면 보호). RNDR min-entropy 실검증(-cpu max cell)은 Manual-Only 로 이연됩니다.

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
#[allow(dead_code)]
unsafe fn collect_hw_into(buf: &mut [u8]) -> Result<(), EntropyError> {
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
