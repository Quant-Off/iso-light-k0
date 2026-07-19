//! capability.rs 에서 lossless move 된 x86_64 HW RDSEED/RDRAND 엔트로피 어댑터
//!
//! # Features
//! RDSEED 우선 RDRAND 폴백의 하드웨어 엔트로피 수집을 제공합니다. 본문은
//! capability.rs 의 기존 구현을 의미 변경 0 으로 이동한 것이며 Wave 3 의
//! quorum 합류 시 QuorumEntropy 의 hw source 로 사용됩니다.

use crate::arch::common::entropy::EntropyError;
use zeroize::Zeroize;

/// 하드웨어 엔트로피 수집에 필요한 최대 재시도 횟수.
///
/// Intel SDM Vol. 1 §7.3.17.2: RDSEED는 DRBG 큐 소진 시 CF=0 을 반환하며,
/// 충분히 재시도해야 유효값을 얻을 수 있음. 과도한 경합 시에는 다음 폴백
/// 엔트로피 소스로 전환해야 함.
const HW_RNG_MAX_RETRIES: u32 = 1024;

/// RDSEED 명령으로 64비트 엔트로피를 시도함.
///
/// # Safety
/// `cpu::features().rdseed == true` 인 경우에만 호출 가능.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) unsafe fn rdseed64() -> Option<u64> {
    let value: u64;
    let cf: u8;
    // SAFETY: RDSEED는 Ring0에서 안전. CF를 `setc`로 즉시 읽어 성공 여부 확정
    unsafe {
        core::arch::asm!(
            "rdseed {v}",
            "setc {c}",
            v = out(reg) value,
            c = out(reg_byte) cf,
            options(nostack),
        );
    }
    if cf == 1 { Some(value) } else { None }
}

/// RDRAND 명령으로 64비트 의사난수를 시도함.
///
/// RDRAND는 CPU 내부 CSPRNG(CSRNG 재시드 대상)에서 출력되므로 DRBG 시드용도
/// 로는 RDSEED 보다 약간 약함. 그러나 NIST SP 800-90C 호환 시드 자료로는
/// 충분한 엔트로피 입력을 제공함.
///
/// # Safety
/// `cpu::features().rdrand == true` 인 경우에만 호출 가능.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) unsafe fn rdrand64() -> Option<u64> {
    let value: u64;
    let cf: u8;
    // SAFETY: RDRAND는 Ring0에서 안전. CF를 `setc`로 즉시 읽음
    unsafe {
        core::arch::asm!(
            "rdrand {v}",
            "setc {c}",
            v = out(reg) value,
            c = out(reg_byte) cf,
            options(nostack),
        );
    }
    if cf == 1 { Some(value) } else { None }
}

/// `buf` 를 하드웨어 엔트로피로 채움 (RDSEED 우선, RDRAND 폴백).
///
/// # Errors
/// `EntropyError::SourceUnavailable` — CPU에 RDSEED/RDRAND 가 없거나 재시도
/// 한도 내에 충분한 엔트로피를 수집하지 못한 경우.
///
/// # Safety
/// 단일 코어 부팅 초기 혹은 적절한 동기화 이후에 호출되어야 함.
/// CPU 기능 탐지(`cpu::enable_simd_fpu`)가 먼저 수행되어야 함.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn collect_hw_into(buf: &mut [u8]) -> Result<(), EntropyError> {
    let feats = crate::cpu::features();
    if !feats.rdseed && !feats.rdrand {
        return Err(EntropyError::SourceUnavailable);
    }

    let mut offset = 0usize;
    while offset < buf.len() {
        // RDSEED 우선 시도, 고갈 시 RDRAND 폴백
        let mut value: Option<u64> = None;
        if feats.rdseed {
            for _ in 0..HW_RNG_MAX_RETRIES {
                // SAFETY: rdseed 지원 확인 완료
                if let Some(v) = unsafe { rdseed64() } {
                    value = Some(v);
                    break;
                }
                core::hint::spin_loop();
            }
        }
        if value.is_none() && feats.rdrand {
            for _ in 0..HW_RNG_MAX_RETRIES {
                // SAFETY: rdrand 지원 확인 완료
                if let Some(v) = unsafe { rdrand64() } {
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
