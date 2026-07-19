//! Phase 8 ENTR-02 QuorumEntropy 정책 + 3 source 결합 mixing 통합점
//!
//! # Features
//! hw / virtio / jitter 3 source 를 per-source NIST SP 800-90B StreamHealth 로 평가한
//! 뒤 production strict 2-of-3 (degraded 빌드 1-of-3) quorum 을 강제합니다. boot path
//! `collect` 은 quorum_min 미달 시 즉시 `Err(QuorumFailed)` 로 fail-close 하며 runtime path
//! `collect_with_retry` 는 D-05 재시드 window 안 복구를 폴링하고 초과 시 직접 panic 합니다.
//! 3 source 결합은 `blake::Blake3` XOF 로만 수행되어 신규 암호 알고리즘이 없습니다 (D-22)

// D-05 정합 Timeout variant 부재 collect_with_retry 가 window 초과 시 내부에서 직접 panic
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum EntropyError {
    QuorumFailed,
    SourceUnavailable,
    HealthTestFailed,
}

/// 3 source quorum 정책의 zero-sized 진입점 구조체
///
/// per-source StreamHealth BSS singleton 을 통해 재시드 사이 health 상태를 유지하며
/// collect 과 collect_with_retry 두 표면만 노출합니다
#[allow(dead_code)]
pub struct QuorumEntropy;

// AUDIT_RING entropy lifecycle result 코드 D-05 잠금 4 events Pitfall 6 12 옥텟 ABI 보존
// result 9..=12 신규 할당 Phase 5/5.1/6 의 0..=8 영역과 충돌 0 32-entry AUDIT_RING
// oldest-overwrite tolerance 정합 (boot enroll ~4 + entropy boot 1 + reseed 4 = peak 9)
#[allow(dead_code)]
const RESULT_ENTROPY_RESEED_ATTEMPT: u8 = 9;
#[allow(dead_code)]
const RESULT_ENTROPY_RESEED_POLLING: u8 = 10;
#[allow(dead_code)]
const RESULT_ENTROPY_RESEED_RECOVERED: u8 = 11;
#[allow(dead_code)]
const RESULT_ENTROPY_RESEED_FAILED_PANIC: u8 = 12;

// FAILED_PANIC 의 bus_kind verdict sub-code slot_idx 0xFE 는 quorum-wide
// slot_idx 0xF0 | source_idx 는 source-specific 실패로 D-05 4 events scope 안 통합
#[allow(dead_code)]
const SUB_QUORUM_MIN: u8 = 0;
#[allow(dead_code)]
const SUB_RCT_FAIL: u8 = 1;
#[allow(dead_code)]
const SUB_APT_FAIL: u8 = 2;
#[allow(dead_code)]
const SUB_SOURCE_MISSING: u8 = 3;

// production strict 2-of-3 degraded 빌드 1-of-3 Open Question 3 RESEARCH 권고
#[cfg(not(feature = "entropy-degraded-ok"))]
#[allow(dead_code)]
const QUORUM_MIN: usize = 2;
#[cfg(feature = "entropy-degraded-ok")]
#[allow(dead_code)]
const QUORUM_MIN: usize = 1;

// capability.rs ENTROPY_LEN + virtio_rng VIRTIO_SCRATCH_LEN 정합
#[allow(dead_code)]
const SAMPLE_BYTES: usize = 32;
#[allow(dead_code)]
const SOURCE_COUNT: usize = 3;
// D-05 재시드 window 상한 ms
#[allow(dead_code)]
const RETRY_BUDGET_MS: u64 = 60_000;
// timer 부재 fail-open-to-hang 차단 spin 상한 (fail-closed 보증)
#[allow(dead_code)]
const RETRY_SPIN_CEILING: u64 = 10_000_000;

#[cfg(target_os = "none")]
use super::health::{HealthVerdict, StreamHealth};
#[cfg(target_os = "none")]
use super::{jitter, virtio_rng};
#[cfg(target_os = "none")]
use crate::hsm_attest::audit_enqueue;
#[cfg(target_os = "none")]
use zeroize::Zeroize;

// per-source health BSS singleton 3 KiB apt_window 포함
#[cfg(target_os = "none")]
static mut HW_HEALTH: StreamHealth = StreamHealth::new();
#[cfg(target_os = "none")]
static mut VIRTIO_HEALTH: StreamHealth = StreamHealth::new();
#[cfg(target_os = "none")]
static mut JITTER_HEALTH: StreamHealth = StreamHealth::new();
// Pitfall 5 visibility main.rs 의 ENTROPY_SOURCES_AVAILABLE marker 가 읽음
#[cfg(target_os = "none")]
static mut SOURCES_AVAILABLE_AT_BOOT: u8 = 0;
#[cfg(target_os = "none")]
static mut SOURCES_LATCHED: bool = false;

#[cfg(target_os = "none")]
impl QuorumEntropy {
    /// 단일 source 를 수집해 per-source StreamHealth 로 평가하는 함수
    ///
    /// # Arguments
    /// `source_idx` - 0 은 hw 1 은 virtio 2 는 jitter
    /// `buf` - source 결과를 담는 SAMPLE_BYTES staging buffer
    ///
    /// # Errors
    /// `EntropyError::SourceUnavailable` - 수집 실패 또는 0 buffer silent-pass 차단
    /// `EntropyError::HealthTestFailed` - RCT 또는 APT cutoff 초과
    ///
    /// # Safety
    /// BSP single-core 부팅 시퀀스 + 각 source BSS singleton 의 단일 진입 가정
    /// audit_enqueue 는 AUDIT_RING oldest-overwrite 정책으로 재진입 없이 호출됨
    unsafe fn collect_from_source(
        source_idx: u8,
        buf: &mut [u8; SAMPLE_BYTES],
    ) -> Result<u8, EntropyError> {
        let fill: Result<(), EntropyError> = match source_idx {
            0 => {
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY cpu::features() 완료 후 단일 코어 hw RDSEED/RDRAND 수집
                    unsafe { crate::arch::x86_64::entropy::hw::collect_hw_into(&mut buf[..]) }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    Err(EntropyError::SourceUnavailable)
                }
            }
            1 => {
                // SAFETY BSP single-core VIRTIO_SCRATCH + VIRTIO_RNG_INSTANCE 단일 진입
                match unsafe { virtio_rng::virtio_collect(&mut buf[..]) } {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            }
            _ => {
                let mut ok = true;
                for slot in buf.iter_mut() {
                    // SAFETY BSP single-core JITTER_POOL 단일 진입
                    match unsafe { jitter::jitter_collect_byte() } {
                        Some(b) => *slot = b,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    Ok(())
                } else {
                    Err(EntropyError::SourceUnavailable)
                }
            }
        };

        if let Err(e) = fill {
            audit_enqueue(
                0xF0 | source_idx,
                RESULT_ENTROPY_RESEED_FAILED_PANIC,
                SUB_SOURCE_MISSING,
                [0u8; 4],
            );
            return Err(e);
        }

        // Pitfall 2 0-buffer silent-pass 차단 constant-time 비교
        let zero = [0u8; SAMPLE_BYTES];
        if blake::ct_eq_slice(&buf[..], &zero[..]).unwrap_u8() == 1 {
            audit_enqueue(
                0xF0 | source_idx,
                RESULT_ENTROPY_RESEED_FAILED_PANIC,
                SUB_SOURCE_MISSING,
                [0u8; 4],
            );
            return Err(EntropyError::SourceUnavailable);
        }

        // per-source StreamHealth sample 단위 평가
        // SAFETY 각 source BSS singleton 의 단일 진입 갱신
        let health: &mut StreamHealth = unsafe {
            match source_idx {
                0 => &mut *(&raw mut HW_HEALTH),
                1 => &mut *(&raw mut VIRTIO_HEALTH),
                _ => &mut *(&raw mut JITTER_HEALTH),
            }
        };
        for &sample in buf.iter() {
            if let HealthVerdict::Fail = health.check(sample) {
                // check() 가 RCT 와 APT 를 HealthVerdict Fail 로 병합하므로 sub-code 1 로 통합
                // SUB_APT_FAIL 은 health.rs verdict 세분화 시점까지 예약
                audit_enqueue(
                    0xF0 | source_idx,
                    RESULT_ENTROPY_RESEED_FAILED_PANIC,
                    SUB_RCT_FAIL,
                    [0u8; 4],
                );
                return Err(EntropyError::HealthTestFailed);
            }
        }

        // min-entropy 추정치 coarse jitter 는 raw delta 로 보수적
        let bits = if source_idx == 2 { 16u8 } else { 32u8 };
        Ok(bits)
    }

    /// boot path 3 source 수집 후 strict quorum 을 강제하는 함수
    ///
    /// # Arguments
    /// `buf` - 수집 결과 출력 buffer 길이만큼 BLAKE3 XOF 출력
    ///
    /// # Errors
    /// `EntropyError::QuorumFailed` - live source 가 QUORUM_MIN 미달 boot 는 polling 없이 즉시 반환
    /// `EntropyError::SourceUnavailable` - BLAKE3 XOF 출력 실패
    ///
    /// # Safety
    /// BSP single-core 부팅 시퀀스 + 3 source BSS singleton 단일 진입 가정
    pub unsafe fn collect(buf: &mut [u8]) -> Result<(), EntropyError> {
        let mut scratches: [[u8; SAMPLE_BYTES]; SOURCE_COUNT] =
            [[0u8; SAMPLE_BYTES]; SOURCE_COUNT];
        let mut live_sources: u8 = 0;
        for idx in 0..SOURCE_COUNT {
            // SAFETY 각 source 어댑터 단일 진입
            match unsafe { Self::collect_from_source(idx as u8, &mut scratches[idx]) } {
                Ok(_) => live_sources += 1,
                Err(_) => {}
            }
        }

        // Pitfall 5 boot source count latch 최초 1 회
        // SAFETY BSP single-core SOURCES_* singleton 단일 진입
        unsafe {
            if !(&raw const SOURCES_LATCHED).read() {
                *(&raw mut SOURCES_AVAILABLE_AT_BOOT) = live_sources;
                *(&raw mut SOURCES_LATCHED) = true;
            }
        }

        if (live_sources as usize) < QUORUM_MIN {
            audit_enqueue(
                0xFE,
                RESULT_ENTROPY_RESEED_FAILED_PANIC,
                SUB_QUORUM_MIN,
                [0u8; 4],
            );
            for s in scratches.iter_mut() {
                s.zeroize();
            }
            return Err(EntropyError::QuorumFailed);
        }

        // BLAKE3 XOF mixing 모든 source 항상 결합 unavailable 은 0 buffer 기여 (RESEARCH L177)
        let mut hasher = blake::Blake3::new();
        for s in scratches.iter() {
            hasher.update(&s[..]);
        }
        let mix = match hasher.finalize_xof(buf.len()) {
            Ok(m) => m,
            Err(_) => {
                for s in scratches.iter_mut() {
                    s.zeroize();
                }
                return Err(EntropyError::SourceUnavailable);
            }
        };
        buf.copy_from_slice(mix.as_slice());
        // mix SecureBuffer 는 Drop 으로 zeroize scratches 는 명시 zeroize
        for s in scratches.iter_mut() {
            s.zeroize();
        }
        Ok(())
    }

    /// runtime reseed path quorum 복구를 재시드 window 안 폴링하는 함수
    ///
    /// # Arguments
    /// `buf` - 수집 결과 출력 buffer
    /// `max_wait_ms` - D-05 재시드 window 상한 ms
    ///
    /// # Errors
    /// `EntropyError::SourceUnavailable` - BLAKE3 XOF 출력 실패
    ///
    /// # Safety
    /// BSP single-core + 3 source BSS singleton 단일 진입 가정 window 초과 시 직접 panic
    pub unsafe fn collect_with_retry(
        buf: &mut [u8],
        max_wait_ms: u64,
    ) -> Result<(), EntropyError> {
        audit_enqueue(0xFE, RESULT_ENTROPY_RESEED_ATTEMPT, 0u8, [0u8; 4]);
        let start = elapsed_since_boot_ms();
        let mut spins: u64 = 0;
        loop {
            // SAFETY 3 source 어댑터 단일 진입
            match unsafe { Self::collect(buf) } {
                Ok(()) => {
                    audit_enqueue(0xFE, RESULT_ENTROPY_RESEED_RECOVERED, 0u8, [0u8; 4]);
                    return Ok(());
                }
                Err(EntropyError::QuorumFailed) => {
                    audit_enqueue(0xFE, RESULT_ENTROPY_RESEED_POLLING, 0u8, [0u8; 4]);
                    let elapsed = elapsed_since_boot_ms().wrapping_sub(start);
                    spins = spins.saturating_add(1);
                    if elapsed > max_wait_ms || spins > RETRY_SPIN_CEILING {
                        audit_enqueue(
                            0xFE,
                            RESULT_ENTROPY_RESEED_FAILED_PANIC,
                            SUB_QUORUM_MIN,
                            [0u8; 4],
                        );
                        panic!("entropy quorum cannot be restored within retry window");
                    }
                    core::hint::spin_loop();
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// boot 시점 latch 된 live source 수를 반환하는 함수
    ///
    /// main.rs 의 ENTROPY_SOURCES_AVAILABLE marker 가 호출함
    pub fn sources_available_at_boot() -> u8 {
        // SAFETY BSP single-core SOURCES_AVAILABLE_AT_BOOT 읽기 전용 접근
        unsafe { (&raw const SOURCES_AVAILABLE_AT_BOOT).read() }
    }
}

/// boot 이후 경과 시간을 ms 로 환산하는 helper 함수
///
/// timer_frequency 가 None 이거나 1 kHz 미만이면 0 을 반환해 collect_with_retry 의
/// spin ceiling 에 종료를 위임함 (Pitfall 12 divide-by-zero 차단)
#[cfg(target_os = "none")]
fn elapsed_since_boot_ms() -> u64 {
    let ticks = crate::arch::cpu::cycle_counter();
    match crate::arch::cpu::timer_frequency() {
        Some((hz, _)) if hz >= 1000 => ticks / (hz / 1000),
        _ => 0,
    }
}
