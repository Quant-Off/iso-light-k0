//! 본 모듈은 timer frequency 탐지와 cycle counter HAL hook 표면을 정의합니다
//!
//! # Features
//! CPUID 0x15 우선 + 0x16 fallback + CMOS RTC calibration 3 단 chain 으로 TSC
//! 주파수를 Hz 단위로 노출합니다. zero frequency 는 None 으로 올려
//! divide-by-zero panic 을 차단합니다. cycle_counter 는 jitter noise source 의
//! timestamp hook 입니다 (rdtsc on x86)

// 두 timer source 구분
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerKind {
    InvariantTsc,
    JitterCalibration,
}

/// CPU cycle counter 를 읽는 HAL hook 함수
///
/// x86_64 는 RDTSC 직접 호출이며 aarch64 분기는 cntvct_el0 으로 채움
pub fn cycle_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: RDTSC 는 Ring 0 에서 임의 시점 안전 실행 가능한 읽기 전용 명령어
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0u64
    }
}

// boot serial 출력 합류 전까지 호출자 부재 한시 허용
//
// timer frequency 는 boot 세션 동안 불변이라 1 회만 계산 후 캐시
// CMOS RTC calibration fallback 은 최대 16M port I/O (wait_uip_falling_edge x2) 로 TCG
// 에서 수십 초가 걸린다. entropy 재시드 폴링(quorum collect_with_retry)이
// elapsed_since_boot_ms -> timer_frequency 를 매 iteration 호출하므로 캐시가 없으면 매
// spin 마다 재calibration 하여 fail-closed 가 사실상 hang 한다 (실기 KVM 은 invariant
// TSC 로 fast path 라 미노출, qemu64 TCG 런타임 검증에서만 표면화)
#[allow(dead_code)]
pub fn timer_frequency() -> Option<(u64, TimerKind)> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
        // STATE 0=uncomputed 1=computing 2=ready. FREQ=0 은 None hz. KIND 0=None 1=Invariant 2=Jitter
        static STATE: AtomicU8 = AtomicU8::new(0);
        static FREQ: AtomicU64 = AtomicU64::new(0);
        static KIND: AtomicU8 = AtomicU8::new(0);

        if STATE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // 최초 진입자만 1 회 계산 (CMOS calibration 은 여기서만 수행)
            let (hz, kind_code) = match timer_frequency_x86_uncached() {
                Some((hz, TimerKind::InvariantTsc)) => (hz, 1u8),
                Some((hz, TimerKind::JitterCalibration)) => (hz, 2u8),
                None => (0u64, 0u8),
            };
            FREQ.store(hz, Ordering::Relaxed);
            KIND.store(kind_code, Ordering::Relaxed);
            STATE.store(2, Ordering::Release);
        } else {
            // 계산 진행 중이면 완료 대기 (단일 코어 부팅에선 미도달)
            while STATE.load(Ordering::Acquire) != 2 {
                core::hint::spin_loop();
            }
        }

        let hz = FREQ.load(Ordering::Relaxed);
        match KIND.load(Ordering::Relaxed) {
            1 => Some((hz, TimerKind::InvariantTsc)),
            2 => Some((hz, TimerKind::JitterCalibration)),
            _ => None,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    None
}

/// timer frequency 실측 (캐시 미적용 내부 구현)
///
/// CPUID 0x15 우선 0x16 fallback CMOS RTC calibration 3 단 chain 으로 TSC 주파수를
/// 산출한다. `timer_frequency` 가 결과를 1 회 캐시하므로 본 함수는 boot 당 1 회만 호출됨
#[cfg(target_arch = "x86_64")]
fn timer_frequency_x86_uncached() -> Option<(u64, TimerKind)> {
    let (eax, ebx, ecx, _edx) = crate::arch::x86_64::cpu::cpuid(0x15, 0);
    if eax != 0 && ebx != 0 && ecx != 0 {
        return Some(((ecx as u64) * (ebx as u64) / (eax as u64), TimerKind::InvariantTsc));
    }
    let (eax16, _ebx16, _ecx16, _edx16) = crate::arch::x86_64::cpu::cpuid(0x16, 0);
    if (eax16 & 0xFFFF) != 0 {
        return Some((((eax16 & 0xFFFF) as u64) * 1_000_000, TimerKind::InvariantTsc));
    }
    // calibration fallback, CPUID 양 leaf fail 시 CMOS RTC polling
    crate::arch::common::entropy::jitter::calibrate_tsc_via_rtc()
        .ok()
        .map(|hz| (hz, TimerKind::JitterCalibration))
}
