//! 본 모듈은 timer frequency 탐지와 cycle counter HAL hook 표면을 정의합니다
//!
//! # Features
//! CPUID 0x15 우선 + 0x16 fallback + CMOS RTC calibration 3 단 chain 으로 TSC
//! 주파수를 Hz 단위로 노출합니다. zero frequency 는 None semantic 으로 lifting
//! 하여 divide-by-zero panic 을 차단합니다 (PITFALLS Pitfall 12). cycle_counter
//! 는 jitter noise source 의 timestamp HAL hook 입니다 (rdtsc on x86)

// W7 ROADMAP SC 7 정합 2-source 구분
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerKind {
    InvariantTsc,
    JitterCalibration,
}

/// CPU cycle counter 를 읽는 HAL hook 함수
///
/// x86_64 는 RDTSC 직접 호출이며 aarch64 분기는 Phase 10 이 cntvct_el0 으로 채움
pub fn cycle_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY RDTSC 는 Ring 0 에서 임의 시점 안전 실행 가능한 읽기 전용 명령어
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0u64
    }
}

// Wave 4 의 boot serial 출력 합류 전까지 호출자 부재 한시 허용
#[allow(dead_code)]
pub fn timer_frequency() -> Option<(u64, TimerKind)> {
    #[cfg(target_arch = "x86_64")]
    {
        let (eax, ebx, ecx, _edx) = crate::arch::x86_64::cpu::cpuid(0x15, 0);
        if eax != 0 && ebx != 0 && ecx != 0 {
            return Some(((ecx as u64) * (ebx as u64) / (eax as u64), TimerKind::InvariantTsc));
        }
        let (eax16, _ebx16, _ecx16, _edx16) = crate::arch::x86_64::cpu::cpuid(0x16, 0);
        if (eax16 & 0xFFFF) != 0 {
            return Some((((eax16 & 0xFFFF) as u64) * 1_000_000, TimerKind::InvariantTsc));
        }
        // calibration fallback (Pitfall 12) CPUID 양 leaf fail 시 CMOS RTC polling
        crate::arch::common::entropy::jitter::calibrate_tsc_via_rtc()
            .ok()
            .map(|hz| (hz, TimerKind::JitterCalibration))
    }
    #[cfg(not(target_arch = "x86_64"))]
    None
}
