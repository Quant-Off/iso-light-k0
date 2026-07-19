//! 본 모듈은 timer frequency 탐지 표면을 정의합니다
//!
//! # Features
//! CPUID 0x15 우선 + 0x16 fallback chain 으로 TSC 주파수를 Hz 단위로 노출합니다.
//! zero frequency 는 None semantic 으로 lifting 하여 divide-by-zero panic 을
//! 차단합니다 (PITFALLS Pitfall 12). calibration fallback 은 Wave 2 의 jitter
//! calibrate 합류 anchor 로 현재 None 을 반환합니다.

// W7 ROADMAP SC 7 정합 2-source 구분 Wave 2 부터 JitterCalibration 활성
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerKind {
    InvariantTsc,
    JitterCalibration,
}

// Wave 2 의 boot serial 출력 합류 전까지 호출자 부재 한시 허용
#[allow(dead_code)]
pub fn timer_frequency() -> Option<(u64, TimerKind)> {
    #[cfg(target_arch = "x86_64")]
    {
        let (eax, ebx, ecx, _edx) = crate::cpu::cpuid(0x15, 0);
        if eax != 0 && ebx != 0 && ecx != 0 {
            return Some(((ecx as u64) * (ebx as u64) / (eax as u64), TimerKind::InvariantTsc));
        }
        let (eax16, _ebx16, _ecx16, _edx16) = crate::cpu::cpuid(0x16, 0);
        if (eax16 & 0xFFFF) != 0 {
            return Some((((eax16 & 0xFFFF) as u64) * 1_000_000, TimerKind::InvariantTsc));
        }
        // Wave 2 의 jitter calibrate 합류 시 활성 TimerKind::JitterCalibration emit
        None
    }
    #[cfg(not(target_arch = "x86_64"))]
    None
}
