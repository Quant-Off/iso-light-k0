//! NIST SP 800-90B §4.4.1 RCT + §4.4.2 APT stream evaluator
//!
//! # Features
//! sample 단위 verdict 평가 + 재허용 메커니즘 (연속 N=16 sample PASS 시 quorum 재진입)
//! NIST 권장 α=2⁻²⁰ W=1024 H=0.5 의 3 source 공통 baseline

#[allow(dead_code)]
pub const ALPHA_EXP: u32 = 20;
#[allow(dead_code)]
pub const APT_WINDOW: usize = 1024;
// NIST SP 800-90B §4.4.1 정본 공식 1 + ceil(20 / 0.5) = 41
#[allow(dead_code)]
pub const RCT_CUTOFF: u32 = 41;
// W=1024 H=0.5 binomial CDF precomputed 1 + CRITBINOM(1024, 2^-0.5, 1-2^-20) = 793
// `tests/entropy_health_rct_apt.rs` 의 binomial reference 가 본 값을 잠금
#[allow(dead_code)]
pub const APT_CUTOFF: u32 = 793;
#[allow(dead_code)]
pub const REENTRY_THRESHOLD: u32 = 16;

/// sample 단위 health 판정 결과를 담는 열거형
///
/// Pass 는 RCT 와 APT 모두 통과 Fail 은 cutoff 초과 NeedMoreData 는
/// APT window 충전 중을 뜻함
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthVerdict {
    Pass,
    Fail,
    NeedMoreData,
}

/// 단일 entropy source 의 RCT + APT 상태를 보유하는 구조체
///
/// source 당 1 개 BSS singleton 으로 배치되며 apt_window 1 KiB 를 포함해
/// 3 source 합계 3 KiB 를 점유함
#[allow(dead_code)]
pub struct StreamHealth {
    rct_last: u8,
    rct_count: u32,
    apt_window: [u8; APT_WINDOW],
    apt_idx: usize,
    apt_observed_count: u32,
    apt_initial: u8,
    apt_filled: usize,
    consecutive_pass: u32,
    disabled: bool,
}

impl Default for StreamHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl StreamHealth {
    /// zero-init 상태의 evaluator 를 생성하는 const 함수
    pub const fn new() -> Self {
        Self {
            rct_last: 0,
            rct_count: 0,
            apt_window: [0u8; APT_WINDOW],
            apt_idx: 0,
            apt_observed_count: 0,
            apt_initial: 0,
            apt_filled: 0,
            consecutive_pass: 0,
            disabled: false,
        }
    }

    /// disabled BSS state 를 조회하는 함수
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// 매 sample 마다 RCT 와 APT 를 평가해 verdict 를 반환하는 함수
    ///
    /// # Arguments
    /// `sample` - source 가 산출한 1 옥텟 sample
    pub fn check(&mut self, sample: u8) -> HealthVerdict {
        if sample == self.rct_last {
            self.rct_count = self.rct_count.saturating_add(1);
            if self.rct_count >= RCT_CUTOFF {
                self.disabled = true;
                self.consecutive_pass = 0;
                return HealthVerdict::Fail;
            }
        } else {
            self.rct_count = 1;
            self.rct_last = sample;
        }

        // sample 단위 재허용 RCT 비실패 sample 마다 증가
        self.consecutive_pass = self.consecutive_pass.saturating_add(1);
        if self.disabled && self.consecutive_pass >= REENTRY_THRESHOLD {
            self.disabled = false;
        }

        if self.apt_filled < APT_WINDOW {
            if self.apt_filled == 0 {
                self.apt_initial = sample;
                self.apt_observed_count = 1;
            } else if sample == self.apt_initial {
                self.apt_observed_count = self.apt_observed_count.saturating_add(1);
            }
            self.apt_filled += 1;
            if self.apt_filled < APT_WINDOW {
                return HealthVerdict::NeedMoreData;
            }
            let observed = self.apt_observed_count;
            self.apt_filled = 0;
            self.apt_observed_count = 0;
            if observed >= APT_CUTOFF {
                self.disabled = true;
                self.consecutive_pass = 0;
                return HealthVerdict::Fail;
            }
        }

        HealthVerdict::Pass
    }
}
