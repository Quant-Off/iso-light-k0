//! RCT cutoff 41 + APT cutoff host binomial reference 검증 (ENTR-03 / RESEARCH §A3)
//!
//! NIST SP 800-90B §4.4.1 RCT 공식과 §4.4.2 APT CRITBINOM 공식을 host 에서
//! 직접 재계산해 kernel const 와 일치를 잠금 (A3 fail-fast 정합)
#![cfg(not(target_os = "none"))]

use iso_light_k0::arch::common::entropy::health::{
    APT_CUTOFF, APT_WINDOW, HealthVerdict, RCT_CUTOFF, REENTRY_THRESHOLD, StreamHealth,
};

/// binomial 상위 tail 확률이 alpha 이하가 되는 최소 count 를 계산하는 함수
///
/// NIST SP 800-90B §4.4.2 의 `1 + CRITBINOM(W, 2^-H, 1-alpha)` 와 동치인
/// `min j (P(X >= j) <= alpha)` 형태로 log-space 누산 계산함
fn apt_cutoff_reference(w: usize, p: f64, alpha: f64) -> u32 {
    let n = w;
    let mut ln_fact = vec![0.0f64; n + 1];
    for k in 1..=n {
        ln_fact[k] = ln_fact[k - 1] + (k as f64).ln();
    }
    let ln_p = p.ln();
    let ln_q = (1.0 - p).ln();
    let mut tail = 0.0f64;
    let mut j = n;
    loop {
        let ln_pmf = ln_fact[n] - ln_fact[j] - ln_fact[n - j] + (j as f64) * ln_p
            + ((n - j) as f64) * ln_q;
        let pmf = ln_pmf.exp();
        if tail + pmf > alpha {
            return (j + 1) as u32;
        }
        tail += pmf;
        if j == 0 {
            return 0;
        }
        j -= 1;
    }
}

#[test]
fn rct_cutoff_matches_nist_formula() {
    // C = 1 + ceil(-log2(alpha) / H) = 1 + ceil(20 / 0.5) = 41
    let alpha_exp = 20.0f64;
    let h = 0.5f64;
    let expected = 1 + (alpha_exp / h).ceil() as u32;
    assert_eq!(RCT_CUTOFF, expected);
    assert_eq!(RCT_CUTOFF, 41);
}

#[test]
fn apt_cutoff_matches_binomial_reference() {
    // W=1024 H=0.5 alpha=2^-20 의 CRITBINOM host 재계산과 kernel const 일치 잠금
    let alpha = 2.0f64.powi(-20);
    let p = 2.0f64.powf(-0.5);
    let reference = apt_cutoff_reference(APT_WINDOW, p, alpha);
    assert_eq!(APT_CUTOFF, reference);
}

#[test]
fn rct_triggers_at_cutoff_41() {
    let mut h = StreamHealth::new();
    let mut verdict = HealthVerdict::Pass;
    for _ in 0..41 {
        verdict = h.check(0xAA);
    }
    assert_eq!(verdict, HealthVerdict::Fail);
    assert!(h.is_disabled());

    // 40 회까지는 Fail 미발생 경계 재검증
    let mut h2 = StreamHealth::new();
    for _ in 0..40 {
        assert_ne!(h2.check(0xAA), HealthVerdict::Fail);
    }
    assert!(!h2.is_disabled());
}

#[test]
fn apt_triggers_at_cutoff_in_window_1024() {
    // window 초두 sample 0xCC 를 40 run 상한 (RCT 회피) 으로 반복해 cutoff 초과 유도
    let mut h = StreamHealth::new();
    let mut samples: Vec<u8> = Vec::with_capacity(APT_WINDOW);
    while samples.len() + 41 <= APT_WINDOW {
        for _ in 0..40 {
            samples.push(0xCC);
        }
        samples.push(0xAA);
    }
    let mut toggle = false;
    while samples.len() < APT_WINDOW {
        samples.push(if toggle { 0xAA } else { 0xCC });
        toggle = !toggle;
    }
    let cc_count = samples.iter().filter(|&&b| b == 0xCC).count() as u32;
    assert!(cc_count >= APT_CUTOFF);

    let mut verdict = HealthVerdict::Pass;
    for &s in samples.iter() {
        verdict = h.check(s);
        assert!(!matches!(verdict, HealthVerdict::Fail) || h.is_disabled());
    }
    // window 종료 sample (1024 번째) 에서 APT Fail 판정
    assert_eq!(verdict, HealthVerdict::Fail);
    assert!(h.is_disabled());
}

#[test]
fn reentry_after_16_consecutive_pass() {
    let mut h = StreamHealth::new();
    for _ in 0..41 {
        h.check(0xAA);
    }
    assert!(h.is_disabled());

    // 연속 REENTRY_THRESHOLD 회 비실패 sample 로 재허용 (D-04 sample 단위)
    let mut sample = 0u8;
    for _ in 0..REENTRY_THRESHOLD {
        sample = sample.wrapping_add(1);
        h.check(sample);
    }
    assert!(!h.is_disabled());
}

#[test]
fn need_more_data_during_apt_window_fill() {
    let mut h = StreamHealth::new();
    let mut sample = 0u8;
    for _ in 0..(APT_WINDOW - 1) {
        sample = sample.wrapping_add(1);
        assert_eq!(h.check(sample), HealthVerdict::NeedMoreData);
    }
}
