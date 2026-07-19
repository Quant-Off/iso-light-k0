//! 1 source 가용 시 strict 2-of-3 fail-stop panic host 검증 (ENTR-02)
//!
//! quorum.rs 본문은 Wave 3 합류라 본 test 는 D-05 잠금 정책 (QUORUM_MIN=2 +
//! 60sec budget 초과 시 panic) 의 host 거울 harness 로 실 health evaluator
//! (`StreamHealth`) 를 통과시켜 fail-stop 경로를 검증함 Wave 3 이 kernel
//! `collect_with_retry` 합류 시 동일 panic message 계약을 상속함
#![cfg(not(target_os = "none"))]

use iso_light_k0::arch::common::entropy::health::{HealthVerdict, StreamHealth};

// D-05 잠금 production strict 2-of-3
const QUORUM_MIN: usize = 2;
const SAMPLE_BYTES: usize = 64;

enum MockSource {
    Unavailable,
    ZeroBuffer,
    Healthy(u64),
}

impl MockSource {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), ()> {
        match self {
            MockSource::Unavailable => Err(()),
            MockSource::ZeroBuffer => {
                for b in buf.iter_mut() {
                    *b = 0;
                }
                Ok(())
            }
            MockSource::Healthy(state) => {
                for b in buf.iter_mut() {
                    // xorshift64 결정적 PRNG test 재현성 확보
                    *state ^= *state << 13;
                    *state ^= *state >> 7;
                    *state ^= *state << 17;
                    *b = (*state & 0xFF) as u8;
                }
                Ok(())
            }
        }
    }
}

/// health verdict PASS 인 가용 source 개수를 세는 함수
///
/// # Arguments
/// `sources` - 3 mock source
/// `health` - source 별 stream evaluator
fn healthy_source_count(sources: &mut [MockSource; 3], health: &mut [StreamHealth; 3]) -> usize {
    let mut count = 0;
    for (src, h) in sources.iter_mut().zip(health.iter_mut()) {
        let mut buf = [0u8; SAMPLE_BYTES];
        if src.fill(&mut buf).is_err() {
            continue;
        }
        let mut failed = false;
        for &b in buf.iter() {
            if h.check(b) == HealthVerdict::Fail {
                failed = true;
            }
        }
        if !failed && !h.is_disabled() {
            count += 1;
        }
    }
    count
}

/// D-05 collect_with_retry 정책의 host 거울 함수
///
/// # Errors
/// budget (max_attempts) 소진까지 QUORUM_MIN 미달 시 panic (fail-stop)
fn collect_with_retry_mirror(sources: &mut [MockSource; 3], max_attempts: usize) {
    let mut health = [StreamHealth::new(), StreamHealth::new(), StreamHealth::new()];
    for _ in 0..max_attempts {
        if healthy_source_count(sources, &mut health) >= QUORUM_MIN {
            return;
        }
    }
    panic!("entropy quorum cannot be restored within 60sec window");
}

// fault-injection panic 경로 test VALIDATION 정합 --include-ignored 로 실행
#[test]
#[ignore]
#[should_panic(expected = "entropy quorum")]
fn one_source_only_panics_within_budget() {
    // 1 source 만 가용 (zero-buffer source 는 RCT 41 로 disabled) production panic
    let mut sources = [
        MockSource::Unavailable,
        MockSource::ZeroBuffer,
        MockSource::Healthy(0x9E37_79B9_7F4A_7C15),
    ];
    collect_with_retry_mirror(&mut sources, 3);
}

#[test]
fn two_of_three_passes_strict_quorum() {
    let mut sources = [
        MockSource::Unavailable,
        MockSource::Healthy(0x0123_4567_89AB_CDEF),
        MockSource::Healthy(0x9E37_79B9_7F4A_7C15),
    ];
    // panic 없이 반환하면 strict 2-of-3 충족
    collect_with_retry_mirror(&mut sources, 3);
}

#[test]
fn zero_buffer_source_disabled_by_rct() {
    // zero-buffer 강제 source 가 RCT cutoff 41 로 quorum 카운트에서 제외됨을 실측
    let mut sources = [
        MockSource::ZeroBuffer,
        MockSource::Healthy(0xDEAD_BEEF_CAFE_F00D),
        MockSource::Healthy(0x1357_9BDF_0246_8ACE),
    ];
    let mut health = [StreamHealth::new(), StreamHealth::new(), StreamHealth::new()];
    let count = healthy_source_count(&mut sources, &mut health);
    assert_eq!(count, 2);
    assert!(health[0].is_disabled());
}
