//! Phase 8 ENTR-02 placeholder Wave 3 본문 채움 anchor

// D-05 정합 Timeout variant 부재 collect_with_retry 가 60sec 초과 시 내부에서 직접 panic
// QuorumFailed 와 HealthTestFailed 는 Wave 2~3 본문이 구성 한시 허용
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum EntropyError {
    QuorumFailed,
    SourceUnavailable,
    HealthTestFailed,
}

// TODO Wave 3 QuorumEntropy 본문 합류
