//! arch-중립 entropy quorum + health test + JitterRng + virtio-rng 어댑터의 progressive entry
//!
//! # Features
//! `entropy-degraded-ok` 활성 시 quorum_min = 1 이며 production 빌드 (`tls-external`) 와는
//! compile-time mutex 로 동시 활성이 차단됩니다 (ENTR-05). 모든 진입은
//! `QuorumEntropy::collect` 또는 `collect_with_retry` 단일점만 허용됩니다.

#[cfg(all(feature = "entropy-degraded-ok", feature = "tls-external"))]
compile_error!(
    "entropy-degraded-ok cannot coexist with tls-external 이는 production builds 가 strict 2-of-3 quorum 을 요구하기 때문"
);

pub mod health;
pub mod jitter;
pub mod quorum;
pub mod virtio_rng;

pub use quorum::EntropyError;
