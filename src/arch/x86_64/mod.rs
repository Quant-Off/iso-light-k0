//! x86_64 arch-specific 모듈 re-export hub
//!
//! # Features
//! x86_64 전용 entropy 어댑터 (RDSEED/RDRAND + virtio PCI transport) 를 노출합니다.
//! Phase 10 의 aarch64 합류 시 본 모듈과 대칭인 aarch64 hub 가 신설됩니다.

pub mod entropy;
