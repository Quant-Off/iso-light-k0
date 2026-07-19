//! arch 디렉토리 루트 cfg-conditional re-export hub
//!
//! # Features
//! Phase 8 D-01 Forward 정합의 디렉토리 골격 루트입니다. arch-중립 모듈은 `common` 아래에,
//! x86_64 전용 어댑터는 `x86_64` 아래에 배치되며 활성 아키텍처는 `active` 별칭으로
//! 노출됩니다. Phase 9 의 HAL trait 추출은 본 골격 위에 trait 정의만 추가하면 됩니다.

pub mod common;
pub mod cpu;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as active;
