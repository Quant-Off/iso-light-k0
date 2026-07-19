//! host 전용 테스트 표면 lib crate (BLOCKER-5 정합 cross-repo 의존 0)
//!
//! # Features
//! kernel target (`target_os = "none"`) 빌드에서는 빈 crate 로 축소되어 커널
//! 산출물과 boot path 에 영향이 없습니다. host triple 의 `cargo test` 만 본
//! 표면을 사용하며 노출 모듈은 host 에서 컴파일 가능한 안전 표면 한정입니다
#![no_std]
#![cfg(not(target_os = "none"))]

pub mod arch {
    pub mod common {
        pub mod entropy {
            pub mod health;
            pub mod quorum;
            pub mod virtio_rng;

            pub use quorum::EntropyError;
        }
    }
}

pub mod hsm_attest;
