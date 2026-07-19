//! arch-중립 모듈 re-export hub
//!
//! # Features
//! 아키텍처에 독립적인 커널 모듈을 모읍니다. 현재는 Phase 8 의 entropy 서브트리만
//! 존재하며 Phase 10 aarch64 합류 시에도 본 모듈은 변경 없이 재사용됩니다.

pub mod entropy;
