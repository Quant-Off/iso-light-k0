//! Phase 8 ENTR-05 entropy-degraded-ok + tls-external compile-fail 1차 안전망
//!
//! cargo build --features tls-external,entropy-degraded-ok 시도 시
//! src/arch/common/entropy/mod.rs 의 compile_error! 트리거를 검증한다 (Wave 1 신설)
//!
//! 실제 cargo test harness 미통합 Makefile 의 check-entropy-mutex leg 가
//! 직접 cargo build 호출 후 stderr 의 compile_error 토큰을 grep 으로 검증

#[cfg(all(feature = "entropy-degraded-ok", feature = "tls-external"))]
const _: () = panic!("entropy-degraded-ok with tls-external must compile-fail");
