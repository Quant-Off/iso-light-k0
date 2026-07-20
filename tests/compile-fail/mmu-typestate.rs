//! Phase 9 HAL-07 Mmu typestate 음성 컴파일 probe 1차 안전망
//!
//! cargo check --target x86_64-unknown-none --features mmu-typestate-probe 시도 시
//! src/arch/mmu_typestate_probe.rs 가 Mmu<Uninitialized> 에서 activate 호출을
//! 시도하여 E0599 컴파일 거부를 검증한다 (Wave 1 신설)
//!
//! 실제 cargo test harness 미통합 Makefile 의 check-mmu-typestate leg 가
//! 직접 cargo check 호출 후 출력의 E0599 토큰을 grep 으로 검증
