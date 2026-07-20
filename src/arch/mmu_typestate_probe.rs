//! Phase 9 HAL-07 Mmu typestate 음성 컴파일 probe 모듈
//!
//! # Features
//! feature `mmu-typestate-probe` 활성 시에만 컴파일되며 `Mmu<Uninitialized>` 에서
//! `activate` 호출을 시도합니다. typestate 강제가 유효하면 E0599 로 컴파일이
//! 거부되는 것이 정상이며 Makefile check-mmu-typestate leg 가 이를 grep 검증합니다.
//! production 빌드 (기본 feature) 에는 포함되지 않습니다. 경로는 `crate::mmu` 를
//! 사용하여 9-B 이동 후에도 re-export 로 동일 해석되어 probe 가 전 구간 유효합니다.

/// Mmu<Uninitialized> 에서 activate 를 오호출하는 음성 probe 함수
///
/// # Safety
/// 본 함수는 E0599 로 컴파일 자체가 거부되어야 하며 실행 경로에 존재하지 않음
pub unsafe fn probe_activate_before_initialize(
    mmu: &crate::mmu::Mmu<crate::mmu::Uninitialized>,
    space: &crate::mmu::AddressSpace,
) {
    // E0599 예상 지점 activate 는 Mmu<Initialized> 에서만 호출 가능
    unsafe { mmu.activate(space) };
}
