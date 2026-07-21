//! 본 모듈은 aarch64 el1_entry asm 스텁에서 bl 로 진입하는 커널 부팅 합류점을 제공합니다.
//!
//! # Features
//! `aarch64_kernel_entry(dtb)` 는 boot_stub `el1_entry` 가 EL=1 early print 직후 `bl`
//! 로 분기하는 Rust 진입 함수입니다. RESEARCH System Architecture Diagram 순서대로
//! 정적 페이지 테이블 구축(build_stage1_map + GICD/GICR Device 매핑) -> HAL Mmu 3 단계
//! (self_test + MMU=ON) -> GIC base 선형 VA 갱신 -> Idt::init(GICR wake + GRP1 + boot
//! proof IRQ) -> psci report_version 을 배선하여 7-line boot proof 를 런타임 emit 합니다.
//! 신규 로직은 이 진입 함수 하나이며 각 단계는 Phase 10 이 코딩한 파이프라인의 배선입니다.
//!
//! x86_64 `boot_stub` -> `_boot_adapter_mb2` -> `_kernel_start` 합류 계약을 mirror 하되
//! aarch64 는 EL1 MMU-off identity 실행 상태에서 진입하므로 진입 함수가 직접 stage1
//! MMU 를 켭니다. DTB 파싱과 arch-중립 `_kernel_start` 합류는 Phase 11 LIVE-01 로
//! 이연되며 본 진입점은 하드코딩 QEMU virt 상수로 7-line proof 후 wfi park 합니다.

use crate::arch::aarch64::{Aarch64Idt, Aarch64Mmu, cpu, gic, mmu, psci};
use crate::arch::{Idt, Mmu};

/// 커널 stage1 주소 공간을 정적 소유하는 arch 내부 전역 (동적 할당 0).
///
/// 본체(main.rs KERNEL_ADDR_SPACE) 결합을 피하기 위해 aarch64 내부 static 으로 두며
/// 부팅 초기 단일 코어가 배타 접근함
static mut AARCH64_KERNEL_SPACE: mmu::AddressSpace = mmu::AddressSpace::new();

/// boot_stub el1_entry 가 EL=1 early print 후 bl 로 진입하는 커널 부팅 합류점.
///
/// build_stage1_map -> HAL Mmu 3 단계 -> gic base 선형 VA 갱신 -> Idt::init ->
/// psci report_version 순서로 코딩된 부팅 파이프라인을 배선하여 QEMU virt TCG 부팅에서
/// 7-line boot proof 를 런타임 emit 함
///
/// # Arguments
/// `_dtb` - 진입 x0 DTB 물리 주소 (10.1 범위 미사용 Phase 11 LIVE-01 파싱 이연)
///
/// # Safety
/// boot_stub el1_entry 특권 정규화(SP_EL1 VBAR_EL1 CPACR_EL1) 완료 후 부팅 초기 단일
/// 코어에서 1 회만 진입해야 하며 반환 없는 -> ! 계약을 승계함
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_kernel_entry(_dtb: u64) -> ! {
    // KASLR stage-1 오프셋은 Phase 11 LIVE-01 이연 고정 기저 사용
    let kaslr = 0u64;

    // 1) stage1 페이지 테이블 구축 (커널 W^X + UART/GICD/GICR Device 매핑)
    // SAFETY MMU off identity 상태에서 1 회 호출 정적 AARCH64_KERNEL_SPACE 단독 접근
    let build = unsafe {
        (*(&raw mut AARCH64_KERNEL_SPACE)).build_stage1_map(kaslr, mmu::UART_PHYS)
    };
    if build.is_err() {
        // 정적 풀 소진/W^X 위반 등 매핑 실패는 fail-stop halt (오매핑 진행 차단)
        cpu::halt_loop();
    }

    // 2) HAL Mmu 3 단계 pre -> enable(12-step activate) -> post(self_test + MMU=ON emit)
    let init = <Aarch64Mmu as Mmu>::pre_mmu_enable(mmu::Mmu::new(), kaslr);
    // SAFETY build_stage1_map 완료 후 MMU off 상태 단일 코어에서 1 회 활성
    unsafe {
        <Aarch64Mmu as Mmu>::mmu_enable(&init, &*(&raw const AARCH64_KERNEL_SPACE));
        <Aarch64Mmu as Mmu>::post_mmu_enable();
    }

    // 3) MMU 후 GIC base 를 커널 선형 매핑 VA 로 갱신 (Task 1 이 GICD/GICR linear 매핑)
    // SAFETY mmu_enable 완료 후 선형 매핑이 GICD/GICR Device 페이지를 포함함
    unsafe {
        gic::update_base(
            (mmu::linear_base() + mmu::GICD_PHYS) as *mut u8,
            (mmu::linear_base() + mmu::GICR_PHYS) as *mut u8,
        );
    }

    // 4) GIC bring-up (GICR wake FIRST + GRP1) + boot proof IRQ delivery (vectors::init 선행)
    // SAFETY VBAR_EL1 로드 완료 후 부팅 초기 단일 코어에서 1 회 호출
    unsafe {
        <Aarch64Idt as Idt>::init();
    }

    // 5) PSCI 버전 조회 (HVC conduit) -> PSCI >= 0x10000 마커 emit
    // SAFETY GIC bring-up 직후 EL1 단일 코어 시퀀스에서 호출
    unsafe {
        psci::report_version();
    }

    // 6) park (Phase 11 이 EL0 enter_user 진입으로 승격)
    loop {
        cpu::wait_for_interrupt();
    }
}
