//! aarch64 arch-specific 모듈 re-export hub (Phase 10 진입 anchor stub)
//!
//! # Features
//! x86_64 hub (`crate::arch::x86_64`) 와 대칭인 aarch64 골격입니다. 6 HAL trait
//! (Cpu Mmu Idt Console BootEntry Entropy) 의 두 번째 구현체가 채워질 자리를
//! 표면으로만 잠급니다 (9-D 표면 잠금). 본 모듈은 `#[cfg(target_arch = "aarch64")]`
//! 로만 컴파일 대상에 진입하므로 현재 활성 타깃 x86_64-unknown-none 산출물에는
//! 유입되지 않습니다.
//!
//! 모든 구현체는 크기 0 의 ZST 이며 본문은 `unimplemented!` 골격입니다. 실제
//! DAIF/CPACR_EL1/TTBR0_EL1/PL011/eret asm 배선과 첫 컴파일
//! (`cargo check --target aarch64-unknown-none-softfloat`) 은 Phase 10 ARM-01 로
//! 이월됩니다 (OQ4 텍스트 표면 잠금, aarch64-unknown-none-softfloat 타깃 미설치).

use crate::arch::common::entropy::EntropyError;

// Phase 10 10-B ISA 의존 서브모듈 (x86_64 hub 대칭 위임 전환)
// cpu 는 DAIF/WFI/CNTVCT_EL0/CPACR_EL1/PAN 시스템 레지스터 배선을 담당함
pub mod cpu;
// boot_stub 는 _start EL2->EL1 eret 강하 + el1_entry 특권 정규화 global_asm
pub mod boot_stub;
// vectors 는 16-entry .vector_table + VBAR_EL1 로드 + SPSel #1 panic 스택 (Pitfall 14)
pub mod vectors;
// console 은 PL011 UART MMIO 직렬 콘솔 (arm-pl011-uart 위임 + MMU 전/후 base 갱신)
pub mod console;
// mmu 는 stage1 4KiB/48-bit VA/TTBR split 페이지 테이블 + 12-step activate + self_test
pub mod mmu;

//
// 6 HAL trait aarch64 두 번째 구현체 골격 (HAL-03 ZST 대칭)
//
// x86_64 hub 와 동일하게 dyn/Box 미사용 ZST 이며 Phase 10 이 본문만 채우면 되는
// 상태로 표면을 고정함. 본문 unimplemented! 은 aarch64 타깃 컴파일 (Phase 10) 전까지
// 실행 경로에 진입할 수 없음 (cfg 게이트로 x86_64 빌드에서 완전 배제).
//

/// Cpu trait aarch64 구현체 골격 (Phase 10 이 DAIF/WFI/CNTVCT_EL0 배선).
#[allow(dead_code)]
pub struct Aarch64Cpu;

impl crate::arch::Cpu for Aarch64Cpu {
    #[inline(always)]
    unsafe fn user_access_begin() {
        // SAFETY 호출자가 user_access_end 와 쌍 호출 계약을 그대로 승계
        unsafe { cpu::user_access_begin() }
    }
    #[inline(always)]
    unsafe fn user_access_end() {
        // SAFETY user_access_begin 직후 user 메모리 작업 종료 시점에 호출
        unsafe { cpu::user_access_end() }
    }
    #[inline(always)]
    unsafe fn interrupts_disable() {
        // SAFETY EL1 에서만 호출하며 임계 구역 종료 시 interrupts_enable 로 복구
        unsafe { cpu::interrupts_disable() }
    }
    #[inline(always)]
    unsafe fn interrupts_enable() {
        // SAFETY VBAR_EL1 벡터 테이블 초기화 완료 이후에만 호출
        unsafe { cpu::interrupts_enable() }
    }
    #[inline(always)]
    fn wait_for_interrupt() {
        cpu::wait_for_interrupt()
    }
    #[inline(always)]
    fn halt_loop() -> ! {
        cpu::halt_loop()
    }
    #[inline(always)]
    unsafe fn enable_simd_fpu() {
        // SAFETY 부팅 초기 단일 코어 시퀀스에서 1 회 호출 계약 승계
        unsafe { cpu::enable_simd_fpu() }
    }
    #[inline(always)]
    unsafe fn enable_security_bits() {
        // SAFETY 부팅 초기 단일 코어 시퀀스에서 1 회 호출 계약 승계
        unsafe { cpu::enable_security_bits() }
    }
    #[inline(always)]
    unsafe fn finalize_simd_fpu() {
        // SAFETY enable_simd_fpu 호출 이후에만 호출
        unsafe { cpu::finalize_simd_fpu() }
    }
    #[inline(always)]
    fn cycle_counter() -> u64 {
        cpu::cycle_counter()
    }
    #[inline(always)]
    fn timer_frequency() -> Option<(u64, crate::arch::cpu::TimerKind)> {
        cpu::timer_frequency()
    }
}

/// Mmu trait aarch64 구현체. typestate 강제는 `mmu::Mmu<State>` 가 담당하며 본
/// 구현체는 3 단계 전이 표면을 위임 매핑함 (x86 X86Mmu 대칭 HAL-07).
#[allow(dead_code)]
pub struct Aarch64Mmu;

impl crate::arch::Mmu for Aarch64Mmu {
    type Uninit = mmu::Mmu<mmu::Uninitialized>;
    type Init = mmu::Mmu<mmu::Initialized>;
    type AddrSpace = mmu::AddressSpace;

    #[inline(always)]
    fn pre_mmu_enable(m: Self::Uninit, kaslr_offset: u64) -> Self::Init {
        m.initialize(Some(kaslr_offset))
    }
    #[inline(always)]
    unsafe fn mmu_enable(m: &Self::Init, space: &Self::AddrSpace) {
        // SAFETY 호출자가 space TTBR0/TTBR1 루트 유효성 + 커널 매핑 포함을 보장
        //        12-step barrier activate 로 승계 (Pitfall 10 순서 강제)
        unsafe { m.activate(space) }
    }
    #[inline(always)]
    unsafe fn post_mmu_enable() {
        // SAFETY mmu_enable 완료 후 self_test + console 선형 재배치 + MMU=ON 마커
        unsafe { mmu::post_mmu_enable() }
    }
    #[inline(always)]
    fn phys_to_virt(pa: u64) -> u64 {
        // 커널 선형 매핑 VMA = phys + KERNEL_VMA_BASE (TTBR1 상위 절반 기저)
        pa + mmu::KERNEL_VMA_BASE
    }
}

/// Idt trait aarch64 구현체 골격 (Phase 10 이 GIC 벡터 테이블/VBAR_EL1 배선).
#[allow(dead_code)]
pub struct Aarch64Idt;

impl crate::arch::Idt for Aarch64Idt {
    #[inline(always)]
    unsafe fn init() {
        // SAFETY 부팅 초기 단일 코어 시퀀스에서 1 회 호출 계약 승계
        //        VBAR_EL1 벡터 로드 + 초기 IRQ mask (GIC enable_irq/eoi 는 10-D)
        unsafe { vectors::init() }
    }
    #[inline(always)]
    unsafe fn enable_irq(_irq: u8) {
        // Phase 10 GICD_ISENABLER 세트로 채움
        unimplemented!("ARM-01 aarch64 enable_irq")
    }
    #[inline(always)]
    unsafe fn eoi(_irq: u8) {
        // Phase 10 GICC_EOIR 통지로 채움
        unimplemented!("ARM-01 aarch64 eoi")
    }
}

/// Console trait aarch64 구현체 골격 (Phase 10 이 PL011 UART MMIO 배선).
#[allow(dead_code)]
pub struct Aarch64Console;

impl crate::arch::Console for Aarch64Console {
    #[inline(always)]
    unsafe fn write_str(s: &str) {
        // SAFETY 호출자가 PL011_BASE 유효 초기화 계약을 승계
        //        (release 빌드에서 write_str 는 no-op 로 축약 boot proof 마커는
        //         console::write_bytes 로 별도 무조건 emit)
        unsafe { console::write_str(s) }
    }
    #[inline(always)]
    unsafe fn clear() {
        // SAFETY PL011 직렬은 프레임버퍼 부재로 no-op (trait 계약 정합)
        unsafe { console::clear() }
    }
}

/// BootEntry trait aarch64 구현체 골격 (Phase 10 이 ttbr0 + eret 강하 asm 배선).
#[allow(dead_code)]
pub struct Aarch64BootEntry;

impl crate::arch::BootEntry for Aarch64BootEntry {
    #[inline(always)]
    unsafe fn enter_user(_addr_space_root: u64, _entry: u64, _stack: u64) -> ! {
        // Phase 10 msr ttbr0_el1 + msr elr_el1 + msr sp_el0 + eret 로 채움
        unimplemented!("ARM-01 aarch64 enter_user (eret 강하)")
    }
}

/// Entropy trait aarch64 구현체 골격 (Phase 10 이 RNDR/RNDRRS + jitter quorum 배선).
#[allow(dead_code)]
pub struct Aarch64Entropy;

impl crate::arch::Entropy for Aarch64Entropy {
    #[inline(always)]
    unsafe fn collect(_buf: &mut [u8]) -> Result<(), EntropyError> {
        // Phase 10 FEAT_RNG (mrs rndr/rndrrs) + jitter quorum 배선으로 채움
        unimplemented!("ARM-01 aarch64 entropy collect")
    }
}
