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
        // Phase 10 PAN 해제 (msr pan, #0) 로 채움
        unimplemented!("ARM-01 aarch64 user_access_begin")
    }
    #[inline(always)]
    unsafe fn user_access_end() {
        // Phase 10 PAN 설정 (msr pan, #1) 로 채움
        unimplemented!("ARM-01 aarch64 user_access_end")
    }
    #[inline(always)]
    unsafe fn interrupts_disable() {
        // Phase 10 daifset (msr daifset, #0b0010) 로 채움
        unimplemented!("ARM-01 aarch64 interrupts_disable")
    }
    #[inline(always)]
    unsafe fn interrupts_enable() {
        // Phase 10 daifclr (msr daifclr, #0b0010) 로 채움
        unimplemented!("ARM-01 aarch64 interrupts_enable")
    }
    #[inline(always)]
    fn wait_for_interrupt() {
        // Phase 10 wfi 로 채움
        unimplemented!("ARM-01 aarch64 wait_for_interrupt")
    }
    #[inline(always)]
    fn halt_loop() -> ! {
        // Phase 10 wfi 무한 루프로 채움
        unimplemented!("ARM-01 aarch64 halt_loop")
    }
    #[inline(always)]
    unsafe fn enable_simd_fpu() {
        // Phase 10 CPACR_EL1.FPEN = 0b11 로 채움 (cpu.rs 기존 aarch64 스텁 승계)
        unimplemented!("ARM-01 aarch64 enable_simd_fpu")
    }
    #[inline(always)]
    unsafe fn enable_security_bits() {
        // Phase 10 PAN/UAO/SCTLR_EL1 보안 비트 설정으로 채움
        unimplemented!("ARM-01 aarch64 enable_security_bits")
    }
    #[inline(always)]
    unsafe fn finalize_simd_fpu() {
        // Phase 10 지연 초기화 마무리로 채움
        unimplemented!("ARM-01 aarch64 finalize_simd_fpu")
    }
    #[inline(always)]
    fn cycle_counter() -> u64 {
        // Phase 10 mrs cntvct_el0 로 채움
        unimplemented!("ARM-01 aarch64 cycle_counter")
    }
    #[inline(always)]
    fn timer_frequency() -> Option<(u64, crate::arch::cpu::TimerKind)> {
        // Phase 10 mrs cntfrq_el0 탐지로 채움
        unimplemented!("ARM-01 aarch64 timer_frequency")
    }
}

/// aarch64 MMU 미초기화 상태 골격 (Phase 10 이 페이지 테이블 빌더로 채움).
#[allow(dead_code)]
pub struct Aarch64MmuUninit;

/// aarch64 MMU 활성화 가능 상태 골격.
#[allow(dead_code)]
pub struct Aarch64MmuInit;

/// aarch64 주소 공간 루트 골격 (TTBR0_EL1/TTBR1_EL1 후보).
#[allow(dead_code)]
pub struct Aarch64AddrSpace;

/// Mmu trait aarch64 구현체 골격. typestate 전이 표면만 잠그며 Phase 10 이
/// TTBR0_EL1/SMMU 배선으로 채움.
#[allow(dead_code)]
pub struct Aarch64Mmu;

impl crate::arch::Mmu for Aarch64Mmu {
    type Uninit = Aarch64MmuUninit;
    type Init = Aarch64MmuInit;
    type AddrSpace = Aarch64AddrSpace;

    #[inline(always)]
    fn pre_mmu_enable(_m: Self::Uninit, _kaslr_offset: u64) -> Self::Init {
        // Phase 10 페이지 테이블 구축 + KASLR 반영으로 채움
        unimplemented!("ARM-01 aarch64 pre_mmu_enable")
    }
    #[inline(always)]
    unsafe fn mmu_enable(_m: &Self::Init, _space: &Self::AddrSpace) {
        // Phase 10 msr ttbr0_el1 + tlbi + isb 로 채움
        unimplemented!("ARM-01 aarch64 mmu_enable")
    }
    #[inline(always)]
    unsafe fn post_mmu_enable() {
        // Phase 10 PL011 베이스 선형 매핑 갱신으로 채움
        unimplemented!("ARM-01 aarch64 post_mmu_enable")
    }
    #[inline(always)]
    fn phys_to_virt(_pa: u64) -> u64 {
        // Phase 10 커널 선형 매핑 오프셋 변환으로 채움
        unimplemented!("ARM-01 aarch64 phys_to_virt")
    }
}

/// Idt trait aarch64 구현체 골격 (Phase 10 이 GIC 벡터 테이블/VBAR_EL1 배선).
#[allow(dead_code)]
pub struct Aarch64Idt;

impl crate::arch::Idt for Aarch64Idt {
    #[inline(always)]
    unsafe fn init() {
        // Phase 10 msr vbar_el1 + GIC 배포기 초기화로 채움
        unimplemented!("ARM-01 aarch64 idt init")
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
    fn write_str(_s: &str) {
        // Phase 10 PL011 UARTDR MMIO 기록으로 채움
        unimplemented!("ARM-01 aarch64 console write_str")
    }
    #[inline(always)]
    fn clear() {
        // Phase 10 프레임버퍼/스크롤 소거로 채움
        unimplemented!("ARM-01 aarch64 console clear")
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
