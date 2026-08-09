//! aarch64 arch-specific 모듈 re-export hub
//!
//! # Features
//! x86_64 hub (`crate::arch::x86_64`) 와 대칭인 aarch64 골격입니다. 6 HAL trait
//! (Cpu Mmu Idt Console BootEntry Entropy) 의 두 번째 구현체를 표면으로 노출합니다.
//! 본 모듈은 `#[cfg(target_arch = "aarch64")]` 로만 컴파일 대상에 진입하므로 현재
//! 활성 타깃 x86_64-unknown-none 산출물에는 유입되지 않습니다.

use crate::arch::common::entropy::EntropyError;

// ISA 의존 서브모듈 (x86_64 hub 대칭 위임 전환)
// cpu 는 DAIF/WFI/CNTVCT_EL0/CPACR_EL1/PAN 시스템 레지스터 배선 담당
pub mod cpu;
// boot_stub 는 _start EL2 에서 EL1 로 eret 강하 + el1_entry 특권 정규화 global_asm
pub mod boot_stub;
// boot 는 el1_entry 가 bl 로 진입하는 커널 부팅 합류점(aarch64_kernel_entry) 배선
pub mod boot;
// vectors 는 16-entry .vector_table + VBAR_EL1 로드 + SPSel #1 panic 스택
pub mod vectors;
// console 은 PL011 UART MMIO 직렬 콘솔 (arm-pl011-uart 위임 + MMU 전/후 base 갱신)
pub mod console;
// mmu 는 stage1 4KiB/48-bit VA/TTBR split 페이지 테이블 + 12-step activate + self_test
pub mod mmu;
// gic 는 GICv3 redistributor wake + GRP1 + enable_irq/eoi (arm-gic 0.8.1 위임)
pub mod gic;
// psci 는 PSCI PSCI_VERSION/CPU_ON 을 HVC conduit 으로 호출하는 전원 표면 (smccc 0.2.3 위임)
pub mod psci;
// syscall 은 SVC #0 벡터 진입(ESR_EL1.EC==0b010101) + arch/common dispatch
pub mod syscall;
// process_entry 는 EL0 최초 진입 eret 시퀀스(ttbr0/tlbi/elr_el1/sp_el0/spsr_el1)
pub mod process_entry;
// entropy 는 FEAT_RNG RNDR/RNDRRS + CNTVCT jitter + virtio-rng 2-of-3 quorum 위임
pub mod entropy;

// smccc 0.2.3 HVC conduit 표면을 psci 서브모듈에 재노출
// psci.rs 는 Secure Monitor Call conduit 미사용 하드 게이트(문자열 원천 부재)를 위해
// 크레이트를 직접 import 하지 않고 아래 재노출 별칭(Hvc / psci_version_call / psci_cpu_on_call)만 경유
pub(crate) use smccc::Hvc;
pub(crate) use smccc::psci::{cpu_on as psci_cpu_on_call, version as psci_version_call};

/// 스택 캐너리 순회용 IST 가드 범위 HAL 표면 (aarch64 는 IST 부재로 빈 슬라이스).
///
/// aarch64 는 x86 TSS/IST 대신 SP_EL1 dedicated panic 스택을 사용하므로 순회할
/// IST 가드가 없다. `stack` 본체가 arch 분기 없이 0 회 순회하도록 빈 슬라이스를
/// 반환함 (x86 `ist_guard_ranges` 대칭 HAL 표면)
pub fn ist_guard_ranges() -> &'static [(u64, u64)] {
    &[]
}

//
// 6 HAL trait aarch64 두 번째 구현체
//
// x86_64 hub 와 동일하게 dyn/Box 미사용 ZST 이며 각 메서드는 대응 ISA 서브모듈로 위임
// cfg 게이트로 x86_64 빌드에서는 완전 배제
//

/// Cpu trait aarch64 구현체 (DAIF/WFI/CNTVCT_EL0 배선).
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
/// 구현체는 3 단계 전이 표면을 위임 매핑함 (x86 X86Mmu 대칭).
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
        //        12-step barrier activate 로 승계 (barrier 순서 강제)
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

/// Idt trait aarch64 구현체 (GIC 벡터 테이블/VBAR_EL1 배선).
#[allow(dead_code)]
pub struct Aarch64Idt;

impl crate::arch::Idt for Aarch64Idt {
    #[inline(always)]
    unsafe fn init() {
        // SAFETY 부팅 초기 단일 코어 시퀀스에서 1 회 호출 계약 승계
        //        VBAR_EL1 벡터 로드 후 GICv3 redistributor wake FIRST + GRP1 활성
        //        후 부팅 proof SGI 를 1 회 delivery 하여 IRQ N delivered 마커 emit
        unsafe {
            vectors::init();
            gic::setup();
            gic::deliver_boot_proof_irq();
        }
    }
    #[inline(always)]
    unsafe fn enable_irq(irq: u8) {
        // SAFETY setup() 완료 및 해당 IRQ 벡터 경로 준비 후 호출 GICD/GICR ISENABLER 세트 위임
        unsafe { gic::enable_irq(irq) }
    }
    #[inline(always)]
    unsafe fn eoi(irq: u8) {
        // SAFETY IRQ 핸들러 컨텍스트에서만 호출 ICC_EOIR1_EL1 통지 위임
        unsafe { gic::eoi(irq) }
    }
}

/// Console trait aarch64 구현체 (PL011 UART MMIO 배선).
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

/// BootEntry trait aarch64 구현체 (ttbr0 + eret 강하 asm 배선).
#[allow(dead_code)]
pub struct Aarch64BootEntry;

impl crate::arch::BootEntry for Aarch64BootEntry {
    #[inline(always)]
    unsafe fn enter_user(addr_space_root: u64, entry: u64, stack: u64) -> ! {
        // SAFETY 호출자가 BootEntry::enter_user 계약(유효 TTBR0 루트 + 커널 매핑 계승 +
        //        EL0 엔트리/스택)을 승계함. process_entry 가 ttbr0/tlbi/eret 시퀀스로 강하
        unsafe { process_entry::enter_user(addr_space_root, entry, stack) }
    }
}

/// Entropy trait aarch64 구현체 (RNDR/RNDRRS + jitter quorum 배선).
#[allow(dead_code)]
pub struct Aarch64Entropy;

impl crate::arch::Entropy for Aarch64Entropy {
    #[inline(always)]
    unsafe fn collect(buf: &mut [u8]) -> Result<(), EntropyError> {
        // SAFETY 호출자가 Entropy::collect 계약(단일 진입 + 출력 버퍼 유효)을 승계
        //        entropy::collect 가 arch-중립 QuorumEntropy 2-of-3 quorum 으로 위임
        unsafe { entropy::collect(buf) }
    }
}
