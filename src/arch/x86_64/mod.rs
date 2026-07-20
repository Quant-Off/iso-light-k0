//! x86_64 arch-specific 모듈 re-export hub
//!
//! # Features
//! x86_64 전용 entropy 어댑터 (RDSEED/RDRAND + virtio PCI transport) 를 노출합니다.
//! Phase 10 의 aarch64 합류 시 본 모듈과 대칭인 aarch64 hub 가 신설됩니다.

pub mod entropy;

// Phase 9 9-A HAL-04 ISA 의존 모듈 (구 src/{cpu,boot->gdt,tss,vga,boot_stub}.rs lossless 이동본)
pub mod boot_stub;
pub mod cpu;
pub mod gdt;
pub mod tss;
pub mod vga;

// Phase 9 9-B HAL-04 잔여 ISA 의존 모듈 (구 src/{mmu,idt,syscall}.rs lossless 이동본)
// memory_map 은 9-C 에서 src/boot/{memory_map,multiboot2}.rs 로 2차 분할 이동됨 (OQ3)
pub mod idt;
pub mod mmu;
pub mod syscall;

// Phase 9 9-C BootEntry 표면 (구 process.rs enter_ring3 asm lossless 추출본)
pub mod process_entry;

//
// 6 HAL trait x86_64 첫 구현체 (HAL-03 ZST + inline(always) 전수)
//
// 모든 구현체는 크기 0 의 ZST 이며 기존 free fn / typestate 메서드로의 thin
// 위임임. dyn/Box 미사용으로 vtable 미생성 (HAL-02) 이며 Phase 10 aarch64 가
// 동일 표면을 구현하도록 강제하는 컴파일 타임 계약의 첫 실증체임.
//

/// Cpu trait x86_64 구현체.
#[allow(dead_code)]
pub struct X86Cpu;

impl crate::arch::Cpu for X86Cpu {
    #[inline(always)]
    unsafe fn user_access_begin() {
        // SAFETY: 호출자가 user_access_end 와 쌍 호출 계약을 그대로 승계
        unsafe { cpu::stac() }
    }
    #[inline(always)]
    unsafe fn user_access_end() {
        // SAFETY: user_access_begin 직후 user 메모리 작업 종료 시점에 호출
        unsafe { cpu::clac() }
    }
    #[inline(always)]
    unsafe fn interrupts_disable() {
        // SAFETY: Ring 0 에서만 호출하며 임계 구역 종료 시 interrupts_enable 로 복구
        unsafe { core::arch::asm!("cli", options(nomem, nostack, preserves_flags)) }
    }
    #[inline(always)]
    unsafe fn interrupts_enable() {
        // SAFETY: IDT/PIC 초기화 완료 이후에만 호출
        unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) }
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
        // SAFETY: 부팅 초기 단일 코어 시퀀스에서 1 회 호출 계약 승계
        unsafe { cpu::enable_simd_fpu() }
    }
    #[inline(always)]
    unsafe fn enable_security_bits() {
        // SAFETY: 부팅 초기 단일 코어 시퀀스에서 1 회 호출 계약 승계
        unsafe { cpu::enable_security_bits() }
    }
    #[inline(always)]
    unsafe fn finalize_simd_fpu() {
        // SAFETY: enable_simd_fpu 호출 이후에만 호출
        unsafe { cpu::finalize_simd_fpu() }
    }
    #[inline(always)]
    fn cycle_counter() -> u64 {
        crate::arch::cpu::cycle_counter()
    }
    #[inline(always)]
    fn timer_frequency() -> Option<(u64, crate::arch::cpu::TimerKind)> {
        crate::arch::cpu::timer_frequency()
    }
}

/// Mmu trait x86_64 구현체. typestate 강제는 기존 `mmu::Mmu<State>` 가 담당하며
/// 본 구현체는 3 단계 전이 표면을 위임 매핑만 함 (HAL-07).
#[allow(dead_code)]
pub struct X86Mmu;

impl crate::arch::Mmu for X86Mmu {
    type Uninit = mmu::Mmu<mmu::Uninitialized>;
    type Init = mmu::Mmu<mmu::Initialized>;
    type AddrSpace = mmu::AddressSpace;

    #[inline(always)]
    fn pre_mmu_enable(m: Self::Uninit, kaslr_offset: u64) -> Self::Init {
        m.initialize(Some(kaslr_offset))
    }
    #[inline(always)]
    unsafe fn mmu_enable(m: &Self::Init, space: &Self::AddrSpace) {
        // SAFETY: 호출자가 space PML4 유효성 + 커널 매핑 포함을 보장
        unsafe { m.activate(space) }
    }
    #[inline(always)]
    unsafe fn post_mmu_enable() {
        // SAFETY: mmu_enable 완료 후 VGA 버퍼(phys 0xB8000) 를 커널 선형 매핑
        //         가상 주소로 재배치 (선형 매핑 활성 이후에만 유효)
        unsafe { vga::update_base((mmu::KERNEL_VMA_BASE + 0xB8000) as *mut u16) }
    }
    #[inline(always)]
    fn phys_to_virt(pa: u64) -> u64 {
        // 커널 세그먼트 매핑 VMA = phys + KERNEL_VMA_BASE (AddressSpace::virt_to_phys 의 역)
        pa + mmu::KERNEL_VMA_BASE
    }
}

/// Idt trait x86_64 구현체.
#[allow(dead_code)]
pub struct X86Idt;

impl crate::arch::Idt for X86Idt {
    #[inline(always)]
    unsafe fn init() {
        // SAFETY: 부팅 초기 단일 코어 시퀀스에서 1 회 호출 계약 승계
        unsafe { idt::init_idt() }
    }
    #[inline(always)]
    unsafe fn enable_irq(irq: u8) {
        // SAFETY: init 완료 + 해당 IRQ 핸들러 등록 상태 계약 승계
        unsafe { idt::enable_irq(irq) }
    }
    #[inline(always)]
    unsafe fn eoi(irq: u8) {
        // SAFETY: 해당 IRQ 핸들러 내부에서만 호출
        //         IRQ 8..15 는 Slave PIC 경유이므로 Master+Slave 양쪽 EOI 필요
        unsafe {
            if irq >= 8 {
                idt::pic_eoi_slave();
            } else {
                idt::pic_eoi_master();
            }
        }
    }
}

/// Console trait x86_64 구현체 (VGA 텍스트 버퍼 위임).
#[allow(dead_code)]
pub struct X86Console;

impl crate::arch::Console for X86Console {
    #[inline(always)]
    fn write_str(s: &str) {
        // SAFETY: VGA_BASE 는 부팅 초기 update_base 이후 유효 포인터를 가리킴
        //         (release 빌드에서 print 는 no-op 로 축약됨)
        unsafe { vga::print(s.as_bytes(), vga::Color::White) }
    }
    #[inline(always)]
    fn clear() {
        // SAFETY: VGA_BASE 유효 포인터 전제 (release 빌드 no-op)
        unsafe { vga::clear() }
    }
}

/// BootEntry trait x86_64 구현체 (Ring 3 진입 asm 위임).
#[allow(dead_code)]
pub struct X86BootEntry;

impl crate::arch::BootEntry for X86BootEntry {
    #[inline(always)]
    unsafe fn enter_user(addr_space_root: u64, entry: u64, stack: u64) -> ! {
        // SAFETY: 호출자가 addr_space_root PML4 유효성 + syscall/tss 설치 완료를
        //         보장하며 process_entry::enter_user 로 그대로 승계
        unsafe { process_entry::enter_user(addr_space_root, entry, stack) }
    }
}
