//! x86_64 arch-specific 모듈 re-export hub
//!
//! # Features
//! x86_64 전용 entropy 어댑터 (RDSEED/RDRAND + virtio PCI transport) 를 노출합니다.
//! aarch64 합류 시 본 모듈과 대칭인 aarch64 hub 가 신설됩니다.

pub mod entropy;

// ISA 의존 모듈 (CPU 제어, GDT, TSS, VGA, 부트 트램폴린)
pub mod boot_stub;
pub mod cpu;
pub mod gdt;
pub mod tss;
pub mod vga;

// 잔여 ISA 의존 모듈 (MMU, IDT, syscall)
pub mod idt;
pub mod mmu;
pub mod syscall;

// BootEntry 표면 (Ring 3 진입 asm)
pub mod process_entry;

// x86 전용 부팅 진입 시퀀스 및 GRUB Multiboot2 어댑터
pub mod kernel_start;
pub mod multiboot2;

/// 스택 캐너리 순회용 IST 가드 범위 HAL 표면 (x86 실범위 4 종).
///
/// `stack::install_canaries` 와 `validate_canaries` 가 arch 분기 없이 소비하도록
/// tss 의 IST 가드 4 종을 write-once static 슬라이스로 노출함.
/// aarch64 대칭 표면은 빈 슬라이스를 반환하여 IST 부재(SP_EL1 dedicated panic 스택)를 표현함
pub fn ist_guard_ranges() -> &'static [(u64, u64)] {
    use core::sync::atomic::{AtomicU8, Ordering};

    // 부팅 초기 write-once 후 공유 참조로만 소비되는 정적 백업 저장소
    static mut IST_GUARD_RANGES: [(u64, u64); 4] = [(0, 0); 4];
    // write-once latch 상태 0 미초기화 1 초기화 진행 2 완료
    //
    // CAS latch 로 최초 진입자만 1 회 기록하여 이미 반환된 &'static alias 와 &mut 쓰기의
    // 공존을 막고 (write-once 재진입 UB 방지), 이후 호출은 캐시된 슬라이스만 반환
    static STATE: AtomicU8 = AtomicU8::new(0);

    if STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // SAFETY 최초 진입자만 도달 다른 경로는 STATE!=0 이라 미도달 배타적 단일 기록
        // 기록 값은 정적 IST 스택 주소 유래로 결정론적이라 write-once 가 의미 동일
        unsafe {
            *(&raw mut IST_GUARD_RANGES) = tss::ist_guard_ranges();
        }
        STATE.store(2, Ordering::Release);
    } else {
        // 초기화 진행 중이면 완료까지 대기 (단일 코어 부팅에선 사실상 즉시 종료)
        while STATE.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
    }

    // SAFETY STATE==2 이후 IST_GUARD_RANGES 는 더 이상 기록되지 않으며 정적 수명
    // 불변 공유 참조로만 소비됨 (write-once 완료)
    unsafe { &*(&raw const IST_GUARD_RANGES) }
}

//
// HAL trait x86_64 구현체 (ZST + inline(always) 위임)
//
// 모든 구현체는 크기 0 의 ZST 로 기존 free fn / typestate 메서드에 얇게 위임
// dyn/Box 를 쓰지 않아 vtable 이 생성되지 않으며 aarch64 도 동일 표면을 구현하도록
// 강제하는 컴파일 타임 계약 역할
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
        unsafe { cpu::interrupts_disable() }
    }
    #[inline(always)]
    unsafe fn interrupts_enable() {
        // SAFETY: IDT/PIC 초기화 완료 이후에만 호출
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
/// 본 구현체는 3 단계 전이 표면을 위임 매핑만 함.
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
    unsafe fn write_str(s: &str) {
        // SAFETY: 호출자가 VGA_BASE 유효 초기화 계약을 승계
        //         (release 빌드에서 print 는 no-op 로 축약됨)
        unsafe { vga::print(s.as_bytes(), vga::Color::White) }
    }
    #[inline(always)]
    unsafe fn clear() {
        // SAFETY: 호출자가 VGA_BASE 유효 초기화 계약을 승계 (release 빌드 no-op)
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
