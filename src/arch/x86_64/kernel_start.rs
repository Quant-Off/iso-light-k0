//! x86_64 GRUB Multiboot2 부팅 진입 시퀀스(`_kernel_start`)를 담는 arch 전용 모듈입니다.
//!
//! # Features
//! x86 전용 부팅 진입점 `_kernel_start` 와 그 직렬화 헬퍼(fmt_dec / format_*)를
//! 제공합니다. 본 모듈은 `crate::arch::x86_64` 하위이므로 모듈 전체가 이미
//! `#[cfg(target_arch = "x86_64")]` 로 게이트되어 per-item arch cfg 가 불필요합니다.
//! `_boot_adapter_mb2` 어댑터가 mb2 핸드오프를 파싱한 뒤 no_mangle 심볼로 본
//! 진입점에 합류하며 aarch64 는 별도 boot 경로(arch/aarch64/boot.rs)를 사용합니다.

// arch 내부(super = arch::x86_64) ISA 의존 모듈
use super::mmu::{KERNEL_VMA_BASE, Mmu, PageTableFlags, Uninitialized};
use super::{cpu, gdt, idt, mmu, syscall, tss, vga};
// 부팅 시퀀스가 소비하는 crate-root 중립 모듈
// KERNEL_ADDR_SPACE 와 kernel_main_loop 는 x86 전용이라 본 모듈에 둔다
use crate::{air_gap, allocator, capability, hsm_attest, ipc, stack};
// debug 빌드 전용 SCAFFOLD 스모크 테스트 + 사용자 ELF 페이로드
#[cfg(debug_assertions)]
use crate::{
    USER_HELLO_ELF, USER_LUMEN_ELF, bus_phase2_smoke_test, chan_phase3_smoke_test,
    crypto_smoke_test, hsm_registry_smoke_test, tls_smoke_test, try_spawn_user,
};
#[cfg(all(debug_assertions, feature = "smoke"))]
use crate::{attest_phase5_1_wire_smoke_test, attest_phase5_smoke_test, gap_phase6_smoke_test};

//
// 링커 스크립트 심볼
//
// ELF absolute 심볼: `(&raw const sym) as u64` = 심볼 값
// Higher-Half 재배치 후 *_start / *_end 는 VMA (고주소 0xFFFFFFFF80XXXXXX) 이고,
// _kernel_end_phys 는 물리 주소(VMA - KERNEL_VMA_BASE) 임
unsafe extern "C" {
    // 섹션 경계 (VMA, W^X 매핑 범위 계산에 사용)
    static _text_start: u8;
    static _rodata_start: u8;
    static _data_start: u8;
    static _bss_start: u8;
    static _kernel_end_aligned: u8; // _kernel_end를 4KiB 올림 정렬한 VMA

    // 물리 주소 (allocator 보호 범위 계산에 사용)
    static _kernel_end_phys: u8;
}

//
// 커널 전역 주소 공간
//

/// 커널 전역 주소 공간 (PML4 루트 페이지 테이블 보유).
/// 부팅 후 CR3에 로드되어 커널 메모리 격리를 담당함.
// SAFETY: 부팅 초기 단일 코어 접근만 허용
// x86 전용 aarch64 는 arch/aarch64/boot.rs 내부 static 을 사용 (본체 결합 회피)
static mut KERNEL_ADDR_SPACE: mmu::AddressSpace = mmu::AddressSpace::new();

//
// 커널 진입점
//
// 64-bit 커널 진입점 boot_stub.rs 의 어셈블리 스텁 _start64 가 호출함
// mb2_addr GRUB 이 전달한 Multiboot2 info 구조체 물리 주소
//
// 부팅 시퀀스
//   1. 인터럽트 비활성화 (cli) boot_stub._start 에서 이미 수행
//   2. TSS 초기화 (IST 스택 설정)
//   3. GDT 초기화 + TSS 디스크립터 등록 + LTR 로드
//   4. IDT 초기화 + 8259 PIC 재매핑 + LIDT 로드
//   5. Multiboot2 메모리 맵 파싱
//   6. 물리 프레임 할당자 초기화
//   7. MMU typestate 초기화 (KASLR 오프셋 주입)
//   8. 직접 선형 매핑 구축 (2 MiB 페이지)
//   9. 커널 세그먼트 매핑 (W^X 정책 강제)
//  10. 커널 주소 공간 활성화 (CR3 재로드)
//  11. 인터럽트 활성화 (sti) + 커널 메인 이벤트 루프

/// u64 를 10 진 ASCII 로 buffer 에 기록하는 함수
///
/// # Arguments
/// `out` - 기록 대상 buffer
/// `at` - 기록 시작 offset
/// `v` - 직렬화할 값
fn fmt_dec(out: &mut [u8], mut at: usize, v: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut i = 0;
    let mut n = v;
    if n == 0 {
        if at < out.len() {
            out[at] = b'0';
            at += 1;
        }
        return at;
    }
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        if at < out.len() {
            out[at] = tmp[i];
            at += 1;
        }
    }
    at
}

/// timer 주파수 line 을 TimerKind 분기로 직렬화하는 함수
///
/// # Arguments
/// `buf` - 직렬화 대상 64 옥텟 buffer
/// `hz` - TSC 주파수 Hz
/// `kind` - invariant_tsc 또는 jitter_calibration 구분
fn format_timer_line(buf: &mut [u8; 64], hz: u64, kind: crate::arch::cpu::TimerKind) -> &[u8] {
    let prefix: &[u8] = match kind {
        crate::arch::cpu::TimerKind::InvariantTsc => {
            b"[iso-light-k0] timer: invariant_tsc=true freq="
        }
        crate::arch::cpu::TimerKind::JitterCalibration => {
            b"[iso-light-k0] timer: jitter_calibration freq="
        }
    };
    let mut at = 0usize;
    for &c in prefix {
        if at < buf.len() {
            buf[at] = c;
            at += 1;
        }
    }
    at = fmt_dec(&mut buf[..], at, hz);
    for &c in b" hz" {
        if at < buf.len() {
            buf[at] = c;
            at += 1;
        }
    }
    &buf[..at]
}

/// ENTROPY_SOURCES_AVAILABLE marker line 을 직렬화하는 함수
///
/// # Arguments
/// `buf` - 직렬화 대상 64 옥텟 buffer
/// `n` - boot 시점 latch 된 live source 수
fn format_sources_line(buf: &mut [u8; 64], n: u8) -> &[u8] {
    let prefix: &[u8] = b"[iso-light-k0] ENTROPY_SOURCES_AVAILABLE=";
    let mut at = 0usize;
    for &c in prefix {
        if at < buf.len() {
            buf[at] = c;
            at += 1;
        }
    }
    at = fmt_dec(&mut buf[..], at, n as u64);
    &buf[..at]
}

/// JITTER_DUMP 한 line 을 hex 직렬화하는 함수 (host-side min-entropy 분석 입력)
///
/// # Arguments
/// `buf` - 직렬화 대상 600 옥텟 buffer
/// `data` - 256 옥텟 raw delta 표본 slice
/// `line_idx` - 0..63 line 번호 2-digit decimal 표기
fn format_jitter_dump_line<'a>(buf: &'a mut [u8; 600], data: &[u8], line_idx: u8) -> &'a [u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let prefix: &[u8] = b"[iso-light-k0] JITTER_DUMP[";
    let mut at = 0usize;
    for &c in prefix {
        if at < buf.len() {
            buf[at] = c;
            at += 1;
        }
    }
    if at < buf.len() {
        buf[at] = b'0' + (line_idx / 10);
        at += 1;
    }
    if at < buf.len() {
        buf[at] = b'0' + (line_idx % 10);
        at += 1;
    }
    for &c in b"]=" {
        if at < buf.len() {
            buf[at] = c;
            at += 1;
        }
    }
    for &b in data {
        if at + 1 < buf.len() {
            buf[at] = HEX[(b >> 4) as usize];
            buf[at + 1] = HEX[(b & 0x0f) as usize];
            at += 2;
        }
    }
    &buf[..at]
}

// x86_64 multiboot2 부팅 진입점(vga/gdt/tss/idt/build_linear_map/iretq 전용)이며
// aarch64 는 boot_stub el1_entry 에서 별도 부팅 경로(MMU stage1 매핑 후 park)를 밟아
// 본 진입점을 호출하지 않으므로 arch cfg 게이트로 aarch64 컴파일 대상에서 배제
#[unsafe(no_mangle)]
pub extern "C" fn _kernel_start(boot_info: &'static crate::boot::BootInfo) -> ! {
    //
    // 1. 인터럽트 재확인 비활성화
    //
    // boot_stub._start에서 cli를 실행했지만, 64-bit 진입 후에도 명시적으로 보장
    // SAFETY: GDT/IDT 설정 전, 인터럽트 비활성화 안전
    unsafe {
        crate::arch::active::cpu::interrupts_disable();
    }

    //
    // 조기 VGA 부팅 메시지 (debug 전용)
    //
    // GDT/IDT 초기화 전이지만 boot_stub의 4 GiB identity map이 유효하므로
    // 물리 주소 0xB8000(VGA 버퍼)을 직접 접근 가능
    // SAFETY: identity map 활성, VGA_BASE = 0xB8000(물리=가상), CLI 상태
    #[cfg(debug_assertions)]
    unsafe {
        vga::clear();
        vga::println(b"[iso-light-k0] Booted. Initializing...", vga::Color::Green);
    }

    //
    // 1.5. SIMD/FPU 컨텍스트 활성화
    //
    // elib-k0-nt의 암호 기본연산(AES-NI, SHA-NI, BLAKE3 SIMD, mfence 등)이
    // #UD 없이 실행되도록 x87/SSE, 가능 시 AVX를 활성화함
    // IDT 설치 전에 수행해도 되지만, 치명 예외 발생 시 fatal_halt로 떨어지도록
    // IDT 설치 직후에 한 번 더 상태를 확정함 (아래 4단계 직후 finalize)
    // SAFETY: 단일 코어, CLI 상태에서 CR0/CR4/XCR0 MSR 조작
    unsafe {
        cpu::enable_simd_fpu();
        #[cfg(debug_assertions)]
        vga::println(
            b"[iso-light-k0] CPU SIMD/FPU Context Ready.",
            vga::Color::Green,
        );
    }

    //
    // 1.6. 스택 가드 캐너리 설치
    //
    // 부트 스택 / IST 스택 가드 영역에 고유 패턴을 기록
    // MMU 페이지 가드가 활성화되기 전(activate() 이전) 스택 오버플로를
    // 탐지하기 위한 소프트웨어 감시 레이어
    unsafe {
        stack::install_canaries();
    }

    //
    // 2. TSS 초기화 (#DF IST 스택 설정)
    //
    // SAFETY: 인터럽트 비활성화 상태, 단일 코어 부팅 초기
    unsafe {
        vga::println(b"[iso-light-k0] TSS Init...", vga::Color::Green);
        tss::init();
        vga::println(b"[iso-light-k0] Done.", vga::Color::Green);
    }

    //
    // 3. GDT 초기화 + TSS 등록 + LTR
    //
    // boot_stub의 boot_gdt64를 Rust 커널 GDT(+ TSS)로 교체함
    // SAFETY: CLI 상태, TSS 초기화 완료, KERNEL_GDT 유효
    unsafe {
        vga::println(b"[iso-light-k0] GDT Init & Apply TSS...", vga::Color::Green);
        gdt::init_gdt(tss::base_addr(), tss::limit());
        vga::println(b"[iso-light-k0] Done.", vga::Color::Green);
    }

    //
    // 4. IDT 초기화 + 8259 PIC 재매핑 + LIDT
    //
    // SAFETY: CLI 상태, GDT/TSS 로드 완료
    unsafe {
        vga::println(b"[iso-light-k0] IDT Init...", vga::Color::Green);
        idt::init_idt();
        vga::println(b"[iso-light-k0] Done.", vga::Color::Green);
    }

    //
    // 4.5. SIMD/FPU 최종 확정 (예외 핸들러 가용 상태에서 재검증)
    //
    // SAFETY: IDT가 로드된 이후이므로 XSETBV가 GP를 일으키면 #GP 핸들러로 진입 가능
    unsafe {
        cpu::finalize_simd_fpu();
    }

    //
    // 4.6. 사용자/커널 격리 보안 비트 일괄 활성화
    //
    // CR0.WP, CR4.SMEP/SMAP/UMIP, IA32_EFER.SCE 를 한 번에 켜서 Ring 3
    // 사용자 프로세스가 진입하기 전에 격리 경계를 확립함
    // SAFETY: enable_simd_fpu() 로 CpuFeatures 가 캐싱됨, IDT 활성, CLI 상태
    unsafe {
        cpu::enable_security_bits();
        vga::println(
            b"[iso-light-k0] CR0.WP + CR4.SMEP/SMAP/UMIP + EFER.SCE Ready.",
            vga::Color::Green,
        );
    }

    //
    // 4.7. syscall/sysret 인프라 설치
    //
    // STAR/LSTAR/CSTAR/SFMASK + KernelGsBase 를 BSP 에 설치
    // RSP0 는 부트 스택 최상단(boot_stack_top) 으로 설정하며 인터럽트가 사용자
    // 모드에서 발생하면 자동으로 본 RSP 가 적재되고 syscall stub 은 GS-relative
    // 로 동일 값 사용
    unsafe {
        let (_, kstack_top) = stack::boot_stack_range();
        // 16-byte 정렬은 System V x86_64 ABI 요구사항
        let kstack_top = kstack_top & !0xF;
        tss::set_rsp0(kstack_top);
        syscall::install(kstack_top);
        vga::println(
            b"[iso-light-k0] Syscall ABI Installed (STAR/LSTAR/SFMASK).",
            vga::Color::Green,
        );
    }

    //
    // 5. BootInfo 메모리 맵 소비 (파싱은 boot 어댑터가 수행 완료)
    //
    // 어댑터(_boot_adapter_mb2)가 mb2 핸드오프를 파싱해 boot_info.memory_map 을
    // 채운 뒤 진입시켰으므로 _kernel_start 는 펌웨어-중립 참조만 소비함
    let memory_map = &boot_info.memory_map;
    unsafe {
        vga::println(
            b"[iso-light-k0] BootInfo Memory Map Consumed.",
            vga::Color::Green,
        );
    }
    // kaslr_offset 은 mb2 어댑터(_boot_adapter_mb2)가 parse_kaslr_offset 로 배선함
    // 태그 부재 시 0(미제공)이면 None 이고 부트로더가 KASLR 태그 삽입 시 Some
    let kaslr_offset: Option<u64> = if boot_info.kaslr_offset == 0 {
        None
    } else {
        Some(boot_info.kaslr_offset)
    };

    //
    // 6. 물리 프레임 할당자 초기화
    //
    // SAFETY: 부팅 초기 단일 코어, MMU 활성화 전
    unsafe {
        vga::println(
            b"[iso-light-k0] Physic Frame Allocator Init...",
            vga::Color::Green,
        );
        allocator::init(memory_map);

        //
        // (a) 하위 1 MiB 예약: BIOS/VGA/IVT 영역
        //
        // QEMU 메모리 맵은 0x0000~0x09FC00 구간을 Usable로 표시함
        // alloc_frame()이 0x0000을 반환하면 Rust/LLVM은 null pointer
        // dereference(UB)로 처리하여 미정의 동작이 발생함
        // x86 관례: 하위 1 MiB(BIOS 데이터, VGA 버퍼, BIOS ROM)는
        // 커널 페이지 테이블 프레임으로 절대 사용하지 않음
        allocator::mark_used(0, 0x100000);

        //
        // (b) 커널 자신의 물리 영역 보호
        //
        // GRUB의 Multiboot2 메모리 맵은 커널이 로드된 영역(0x100000~)을
        // Usable로 표시하는 경우가 있으며 이때 alloc_frame()이 boot_pml4
        // (0x12B000), boot_pdpt(0x12C000), boot_stack(0x12D000~) 등
        // 현재 사용 중인 프레임을 반환하여 페이지 테이블을 파괴함
        // 따라서 링커 심볼 _kernel_end로 정확한 끝 주소를 구해 전체 범위를 예약함
        //
        // SAFETY: _kernel_end는 링커가 .bss 끝에 배치한 심볼
        //         phys_end는 0x100000에서 시작하는 커널의 물리 끝 주소
        let phys_end = (&raw const _kernel_end_phys) as u64;
        // 페이지 정렬(4KiB)로 올림
        let phys_end_aligned = (phys_end + 0xFFF) & !0xFFF;
        allocator::mark_used(0x100000, phys_end_aligned - 0x100000);

        //
        // (c) 펌웨어 핸드오프(mb2 info) 구조체는 boot 어댑터가 이미 전량 소비했음
        //
        // 파싱 결과가 BootInfo(커널 .bss, (b) 로 이미 보호됨)로 복사되었으므로
        // 원본 mb2 info 영역은 더 이상 참조되지 않으며 펌웨어-중립 _kernel_start
        // 는 mb2_addr 을 보유하지 않아 죽은 핸드오프 영역의 별도 예약이 불필요하다

        vga::println(b"[iso-light-k0] Done.", vga::Color::Green);
    }

    //
    // 7. MMU Typestate 초기화 + KASLR 오프셋 주입
    //
    let mmu: Mmu<Uninitialized> = Mmu::new();
    let mmu_init = mmu.initialize(kaslr_offset);

    unsafe {
        vga::println(
            b"[iso-light-k0] MMU Typestate Init Done.",
            vga::Color::Green,
        );
    }

    //
    // 8. 직접 선형 매핑 + 저주소 identity 매핑 구축 (커널 .text/.rodata RO carve-out)
    //
    // SAFETY: 부팅 초기 단일 코어, KERNEL_ADDR_SPACE 단독 접근
    let kernel_space = unsafe { &mut *(&raw mut KERNEL_ADDR_SPACE) };
    // 커널 .text/.rodata 물리 범위 (phys = VMA - KERNEL_VMA_BASE, linker.ld 보장)
    let ro_phys_start = (&raw const _text_start) as u64 - KERNEL_VMA_BASE;
    let ro_phys_end = (&raw const _data_start) as u64 - KERNEL_VMA_BASE;
    if mmu_init
        .build_linear_map(
            kernel_space,
            memory_map.highest_addr(),
            ro_phys_start,
            ro_phys_end,
        )
        .is_err()
    {
        // SAFETY: VGA MMIO 단일 코어 부팅 시점 접근
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: linear map build failure",
                vga::Color::Red,
            );
        }
        // activate() 가 미완성 매핑으로 진행되면 triple fault 이므로 fail-closed 중단
        panic!("linear map build failure");
    }
    if mmu_init
        .build_identity_map(
            kernel_space,
            memory_map.highest_addr(),
            ro_phys_start,
            ro_phys_end,
        )
        .is_err()
    {
        // SAFETY: VGA MMIO 단일 코어 부팅 시점 접근
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: identity map build failure",
                vga::Color::Red,
            );
        }
        // 저주소 identity 계약(부트 스택 process.rs virtio DMA) 미보존 진행 금지 fail-closed
        panic!("identity map build failure");
    }

    unsafe {
        vga::println(b"[iso-light-k0] Linear Mapping Done.", vga::Color::Green);
    }

    //
    // 9. 커널 세그먼트 매핑 (W^X 정책)
    //
    // Higher-Half 재배치 완료: 커널 섹션은 VMA 0xFFFFFFFF80XXXXXX에 위치
    // 직접 선형 매핑(PML4[256], PHYS_MAP_OFFSET=0xFFFF_8000_0000_0000)과
    // 커널 세그먼트(PML4[511], KERNEL_VMA_BASE=0xFFFF_FFFF_8000_0000)는
    // 서로 다른 PML4 엔트리를 사용하므로 주소 충돌 없음
    //
    // 섹션별 W^X 권한: .text 는 PRESENT (R+X, 쓰기 금지), .rodata 는
    // PRESENT | NO_EXECUTE (R, 쓰기/실행 금지), .data 와 .bss 는
    // PRESENT | WRITABLE | NO_EXECUTE (RW, 실행 금지)
    //
    // 매핑 범위: 링커 심볼 기반 섹션 경계 ([start, next_section_start))
    // 인접 섹션이 4KiB 정렬되므로 ALIGN_UP 계산이 필요 없으며, .bss 끝은
    // _kernel_end_aligned (4KiB 올림 정렬) 임
    //
    // 물리 주소: phys = VMA - KERNEL_VMA_BASE  (linker.ld 보장)
    // phys는 boot_page_table의 identity map(PML4[0]) 범위에 있으므로
    // alloc_or_get_table이 할당한 중간 테이블 프레임도 정상 접근 가능
    unsafe {
        let text_start = (&raw const _text_start) as u64;
        let rodata_start = (&raw const _rodata_start) as u64;
        let data_start = (&raw const _data_start) as u64;
        let bss_start = (&raw const _bss_start) as u64;
        let kernel_end = (&raw const _kernel_end_aligned) as u64;

        let page = mmu::PAGE_SIZE as u64;

        // .text: R+X (PRESENT, 쓰기/NX 없음)
        let mut va = text_start;
        while va < rodata_start {
            let _ = kernel_space.map_page(va, va - KERNEL_VMA_BASE, PageTableFlags::PRESENT);
            va += page;
        }

        // .rodata: R (PRESENT | NO_EXECUTE)
        let ro = PageTableFlags::PRESENT.union(PageTableFlags::NO_EXECUTE);
        va = rodata_start;
        while va < data_start {
            let _ = kernel_space.map_page(va, va - KERNEL_VMA_BASE, ro);
            va += page;
        }

        // .data / .bss: RW (PRESENT | WRITABLE | NO_EXECUTE)
        let rw = PageTableFlags::PRESENT
            .union(PageTableFlags::WRITABLE)
            .union(PageTableFlags::NO_EXECUTE);
        va = data_start;
        while va < bss_start {
            let _ = kernel_space.map_page(va, va - KERNEL_VMA_BASE, rw);
            va += page;
        }
        // .bss 매핑: IST 스택 가드 페이지는 의도적으로 미매핑하여
        // 스택 오버플로 시 하드웨어 수준의 #PF를 유발함 (IST4 #PF 핸들러로 진입)
        let ist_guards = tss::ist_guard_vmas();
        va = bss_start;
        while va < kernel_end {
            if !stack::is_in_any_guard(va, &ist_guards) {
                let _ = kernel_space.map_page(va, va - KERNEL_VMA_BASE, rw);
            }
            va += page;
        }

        vga::println(
            b"[iso-light-k0] Kernel Segment Mapped (W^X + IST Guards).",
            vga::Color::Green,
        );
    }

    //
    // 10. VGA 선형 가상 주소 사전 계산
    //
    // activate() 직후 vga::update_base(vga_virt) 로 VGA 접근을 KERNEL_ADDR_SPACE
    // PML4[256] direct linear map 주소로 전환하기 위한 사전 계산
    let vga_virt = unsafe { mmu_init.phys_to_virt_mut::<u16>(0xB8000) };

    //
    // 11. 커널 주소 공간 활성화 (CR3 재로드, W^X 실효화)
    //
    // SAFETY: Ring 0 부팅 초기 IA32_EFER 읽기
    let efer = unsafe { cpu::rdmsr(cpu::IA32_EFER) };
    if efer & cpu::EFER_NXE == 0 {
        // SAFETY: VGA MMIO 단일 코어 부팅 시점 접근
        unsafe {
            vga::println(b"[iso-light-k0] FATAL: EFER.NXE not set", vga::Color::Red);
        }
        // NXE=0 이면 NO_EXECUTE 비트 페이지 테이블 로드가 reserved bit #PF 이므로 사전 차단
        panic!("EFER.NXE not set");
    }

    // SAFETY: 선형 매핑 + 커널 PML4[256..511] 매핑 + 저주소 identity 매핑(8단계) 완료 이후 호출
    unsafe {
        mmu_init.activate(kernel_space);
    }
    // SAFETY: activate() 직후 + 선형 매핑이 0xB8000 포함 (vga.rs update_base 계약)
    unsafe {
        vga::update_base(vga_virt);
    }

    unsafe {
        vga::println(
            b"[iso-light-k0] W^X Enforced. (CR3 kernel PML4, NXE=1)",
            vga::Color::Green,
        );
    }

    #[cfg(all(feature = "wx-probe-text", not(debug_assertions)))]
    compile_error!("wx-probe-text 는 debug 빌드 전용 실증 프로브다 (release 잔류 금지)");
    #[cfg(all(feature = "wx-probe-linear", not(debug_assertions)))]
    compile_error!("wx-probe-linear 는 debug 빌드 전용 실증 프로브다 (release 잔류 금지)");

    #[cfg(all(target_arch = "x86_64", debug_assertions, feature = "wx-probe-text"))]
    // SAFETY: 의도적 #PF 유발 실증 프로브 idt.rs page_fault_handler 가 fatal_halt
    unsafe {
        vga::println(
            b"[iso-light-k0] WX_PROBE_TEXT: write .text VMA (expect #PF)",
            vga::Color::Yellow,
        );
        core::ptr::write_volatile((&raw const _text_start) as *mut u8, 0xCC);
    }

    #[cfg(all(target_arch = "x86_64", debug_assertions, feature = "wx-probe-linear"))]
    // SAFETY: 의도적 #PF 유발 실증 프로브 linear alias RO carve-out 검증
    unsafe {
        vga::println(
            b"[iso-light-k0] WX_PROBE_LINEAR: write .text linear alias (expect #PF)",
            vga::Color::Yellow,
        );
        core::ptr::write_volatile(mmu_init.phys_to_virt_mut::<u8>(ro_phys_start), 0xCC);
    }

    //
    // 12. Capability DRBG 초기화 (HW 엔트로피 기반 Hash-DRBG)
    //
    // RDSEED / RDRAND 로 수집한 하드웨어 엔트로피로 NIST SP 800-90A Rev.1
    // HashDRBGSHA256 을 인스턴스화하며 이후 Capability 토큰 생성은 모두
    // 이 DRBG 를 통해 이루어짐
    // SAFETY: cpu::enable_simd_fpu() 완료 후 단일 코어에서 최초 1회 호출
    unsafe {
        // (1) virtio-rng PCI probe 부팅 시 1 회
        // SAFETY BSP single-core boot MMU identity map 가정
        crate::arch::common::entropy::virtio_rng::init_virtio_rng_instance();

        // (2) jitter boot self-test 16384 sample min-entropy 회귀 TCG 환경 self-disable
        // SAFETY BSP single-core JITTER_POOL 단일 진입
        let jitter_ok = crate::arch::common::entropy::jitter::jitter_boot_self_test();
        if !jitter_ok {
            vga::println(
                b"[iso-light-k0] WARN: jitter self-test fail (TCG environment likely)",
                vga::Color::Yellow,
            );
        }

        // (3) timer frequency line emit invariant_tsc 와 jitter 소스 구분 None 처리
        match crate::arch::cpu::timer_frequency() {
            Some((hz, kind)) => {
                let mut tbuf = [0u8; 64];
                let msg = format_timer_line(&mut tbuf, hz, kind);
                vga::println(msg, vga::Color::Green);
            }
            None => {
                vga::println(
                    b"[iso-light-k0] WARN: no timer source (jitter disabled)",
                    vga::Color::Red,
                );
            }
        }

        // (4) entropy-degraded-ok build marker Red ALERT 식별
        #[cfg(feature = "entropy-degraded-ok")]
        vga::println(
            b"[iso-light-k0] ENTROPY_DEGRADED_OK_ACTIVE=1",
            vga::Color::Red,
        );

        match capability::init_prng() {
            Ok(()) => {
                vga::println(
                    b"[iso-light-k0] Capability DRBG Init Done. (Hash-DRBG-SHA256)",
                    vga::Color::Green,
                );

                // (5) ENTROPY_SOURCES_AVAILABLE=N marker
                let n_sources =
                    crate::arch::common::entropy::QuorumEntropy::sources_available_at_boot();
                let mut nbuf = [0u8; 64];
                let nmsg = format_sources_line(&mut nbuf, n_sources);
                vga::println(nmsg, vga::Color::Green);

                // (6) quorum status marker production strict / degraded
                #[cfg(not(feature = "entropy-degraded-ok"))]
                vga::println(
                    b"[iso-light-k0] ENTROPY_QUORUM_2_OF_3_OK",
                    vga::Color::Green,
                );
                #[cfg(feature = "entropy-degraded-ok")]
                vga::println(
                    b"[iso-light-k0] ENTROPY_QUORUM_1_OF_3_OK",
                    vga::Color::Green,
                );

                // (7) JitterRng 16384 sample boot self-test PASS 시 raw 표본 전체 hex dump
                // host-side ea_iid (NIST SP 800-90B) 또는 in-tree estimator 가 boot serial 의
                // JITTER_BOOT_DUMP_BEGIN END 사이 16384 옥텟 추출 후 min-entropy >= 0.5 회귀 검증
                // 64 line x 256 byte = 16384 옥텟 raw pre-conditioning 표본 (key material 아님)
                if jitter_ok {
                    vga::println(
                        b"[iso-light-k0] JITTER_BOOT_DUMP_BEGIN N=16384",
                        vga::Color::Green,
                    );
                    // SAFETY BSP single-core BOOT_SELF_TEST_BUF 단일 진입 read
                    let dump_buf =
                        crate::arch::common::entropy::jitter::boot_self_test_samples();
                    for line_idx in 0..64 {
                        let mut hex_buf = [0u8; 600];
                        let off = line_idx * 256;
                        let msg = format_jitter_dump_line(
                            &mut hex_buf,
                            &dump_buf[off..off + 256],
                            line_idx as u8,
                        );
                        vga::println(msg, vga::Color::White);
                    }
                    vga::println(
                        b"[iso-light-k0] JITTER_BOOT_DUMP_END",
                        vga::Color::Green,
                    );
                }
            }
            Err(_) => {
                vga::println(
                    b"[iso-light-k0] FATAL: entropy quorum failure",
                    vga::Color::Red,
                );
                // 엔트로피 quorum 부재는 무조건 부팅 중단 fail-closed
                // 이후 BOOT_CHALLENGE 와 capability 토큰이 전부 0 이 되는 상태로 진행 금지
                panic!("entropy quorum failure");
            }
        }
    }

    // 부팅 시 1 회 신뢰 루트 dual-path 초기화 + BOOT_CHALLENGE 생성
    // capability::init_prng 직후 + ipc::init 직전 위치 BOOT_CHALLENGE 생성은 CAP_DRBG 만 의존
    // SAFETY 단일 코어 부팅 초기 capability::init_prng 완료 가정
    unsafe {
        hsm_attest::init_trust_root();
        vga::println(
            b"[iso-light-k0] Trust Root Init Done. (ML-DSA-44 1312B + BOOT_CHALLENGE 32B)",
            vga::Color::Green,
        );
    }

    // 부팅 시 1 회 NETWORK_ATTACH + AUDIT_READ cap mint (양 프로필 공통 + cfg)
    // 호출 위치 hsm_attest::init_trust_root 직후 capability::init_prng + init_trust_root 완료 가정
    // SAFETY 단일 코어 부팅 초기 BSP single-core invariant 양 init_*_cap 의 단일 진입 갱신
    unsafe {
        air_gap::init_audit_read_cap();
        vga::println(
            b"[iso-light-k0] AUDIT_READ_CAP Init Done.",
            vga::Color::Green,
        );

        #[cfg(feature = "tls-external")]
        {
            air_gap::init_network_cap();
            vga::println(
                b"[iso-light-k0] NETWORK_ATTACH_CAP Init Done.",
                vga::Color::Green,
            );
        }
    }

    //
    // 13. IPC 서브시스템 초기화
    //
    // EP_SYSTEM(0x0000), EP_CRYPTO(0x0001) 엔드포인트를 등록함
    // Capability는 사용자 공간 프로세스에게 ipc::issue_*_capability()로 발급됨
    // EP_CRYPTO 로의 ipc_call 은 crypto_service::dispatch() 가 동기적으로 처리함
    // SAFETY: 단일 코어 부팅 초기, IDT/GDT 초기화 완료 후
    unsafe {
        ipc::init();
        vga::println(
            b"[iso-light-k0] IPC Init Done. (EP_SYSTEM, EP_CRYPTO, EP_SIGN)",
            vga::Color::Green,
        );
    }

    // HsmRegistry 정적 인스턴스는 `const fn new()` 로 부팅 instruction 0 시점부터
    // 온라인이라 별도 init 호출이 불필요하며 VGA 마커로 BSS 배치와 alloc=0 보장을 가시화
    // SAFETY: VGA MMIO 단일 코어 부팅 시점 접근으로 기존 println 호출 규약과 동일
    unsafe {
        vga::println(
            b"[iso-light-k0] HsmRegistry static online (8 slots, alloc=0)",
            vga::Color::Green,
        );
    }

    //
    // 14. 부트 시점 Crypto Service 라운드트립 스모크 테스트
    //
    // 디버그 빌드에서만 수행하며 EP_CRYPTO Capability 를 발급한 뒤
    //   ipc_call(HashReq, BLAKE3, "iso-light-k0")
    // 흐름이 ipc_call 에서 crypto_service::dispatch 를 거쳐 ipc_reply 까지 동기적으로
    // 완결되는지 확인하여 DRBG, IPC, Crypto Service 와이어링이 모두 정상임을
    // 실측하고 결과 페이로드의 첫 두 바이트(`algo` 에코, `key_len`)를
    // 검사하여 성공/실패를 판정함
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    unsafe {
        crypto_smoke_test();
    }

    //
    // 14.5. 부트 시점 TLS 1.3 PSK 핸드셰이크 스모크 테스트
    //
    // 디버그 빌드에서만 수행하며 SoftKeystore 에 임시 PSK 를 등록하고 in-kernel
    // 루프백으로 PSK-PQ-Hybrid (X25519+ML-KEM-768) 와 Classical (X25519) 두
    // 정책에 대해 각각 핸드셰이크 + AEAD 라운드트립을 검증하고 종료 후 키저장소
    // 와 커넥션 풀을 모두 zeroize 함
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    unsafe {
        tls_smoke_test();
    }

    //
    // 14.7. 부트 시점 HsmRegistry 라운드트립 스모크 테스트
    //
    // 디버그 빌드 한정, attach, is_valid_for, detach, zeroize 사이클을 in-kernel
    // 경로로 검증하고 qemu-test.sh 가 기대하는 마커 문자열 출력
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: capability::init_prng / ipc::init / HsmRegistry static 모두 온라인, 단일 코어
    unsafe {
        hsm_registry_smoke_test();
    }

    //
    // 14.8. 부트 시점 BusDriver 라운드트립 스모크 테스트
    //
    // SoftwareBus 루프백 echo(write 후 read) + ct_eq 일치 + detach 후 raw bytes==0
    // 성공 시 qemu-test.sh 의 BUS_PHASE2_OK 마커 게이트 통과, 앞 마커 보존
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: 앞 스모크 완료 직후, REGISTRY 비어 있고 BSP 단일 코어
    unsafe {
        bus_phase2_smoke_test();
    }

    //
    // 14.9. 부트 시점 In-Kernel Inter-HSM Channel 스모크 테스트
    //
    // Blake3 src 에서 AesGcm dst 로 relay 후 ciphertext in-kernel 재계산 동치성
    // 성공 시 qemu-test.sh 의 CHAN_PHASE3_OK 마커 게이트 통과, 앞 마커 보존
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: 앞 스모크 후 detach cascade 가 REGISTRY 를 비움
    unsafe {
        chan_phase3_smoke_test();
    }

    //
    // 14.10. 부트 시점 Attestation Gate 2-leg 스모크 테스트, feature smoke 한정
    //
    // Leg 1 valid sig 흐름 attach 성공, Leg 2 mutated sig 흐름 reject + 슬롯 변동 0
    // 성공 시 qemu-test.sh ATTEST_PHASE5_OK 마커 게이트 통과, closed 프로필 부재
    #[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
    // SAFETY: 앞 스모크 후 detach cascade 가 REGISTRY 를 비움, hsm_attest::init_trust_root 가 BSS 채움
    unsafe {
        attest_phase5_smoke_test();
        // wire AttestSubmit / Status 라운드트립 스모크
        // 앞 마커 직후 호출, 두 마커 모두 emit
        attest_phase5_1_wire_smoke_test();
        // air-gap 이중 게이트 + sys_hsm_status + gap_self_check 4줄 마커 emit
        gap_phase6_smoke_test();
    }

    //
    // 15. 인터럽트 활성화 + 커널 메인 이벤트 루프
    //
    // IDT, GDT, TSS, PIC 초기화 완료 후 STI로 인터럽트 수신 시작
    // SAFETY: IDT/GDT/TSS/PIC/IPC 초기화 완료, 이제 인터럽트 수신 안전
    unsafe {
        crate::arch::active::cpu::interrupts_enable();
        vga::println(b"[iso-light-k0] All Task Done.", vga::Color::Green);
    }

    // Layer 2 self-check, 모든 init + syscall::install + dispatcher arm 등록 직후
    // 호출 위치는 syscall::install 후, try_spawn_user 진입 전 fail-stop 경계
    // SAFETY: 모든 init_* + STAR/LSTAR MSR 등록 완료, Ring 3 진입 이전 단일 코어
    unsafe {
        air_gap::gap_self_check();
        vga::println(b"[iso-light-k0] gap_self_check OK.", vga::Color::Green);
    }

    //
    // 16. Ring 3 사용자 프로세스 spawn (debug 빌드 + 유효 ELF 한정)
    //
    // 우선 lumen 와이어 호환 검증 프로그램(iso-user-lumen) 을 시도. ELF 가
    // placeholder(4 바이트) 또는 빌드되지 않은 경우 elf::parse 가 거절하므로
    // 그 다음 iso-user-hello 를 시도, 둘 다 실패하면 커널 메인 루프 진입
    //
    // enter_ring3 는 ! 반환, 성공 시 본 함수는 결코 메인 루프에 도달하지 않음
    // 사용자 프로세스가 sys_exit 하면 syscall::sys_exit 가 cli + hlt 무한 루프로 정지
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: 위 단계가 모두 완료된 후, activate() 는 호출하지 않으며
    //         enter_ring3 가 사용자 PML4 로 cr3 전환을 직접 수행
    unsafe {
        let kernel_space = &*(&raw const KERNEL_ADDR_SPACE);
        try_spawn_user(USER_LUMEN_ELF, b"iso-user-lumen", kernel_space);
        try_spawn_user(USER_HELLO_ELF, b"iso-user-hello", kernel_space);
        vga::println(
            b"[iso-light-k0] no valid user ELF embedded; entering kernel main loop",
            vga::Color::Yellow,
        );
    }

    kernel_main_loop()
}

/// 마이크로커널 메인 이벤트 루프.
///
/// IPC 요청, 타이머 인터럽트 대기 (hlt).
/// TODO: IPC 수신 큐 처리, Capability 검증, 스케줄러 연동
// x86 전용 진입 aarch64 부팅 합류점은 arch/aarch64 가 별도로 보유
fn kernel_main_loop() -> ! {
    loop {
        crate::arch::active::cpu::wait_for_interrupt();
    }
}
