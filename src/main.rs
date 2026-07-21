#![no_std]
#![no_main]
// x86-interrupt 호출 규약: extern "x86-interrupt" 핸들러 작성에 필요
#![feature(abi_x86_interrupt)]
// `static mut` 접근은 Rust 2024 의 `static_mut_refs`lint를 회피하기 위해
// `*(&raw const|mut X)` 패턴을 사용함. clippy의 `deref_addrof`는 이 패턴을
// `X` 직접 접근과 동치로 보고 경고하지만, 직접 접근은 다시 `static_mut_refs`
// 를 유발하므로 커널 전역에서 본 lint를 명시적으로 허용함
#![allow(clippy::deref_addrof)]

pub mod allocator;
pub mod arch; // Phase 8: arch 디렉토리 골격 (D-01 Forward) + entropy 서브트리
// Phase 9 9-A/9-B HAL-04 ISA 의존 모듈은 src/arch/x86_64/ 로 이동하고 명시 목록 re-export 로 본체 경로 보존 (OQ6)
#[cfg(target_arch = "x86_64")]
pub use crate::arch::active::{boot_stub, cpu, gdt, idt, mmu, syscall, tss, vga};
// aarch64 는 gdt/idt/tss/vga(x86 전용 세그먼트/프레임버퍼) 부재 -> arch-중립 공통
// 서브셋만 re-export (10-05 body 중립화 x86 boot 진입은 아래 cfg 게이트로 분리)
#[cfg(target_arch = "aarch64")]
pub use crate::arch::active::{boot_stub, cpu, mmu, syscall};
// Phase 9 9-C 펌웨어-중립 boot 계층 (BootInfo + multiboot2/uefi 어댑터, HAL-08)
pub mod boot;
// 중립 메모리맵 타입은 boot 계층으로 2차 이동됨 crate::memory_map 경로는 별칭으로 보존 (allocator 본체 무변경)
pub use crate::boot::memory_map;
pub mod capability; // Capability-based Access Control
pub mod crypto_service; // EP_CRYPTO 엔드포인트 암호화 서비스 디스패처
pub mod sign_service;   // EP_SIGN 엔드포인트 ML-DSA PQ 서명 서비스
pub mod elf; // ELF64 정적 실행 파일 파서
pub mod hsm; // HSM 추상 트레이트 + NullHsm
pub mod hsm_registry; // Phase 1: HSM 멀티 슬롯 레지스트리 (capability-backed)
pub mod hsm_attest; // Phase 5: ML-DSA-44 attest verifier + AUDIT_RING + ATTEST_BUF
pub mod air_gap; // Phase 6: air-gap 이중 게이트 + sys_hsm_status + 2 층 self-check
pub mod bus; // Phase 2: 외부 버스 드라이버 추상화 (BusDriver trait + enum-dispatch)
pub mod ipc; // IPC 메시지 패싱 (동기 rendezvous)
pub mod keystore; // 소프트 PSK 키 저장소 (HSM 폴백)
mod panic;
pub mod process; // 정적 프로세스 슬롯 + Ring 3 진입
pub mod stack; // 커널 스택 + 가드 페이지 레이아웃
pub mod tls; // TLS 1.3 PSK (psk_dhe_ke / psk_pq_hybrid_ke)
// 보안 메모리 소거는 외부 `zeroize` 크레이트(elib-k0-nt) 사용

use mmu::AddressSpace;
// KERNEL_VMA_BASE/Mmu/PageTableFlags/Uninitialized 는 x86 _kernel_start boot 시퀀스
// 전용 소비 (aarch64 는 boot_stub 별도 경로) -> arch cfg 로 미사용 import 경고 제거
#[cfg(target_arch = "x86_64")]
use mmu::{KERNEL_VMA_BASE, Mmu, PageTableFlags, Uninitialized};

//
// 사용자 ELF 페이로드 (build.rs 가 OUT_DIR 로 복사한 후 환경변수로 노출)
//
// Phase C/D 의 사용자 크레이트가 빌드되어 있지 않으면 build.rs 가 4-byte
// ELF magic placeholder 만 임베드함. 그 경우 elf::parse() 가 `Truncated` /
// `BadMagic` 으로 거절하여 spawn 시도가 안전하게 fail-stop 됨.
//
// Phase E 통합 단계에서 _kernel_start 가 spawn_elf + enter_ring3 를 호출하면
// dead_code 경고가 자동으로 해소됨. 그 전까지 일시 허용.
#[allow(dead_code)]
const USER_HELLO_ELF: &[u8] = include_bytes!(env!("ISO_USER_HELLO_ELF"));
#[allow(dead_code)]
const USER_LUMEN_ELF: &[u8] = include_bytes!(env!("ISO_USER_LUMEN_ELF"));

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
static mut KERNEL_ADDR_SPACE: AddressSpace = AddressSpace::new();

//
// 커널 진입점
//

/// 64-bit 커널 진입점.
///
/// `boot_stub.rs`의 어셈블리 스텁(`_start64`)이 호출함.
/// `mb2_addr`: GRUB이 전달한 Multiboot2 info 구조체 물리 주소.
///
/// 부팅 시퀀스:
///   1. 인터럽트 비활성화 (cli) <- boot_stub._start에서 이미 수행
///   2. TSS 초기화 (IST 스택 설정)
///   3. GDT 초기화 + TSS 디스크립터 등록 + LTR 로드
///   4. IDT 초기화 + 8259 PIC 재매핑 + LIDT 로드
///   5. Multiboot2 메모리 맵 파싱
///   6. 물리 프레임 할당자 초기화
///   7. MMU typestate 초기화 (KASLR 오프셋 주입)
///   8. 직접 선형 매핑 구축 (2 MiB 페이지)
///   9. 커널 세그먼트 매핑 (W^X 정책 강제)
///  10. 커널 주소 공간 활성화 (CR3 재로드) <- TODO: 링커 스크립트 재배치 후
///  11. 인터럽트 활성화 (sti) + 커널 메인 이벤트 루프
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

/// timer 주파수 line 을 TimerKind 분기로 직렬화하는 함수 (ROADMAP SC 7 2-source 구분)
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

/// ENTROPY_SOURCES_AVAILABLE marker line 을 직렬화하는 함수 (Pitfall 5 visibility)
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

// x86_64 multiboot2 부팅 진입점(vga/gdt/tss/idt/build_linear_map/iretq 전용). aarch64 는
// boot_stub el1_entry 에서 별도 부팅 경로(10-C MMU stage1 + park)를 밟으므로 본 진입점을
// 호출하지 않음 -> arch cfg 게이트로 aarch64 컴파일 대상에서 배제 (x86 byte-diff 0)
#[cfg(target_arch = "x86_64")]
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
    // 사용자 프로세스가 진입하기 전에 격리 경계를 확립함.
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
    // STAR/LSTAR/CSTAR/SFMASK + KernelGsBase 를 BSP 에 설치.
    // RSP0 는 부트 스택 최상단(boot_stack_top) 으로 설정 — 인터럽트가 사용자
    // 모드에서 발생하면 자동으로 본 RSP 가 적재됨. syscall stub 은 GS-relative
    // 로 동일 값을 사용함.
    unsafe {
        let (_, kstack_top) = stack::boot_stack_range();
        // 16-byte 정렬 — System V x86_64 ABI 요구사항
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
    // 채운 뒤 진입시켰으므로 _kernel_start 는 펌웨어-중립 참조만 소비함 (신규 파싱 0)
    let memory_map = &boot_info.memory_map;
    unsafe {
        vga::println(
            b"[iso-light-k0] BootInfo Memory Map Consumed.",
            vga::Color::Green,
        );
    }
    // kaslr_offset 은 mb2 어댑터(_boot_adapter_mb2)가 parse_kaslr_offset 로 배선함
    // 태그 부재 시 0(미제공) -> None 부트로더가 KASLR 태그 삽입 시에만 Some
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
        // x86 관례: 하위 1 MiB(BIOS 데이터·VGA 버퍼·BIOS ROM)는
        // 커널 페이지 테이블 프레임으로 절대 사용하지 않음
        allocator::mark_used(0, 0x100000);

        //
        // (b) 커널 자신의 물리 영역 보호
        //
        // GRUB의 Multiboot2 메모리 맵은 커널이 로드된 영역(0x100000~)을
        // Usable로 표시하는 경우가 있음. 이 경우 alloc_frame()이 boot_pml4
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
        // 원본 mb2 info 영역은 더 이상 참조되지 않는다. 펌웨어-중립 _kernel_start
        // 는 mb2_addr 을 보유하지 않으며 죽은 핸드오프 영역의 별도 예약은 불필요함

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
    // 8. 직접 선형 매핑 구축
    //
    // SAFETY: 부팅 초기 단일 코어, KERNEL_ADDR_SPACE 단독 접근
    let kernel_space = unsafe { &mut *(&raw mut KERNEL_ADDR_SPACE) };
    let _ = mmu_init.build_linear_map(kernel_space, memory_map.highest_addr());

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
    // 섹션별 W^X 권한:
    //   .text    -> PRESENT                          (R+X, 쓰기 금지)
    //   .rodata  -> PRESENT | NO_EXECUTE             (R, 쓰기/실행 금지)
    //   .data    -> PRESENT | WRITABLE | NO_EXECUTE  (RW, 실행 금지)
    //   .bss     -> PRESENT | WRITABLE | NO_EXECUTE  (RW, 실행 금지)
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
        // 스택 오버플로 시 하드웨어 수준의 #PF를 유발함 (-> IST4 #PF 핸들러)
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
    // activate() 이후에는 VGA 버퍼 접근을 direct linear map 주소로 전환해야 함
    // vga::update_base(vga_virt)는 activate() 직후에 호출해야 하는 이유는,
    // update_base()가 VGA_BASE = PHYS_MAP_OFFSET + 0xB8000 으로 변경하면 이후의
    // vga::print*() 호출이 KERNEL_ADDR_SPACE의 PML4[256] 범위를 참조하기 때문임
    // 그런데 현재 활성 페이지 테이블은 boot_stub의 PML4[0/511]뿐이므로
    // PML4[256](direct linear map)은 미매핑 상태이며 접근 시 #PF 로 CPU hang 발생
    //
    // 현재는 부트 페이지 테이블 identity map(0xB8000)으로 VGA 를 계속 사용함
    // TODO: activate() 구현 시 아래 주석 해제
    let _vga_virt = unsafe { mmu_init.phys_to_virt_mut::<u16>(0xB8000) };
    // unsafe { vga::update_base(_vga_virt); }  <- activate() 직후에 활성화

    unsafe {
        vga::println(
            b"[iso-light-k0] VGA: linear addr computed (pending activate()).",
            vga::Color::Green,
        );
    }

    //
    // 11. 커널 주소 공간 활성화 (CR3 재로드)
    //
    // TODO: 현재 커널이 0x100000 (물리=가상)에 링크됨
    //       activate() 이후 새 PML4에서 0x100000이 미매핑되면 즉시 #PF 발생
    //       해결 방법 (택 1):
    //         A) 링커 스크립트로 고반치 커널 재배치 후 activate() 활성화
    //         B) 새 PML4에 0x100000 identity map 추가 후 activate()
    //
    //       현재: boot_stub의 4 GiB identity map을 유지하며 커널 실행
    //       boot_stub의 페이지 테이블은 `.bss`에 위치하며 계속 유효함
    //
    // SAFETY: 선형 매핑과 커널 PML4[256..511] 매핑 완료 이후 호출해야 함
    // unsafe { mmu_init.activate(kernel_space); }

    //
    // 12. Capability DRBG 초기화 (HW 엔트로피 기반 Hash-DRBG)
    //
    // RDSEED / RDRAND 로 수집한 하드웨어 엔트로피로 NIST SP 800-90A Rev.1
    // HashDRBGSHA256 을 인스턴스화함. 이후 Capability 토큰 생성은 모두
    // 이 DRBG 를 통해 이루어짐 (구 XOR-shift PRNG 는 완전히 제거됨)
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

        // (3) timer frequency line emit ROADMAP SC 7 2-source 구분 Pitfall 12 None 처리
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

        // (4) entropy-degraded-ok build marker Red ALERT 식별 D-03
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

                // (5) ENTROPY_SOURCES_AVAILABLE=N marker Pitfall 5 visibility
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
                // H5/M12 엔트로피 quorum 부재는 무조건 부팅 중단 fail-closed
                // 이후 BOOT_CHALLENGE 와 capability 토큰이 전부 0 이 되는 상태로 진행 금지
                panic!("entropy quorum failure");
            }
        }
    }

    // Phase 5 ENROLL D-01 D-09 부팅 시 1 회 신뢰 루트 dual-path 초기화 + BOOT_CHALLENGE 생성
    // capability::init_prng 직후 + ipc::init 직전 위치 BOOT_CHALLENGE 생성은 CAP_DRBG 만 의존
    // SAFETY 단일 코어 부팅 초기 capability::init_prng 완료 가정
    unsafe {
        hsm_attest::init_trust_root();
        vga::println(
            b"[iso-light-k0] Trust Root Init Done. (ML-DSA-44 1312B + BOOT_CHALLENGE 32B)",
            vga::Color::Green,
        );
    }

    // Phase 6 GAP D-02 D-06 부팅 시 1 회 NETWORK_ATTACH + AUDIT_READ cap mint (양 프로필 공통 + cfg)
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

    // Phase 1: HsmRegistry 정적 인스턴스는 `const fn new()` 로 부팅 instruction 0 시점부터
    // 온라인 — 별도 init 호출 불필요. VGA 마커는 BSS 배치 + alloc=0 보장을 가시화.
    // SAFETY: VGA MMIO 단일 코어 부팅 시점 접근 — 기존 println 호출 규약과 동일.
    unsafe {
        vga::println(
            b"[iso-light-k0] HsmRegistry static online (8 slots, alloc=0)",
            vga::Color::Green,
        );
    }

    //
    // 14. 부트 시점 Crypto Service 라운드트립 스모크 테스트
    //
    // 디버그 빌드에서만 수행. EP_CRYPTO Capability 를 발급한 뒤
    //   ipc_call(HashReq, BLAKE3, "iso-light-k0")
    // 흐름이 ipc_call -> crypto_service::dispatch -> ipc_reply 까지 동기적으로
    // 완결되는지 확인하여, DRBG·IPC·Crypto Service 와이어링이 모두 정상임을
    // 실측한다. 결과 페이로드의 첫 두 바이트(`algo` 에코, `key_len`)를
    // 검사하여 성공/실패를 판정함
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    unsafe {
        crypto_smoke_test();
    }

    //
    // 14.5. 부트 시점 TLS 1.3 PSK 핸드셰이크 스모크 테스트
    //
    // 디버그 빌드에서만 수행. SoftKeystore 에 임시 PSK 를 등록하고 in-kernel
    // 루프백으로 PSK-PQ-Hybrid (X25519+ML-KEM-768) -> Classical (X25519) 두
    // 정책에 대해 각각 핸드셰이크 + AEAD 라운드트립을 검증. 종료 후 키저장소
    // 와 커넥션 풀을 모두 zeroize 함
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    unsafe {
        tls_smoke_test();
    }

    //
    // 14.7. 부트 시점 HsmRegistry 라운드트립 스모크 테스트 (Phase 1)
    //
    // 디버그 빌드에서만 수행. attach -> is_valid_for -> detach -> zeroize 사이클을
    // in-kernel 경로로 검증하고 qemu-test.sh 가 기대하는 마일스톤 문자열을 출력.
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: capability::init_prng / ipc::init / HsmRegistry static 모두 온라인. 단일 코어.
    unsafe {
        hsm_registry_smoke_test();
    }

    //
    // 14.8. 부트 시점 Phase 2 BusDriver 라운드트립 스모크 테스트
    //
    // SoftwareBus 루프백 echo (write -> read) + ct_eq 일치 + detach 후 raw bytes==0 (T-02-03).
    // 성공 시 qemu-test.sh 의 BUS_PHASE2_OK 마커 게이트를 통과시킴 (additive — Phase 1 마커 보존).
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: Phase 1 smoke 완료 직후 — REGISTRY 비어 있고 BSP 단일 코어 동일.
    unsafe {
        bus_phase2_smoke_test();
    }

    //
    // 14.9. 부트 시점 Phase 3 In-Kernel Inter-HSM Channel 스모크 테스트
    //
    // Blake3 src → AesGcm dst relay + ciphertext in-kernel 재계산 동치성
    // 성공 시 qemu-test.sh 의 CHAN_PHASE3_OK 마커 게이트 통과 (Phase 1/2 마커 보존)
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: Phase 2 smoke 완료 후 detach cascade 가 REGISTRY 를 비웠음
    unsafe {
        chan_phase3_smoke_test();
    }

    //
    // 14.10. 부트 시점 Phase 5 Attestation Gate 2-leg 스모크 테스트  feature smoke 한정
    //
    // Leg 1 valid sig 흐름 attach 성공  Leg 2 mutated sig 흐름 reject + 슬롯 변동 0
    // 성공 시 qemu-test.sh ATTEST_PHASE5_OK 마커 게이트 통과 closed 프로필 부재
    #[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
    // SAFETY Phase 3 smoke 완료 후 detach cascade 가 REGISTRY 를 비웠음 hsm_attest::init_trust_root 가 BSS 채움
    unsafe {
        attest_phase5_smoke_test();
        // Phase 5.1 D-04 wire AttestSubmit / Status round-trip smoke
        // Phase 5 marker 직후 호출  두 marker 모두 emit (Pitfall 6 substring 충돌 0)
        attest_phase5_1_wire_smoke_test();
        // Phase 6 GAP D-PHASE6 air-gap dual gate + sys_hsm_status + gap_self_check 4-line marker emit
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

    // Phase 6 GAP D-07 Layer 2 self-check 모든 init + syscall::install + dispatcher arm 등록 직후
    // 호출 위치 syscall::install (L226) 후 + try_spawn_user 진입 전 정확한 fail-stop 경계
    // SAFETY 모든 init_* + STAR/LSTAR MSR 등록 완료 Ring 3 진입 이전 단일 코어
    unsafe {
        air_gap::gap_self_check();
        vga::println(b"[iso-light-k0] gap_self_check OK.", vga::Color::Green);
    }

    //
    // 16. Ring 3 사용자 프로세스 spawn (debug 빌드 + 유효 ELF 한정)
    //
    // 우선 lumen 와이어 호환 검증 프로그램(iso-user-lumen) 을 시도. ELF 가
    // placeholder(4 바이트) 또는 빌드되지 않은 경우 elf::parse 가 거절하므로
    // 그 다음 iso-user-hello 를 시도. 둘 다 실패하면 커널 메인 루프 진입.
    //
    // enter_ring3 는 ! 반환 — 성공 시 본 함수는 결코 메인 루프에 도달하지 않음.
    // 사용자 프로세스가 sys_exit 하면 syscall::sys_exit 가 cli + hlt 무한
    // 루프로 정지함.
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    // SAFETY: 위 단계가 모두 완료된 후. activate() 는 호출하지 않으며
    //         enter_ring3 가 사용자 PML4 로 cr3 전환을 직접 수행함.
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

/// 임베드된 사용자 ELF 를 spawn 하고 성공 시 Ring 3 으로 진입함.
///
/// `elf` 가 placeholder (4-byte ELF magic) 이거나 손상된 경우 elf::parse 가
/// 거절하며, 본 함수는 단순히 반환되어 호출자가 다음 ELF 를 시도하거나
/// 메인 루프로 진입하도록 함.
///
/// # Safety
/// 부팅 단계 16 의 모든 사전 조건이 충족된 상태에서만 호출.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn try_spawn_user(elf: &[u8], label: &[u8], kernel_space: &AddressSpace) {
    // 4-byte placeholder 는 ELF 헤더 64 바이트 미만이므로 parse 가 Truncated 로 거절.
    // 그러나 길이 컷오프로 빠르게 판별하여 vga 메시지 노이즈를 줄임.
    if elf.len() < 64 {
        return;
    }

    // SAFETY: 부팅 단계 16 의 사전조건. spawn_elf 내부에서 ELF 검증 + 페이지 매핑.
    match unsafe { process::spawn_elf(kernel_space, elf) } {
        Ok(pid) => {
            // SAFETY: VGA 직접 접근은 debug 빌드 한정 단일 코어 부팅 경로
            unsafe {
                vga::print(b"[iso-light-k0] spawned ", vga::Color::LightGray);
                vga::print(label, vga::Color::White);
                vga::println(b", entering Ring 3...", vga::Color::Green);
            }
            // SAFETY: 본 함수에서 spawn 직후 즉시 진입 — 다른 코드 끼지 않음.
            //         enter_ring3 는 ! 반환.
            unsafe {
                process::enter_ring3(pid);
            }
        }
        Err(_) => {
            // SAFETY: VGA 직접 접근은 debug 빌드 한정 단일 코어 부팅 경로
            unsafe {
                vga::print(b"[iso-light-k0] spawn rejected ", vga::Color::DarkGray);
                vga::println(label, vga::Color::DarkGray);
            }
        }
    }
}

/// EP_CRYPTO 라운드트립 검증용 스모크 테스트 (debug 전용).
///
/// CryptoPayload 레이아웃을 in-place 로 작성하여 BLAKE3 해시 요청을 한 번
/// 수행하고, 응답 페이로드의 형식이 `crypto_service::write_ok_reply` 가 기록한
/// 패턴(algo 에코 · data_len ≥ 32 · 비-에러 응답 타입)과 일치하는지 확인한다.
///
/// # Safety
/// `init_prng()` · `ipc::init()` 완료 후 단일 코어에서만 호출.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn crypto_smoke_test() {
    use ipc::{CryptoAlgo, CryptoPayload, MessageType};

    // 1. Capability 발급
    // SAFETY: init_prng / ipc::init 완료 가정
    let cap = match unsafe { ipc::issue_crypto_capability() } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
            unsafe {
                vga::println(
                    b"[iso-light-k0] crypto smoke: capability issue FAILED",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // 2. CryptoPayload 작성: BLAKE3("iso-light-k0")
    let mut req = CryptoPayload::zeroed();
    req.algo = CryptoAlgo::Blake3 as u8;
    let msg = b"iso-light-k0";
    req.data_len = msg.len() as u16;
    req.data[..msg.len()].copy_from_slice(msg);

    // CryptoPayload 자체를 바이트열로 직렬화하여 ipc_call 페이로드에 주입
    let req_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&req as *const CryptoPayload) as *const u8,
            core::mem::size_of::<CryptoPayload>(),
        )
    };

    // 3. 동기 IPC 호출
    // SAFETY: 단일 코어 부팅 초기, IPC 레지스트리 초기화 완료
    let reply = match unsafe { ipc::ipc_call(&cap, MessageType::HashReq, req_bytes) } {
        Ok(m) => m,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
            unsafe {
                vga::println(
                    b"[iso-light-k0] crypto smoke: ipc_call FAILED",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // 4. 응답 형식 검증: HashResp · algo 에코 · 32바이트 다이제스트
    let payload = reply.payload_bytes();
    let ok = reply.header.msg_type == MessageType::HashResp
        && payload.len() >= ipc::CRYPTO_DATA_OFFSET
        && payload[0] == CryptoAlgo::Blake3 as u8
        && u16::from_le_bytes([payload[4], payload[5]]) as usize == 32;

    // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
    if ok {
        unsafe {
            vga::println(
                b"[iso-light-k0] crypto smoke: BLAKE3 round-trip OK",
                vga::Color::Green,
            );
        }
    } else {
        unsafe {
            vga::println(
                b"[iso-light-k0] crypto smoke: response shape MISMATCH",
                vga::Color::Red,
            );
        }
    }
    // reply 의 Secret<RawPayload> 는 Drop 시 평문 자동 소거
}

/// TLS 1.3 PSK 라운드트립 스모크 테스트 — 디버그 빌드 전용.
///
/// 절차:
///   1. SoftKeystore 에 32B 임시 PSK 를 등록.
///   2. PSK-PQ-Hybrid (Closed 프로필) 로 in-kernel 루프백 핸드셰이크.
///   3. application_data 평문 라운드트립 (양방향 AEAD 검증).
///   4. PSK-Classical (X25519 단독) 로 동일 검증 (레거시 호환 경로).
///   5. 모든 슬롯 + 키 자료 zeroize.
///
/// 실패 시 VGA 로 빨간 메시지 출력. 정상 시 녹색 메시지 출력.
///
/// # Safety
/// `init_prng()` · `ipc::init()` 완료 후 단일 코어에서만 호출.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn tls_smoke_test() {
    use crate::hsm::PskId;
    use crate::tls::{CipherSuite, KexPolicy, Profile};

    // SAFETY: identity-mapped VGA 버퍼(0xB8000), 단일 코어
    unsafe {
        vga::println(b"[tls] === TLS 1.3 PSK smoke test ===", vga::Color::Green);
    }

    //
    // 1. PSK 등록
    //
    let psk_id = PskId::from_bytes(*b"iso-k0-tls-psk01");
    let psk_material = [0xA5u8; 32];
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: keystore init...",
            vga::Color::Green,
        );
    }
    // SAFETY: 단일 코어 부팅 초기
    let ks = unsafe { crate::keystore::global_mut() };
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: keystore ready",
            vga::Color::Green,
        );
    }
    if ks.provision(psk_id, &psk_material).is_err() {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: PSK provisioning FAILED",
                vga::Color::Red,
            );
        }
        return;
    }

    // 핸드셰이크는 SoftKeystore 가 HsmDriver 를 제공
    // SAFETY: 이미 동일 단일 코어 가정
    let ks_ref = unsafe { crate::keystore::global() };

    //
    // 2. PSK-Classical (X25519 단독, 레거시 호환) <- 먼저 실행
    //
    // 본 테스트는 ML-KEM 을 거치지 않아 TCG 환경에서도 빠르게 완결되어야 함
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: Classical handshake...",
            vga::Color::Green,
        );
    }
    // 본 스모크 테스트는 ChaCha20-Poly1305 슈트로 검증
    // AES-256-GCM 슈트도 동일 키 스케줄을 거치므로 코드 경로는 검증되나,
    // SHA-NI / AES-NI 미지원 TCG 환경에서는 GHash u128 GF 곱이 매우 느려
    // 부팅 스모크 시간 한도 내 완료가 어려움. KVM 환경에서는 정상 동작
    let classical = unsafe {
        tls::handshake::run_loopback(
            ks_ref,
            Profile::Closed,
            KexPolicy::Classical,
            CipherSuite::ChaCha20Poly1305Sha256,
            &psk_id,
        )
    };
    let (c2, s2) = match classical {
        Ok(p) => p,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] tls smoke: classical handshake FAILED",
                    vga::Color::Red,
                );
            }
            let ks2 = unsafe { crate::keystore::global_mut() };
            ks2.wipe_all();
            return;
        }
    };
    let msg = b"legacy-compat hello";
    let mut buf = [0u8; 32];
    let r3 = tls::handshake::loopback_send_recv(c2, s2, msg, &mut buf);
    let ok3 = matches!(r3, Ok(n) if n == msg.len() && &buf[..n] == msg);
    let _ = tls::close(c2);
    let _ = tls::close(s2);

    if ok3 {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: Classical (X25519) OK",
                vga::Color::Green,
            );
        }
    } else {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: Classical AEAD round-trip FAILED",
                vga::Color::Red,
            );
        }
    }

    //
    // 3. PSK-PQ-Hybrid 시나리오
    //
    // ML-KEM-768 keygen + encaps + decaps 는 SHAKE 다중 호출을 포함하여
    // SHA-NI 미지원 TCG 환경에서 수십 초 단위로 느릴 수 있음
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: PQ-Hybrid handshake (slow in TCG)...",
            vga::Color::Green,
        );
    }
    let hybrid = unsafe {
        tls::handshake::run_loopback(
            ks_ref,
            Profile::Closed,
            KexPolicy::Hybrid,
            CipherSuite::ChaCha20Poly1305Sha256,
            &psk_id,
        )
    };
    let (c_h, s_h) = match hybrid {
        Ok(p) => p,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] tls smoke: hybrid handshake FAILED",
                    vga::Color::Red,
                );
            }
            let ks2 = unsafe { crate::keystore::global_mut() };
            ks2.wipe_all();
            return;
        }
    };

    let msg_c2s = b"closed-net hello (c->s)";
    let mut recv_buf = [0u8; 64];
    let r1 = tls::handshake::loopback_send_recv(c_h, s_h, msg_c2s, &mut recv_buf);
    let ok_c2s = matches!(r1, Ok(n) if n == msg_c2s.len() && &recv_buf[..n] == msg_c2s);

    let msg_s2c = b"closed-net hello (s->c)";
    let mut recv_buf2 = [0u8; 64];
    let r2 = tls::handshake::loopback_send_recv(s_h, c_h, msg_s2c, &mut recv_buf2);
    let ok_s2c = matches!(r2, Ok(n) if n == msg_s2c.len() && &recv_buf2[..n] == msg_s2c);

    let _ = tls::close(c_h);
    let _ = tls::close(s_h);

    if ok_c2s && ok_s2c {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: PQ-Hybrid (X25519+MLKEM768) OK",
                vga::Color::Green,
            );
        }
    } else {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: PQ-Hybrid AEAD round-trip FAILED",
                vga::Color::Red,
            );
        }
    }

    //
    // 4. 키저장소 + 풀 강제 소거
    //
    let ks2 = unsafe { crate::keystore::global_mut() };
    ks2.wipe_all();
    unsafe {
        crate::tls::wipe_all();
        vga::println(
            b"[iso-light-k0] tls smoke: keystore + pool wiped",
            vga::Color::Green,
        );
    }
}

#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn hsm_registry_smoke_test() {
    use crate::bus::BusKind;
    use hsm_registry::{
        HSM_MAX_SLOTS, HsmCapability, HsmRights, HsmSlotIdx, HsmSlotInfo, attach_kernel_side,
        with_registry, with_registry_mut,
    };

    // Step 1: 초기 상태 확인 — attached_count == 0
    // SAFETY: BSP 단일 코어 부팅 시퀀스 + REGISTRY 정적 인스턴스 온라인
    let initial_count = unsafe { with_registry(|r| r.attached_count()) };
    if initial_count != 0 {
        // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (initial count != 0)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 2: attach -> capability 발급 (실제 Hash-DRBG-SHA256 토큰)
    // SAFETY: capability::init_prng() 완료, BSP 단일 코어
    let cap = match unsafe {
        attach_kernel_side(BusKind::Software, &[], HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE)
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (attach error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // Step 3: is_valid_for 양성/음성 (CT 단일 분기)
    if !cap.is_valid_for(cap.slot, HsmRights::USE) {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (valid cap rejected)",
                vga::Color::Red,
            );
        }
        return;
    }
    let wrong_slot = HsmSlotIdx(if cap.slot.0 == 0 { 1 } else { 0 });
    if cap.is_valid_for(wrong_slot, HsmRights::USE) {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (wrong-slot accepted)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 4: enumerate (cap 보유) — 정확히 1개 슬롯 노출
    let mut info_buf: [HsmSlotInfo; HSM_MAX_SLOTS] = [HsmSlotInfo::empty(); HSM_MAX_SLOTS];
    // SAFETY: BSP 단일 코어 + REGISTRY 정적 인스턴스 온라인
    let written = unsafe { with_registry(|r| r.enumerate(&mut info_buf)) };
    if written != 1 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (enumerate count != 1)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 5: detach 거부 경로 정직 검증 (post-attach CAP-02 정신)
    //   - 위조된 cap (token=0xDEAD_BEEF_DEAD_BEEF, 동일 slot) 으로 detach 호출 -> 실패 기대
    //   - 슬롯 상태는 Attached 유지 (변경 없음)
    let forged = HsmCapability::with_forged_token(0xDEAD_BEEF_DEAD_BEEF, cap.slot, HsmRights::REVOKE);
    // SAFETY: BSP 단일 코어; detach 진입 가능 시점
    let forged_result = unsafe { with_registry_mut(|r| r.detach(&forged, HsmRights::REVOKE)) };
    if forged_result.is_ok() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (forged cap accepted by detach)",
                vga::Color::Red,
            );
        }
        return;
    }
    // SAFETY: BSP 단일 코어; with_registry 의 invariant 동일
    let still_attached = unsafe { with_registry(|r| !r.slot_is_empty(cap.slot)) };
    if !still_attached {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (slot changed despite forged-cap rejection)",
                vga::Color::Red,
            );
        }
        return;
    }
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] HSM_DETACH_NO_CAP_DENIED marker (forged cap rejected, slot unchanged)",
            vga::Color::Green,
        );
    }

    // Step 6: 합법 cap 으로 detach -> 슬롯 Empty 복귀 + zeroize 트리거
    // SAFETY: BSP 단일 코어
    let detach_result = unsafe { with_registry_mut(|r| r.detach(&cap, HsmRights::REVOKE)) };
    if detach_result.is_err() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (legitimate detach error)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 7: 슬롯 Empty + attached_count == 0 검증 (zeroize 효과 가시화)
    // SAFETY: BSP 단일 코어
    let is_empty = unsafe { with_registry(|r| r.slot_is_empty(cap.slot)) };
    // SAFETY: BSP 단일 코어
    let post_count = unsafe { with_registry(|r| r.attached_count()) };
    if !is_empty || post_count != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (slot not zeroized post-detach)",
                vga::Color::Red,
            );
        }
        return;
    }

    // 성공 마일스톤
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] HSM_ATTACH_DETACH_ROUNDTRIP_OK marker",
            vga::Color::Green,
        );
        vga::println(
            b"[iso-light-k0] HsmRegistry smoke: attach -> verify -> detach -> zeroize OK",
            vga::Color::Green,
        );
    }
}

#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn bus_phase2_smoke_test() {
    use crate::bus::{BusDriver, BusInstance, BusKind};
    use hsm_registry::{HsmRights, attach_kernel_side, with_registry, with_registry_mut};

    // Step 1+2: SoftHSM bus_kind 로 attach -> capability 발급
    // SAFETY: capability::init_prng() 완료, BSP 단일 코어
    let cap = match unsafe {
        attach_kernel_side(
            BusKind::Software,
            &[],
            HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (attach error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let slot_idx = cap.slot.0 as usize;

    // 테스트 페이로드 (16 bytes). 스택-로컬, alloc 없음.
    let pattern: [u8; 16] = [
        0xA5, 0x5A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    ];

    // Step 3: SoftwareBus 에 write
    // SAFETY: BSP 단일 코어; with_registry_mut 의 invariant 동일
    let write_result: Result<usize, crate::bus::BusError> = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => bus.write(&pattern),
            None => Err(crate::bus::BusError::NotOpen),
        })
    };
    let written = match write_result {
        Ok(n) => n,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (bus.write error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    if written != pattern.len() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (write short)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 4: SoftwareBus 에서 read-back (루프백 echo)
    let mut readback: [u8; 16] = [0u8; 16];
    // SAFETY: BSP 단일 코어
    let read_result: Result<usize, crate::bus::BusError> = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => bus.read(&mut readback),
            None => Err(crate::bus::BusError::NotOpen),
        })
    };
    let read_n = match read_result {
        Ok(n) => n,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (bus.read error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    if read_n != pattern.len() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (read short)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 5: 루프백 동치성 검증 — 16바이트 XOR-OR fold (early-return 없는 단일 분기).
    // CtEqOps 가 [u8] 슬라이스에 미구현 (스칼라 + SecureBuffer 만 지원) 이므로 동일 의미의
    // O(N) OR-누산 패턴을 직접 작성한다 — 데이터-의존 분기는 발생하지 않음.
    let mut diff: u8 = 0;
    let mut i: usize = 0;
    while i < pattern.len() {
        diff |= pattern[i] ^ readback[i];
        i += 1;
    }
    if diff != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (loopback ct_eq mismatch)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 6: 합법 cap detach -> D-17 close-before-zeroize cascade 트리거
    // SAFETY: BSP 단일 코어
    let detach_result = unsafe { with_registry_mut(|r| r.detach(&cap, HsmRights::REVOKE)) };
    if detach_result.is_err() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (legitimate detach error)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 7: T-02-03 observability — detach 후 slot.bus 의 raw 96바이트 가 전부 0 인지 검사.
    // SoftwareBus::zeroize 가 payload 를 비우고 BusInstance::zeroize 가 *self = Self::Empty
    // (discriminant 0) 로 reset 한 결과를 가시화.
    // SAFETY: BSP 단일 코어; slot_bus_mut 는 idx<HSM_MAX_SLOTS 일 때 항상 Some 반환.
    let raw_all_zero: bool = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => {
                let p: *const u8 = bus as *const BusInstance as *const u8;
                let n: usize = core::mem::size_of::<BusInstance>();
                // SAFETY: bus 는 유효한 &mut BusInstance — 동일 메모리 영역을 u8 슬라이스로 재해석.
                let slice = core::slice::from_raw_parts(p, n);
                slice.iter().all(|&b| b == 0)
            }
            None => false,
        })
    };
    if !raw_all_zero {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (slot.bus raw bytes nonzero after detach)",
                vga::Color::Red,
            );
        }
        return;
    }

    // 추가 보강: registry 카운트 0 + 슬롯 Empty (Phase 1 cascade 와 동일)
    // SAFETY: BSP 단일 코어
    let post_count = unsafe { with_registry(|r| r.attached_count()) };
    if post_count != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (attached_count != 0 post-detach)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 8: 성공 마커 (qemu-test.sh 가 grep 으로 게이트)
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] BUS_PHASE2_OK marker (SoftwareBus loopback + detach cascade)",
            vga::Color::Green,
        );
    }
}

// chan_phase3_smoke_test  Phase 3 in-kernel relay 라운드트립 검증  H4 모델 (D-22)  marker CHAN_PHASE3_OK
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn chan_phase3_smoke_test() {
    use crate::bus::{BusDriver, BusInstance, BusKind, SoftHsmRole};
    use aes::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
    use blake::{BLAKE3_OUT_LEN, Blake3};
    use hsm_registry::{HsmRights, attach_kernel_side, with_registry, with_registry_mut, with_relay_buf};

    // (1) Blake3 src 슬롯 attach  rights = USE | REVOKE | RELAY_SRC
    // SAFETY: capability::init_prng / REGISTRY static 모두 온라인  BSP 단일 코어
    let cap_src = match unsafe {
        attach_kernel_side(
            BusKind::Software,
            &[SoftHsmRole::Blake3 as u8],
            HsmRights::USE | HsmRights::REVOKE | HsmRights::RELAY_SRC,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (attach Blake3 src)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let src_slot = cap_src.slot.0 as usize;

    // (2) AesGcm dst 슬롯 attach  rights = USE | REVOKE | RELAY_DST
    // SAFETY: Phase 2 와 동일 invariant
    let cap_dst = match unsafe {
        attach_kernel_side(
            BusKind::Software,
            &[SoftHsmRole::AesGcm as u8],
            HsmRights::USE | HsmRights::REVOKE | HsmRights::RELAY_DST,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (attach AesGcm dst)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let dst_slot = cap_dst.slot.0 as usize;

    // (3) src.write(b"PHASE3_INPUT")  Role::Blake3 → src.ring 에 32B digest 저장
    let write_input: &[u8; 12] = b"PHASE3_INPUT";
    // SAFETY: BSP 단일 코어; with_registry_mut 의 invariant 동일
    let write_ok = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(src_slot) {
            Some(bus) => bus.write(write_input).is_ok(),
            None => false,
        })
    };
    if !write_ok {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (src.write)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (4) kernel-side relay  with_relay_buf 안에서 src.read 32B → dst.write 32B
    // D-22 H4  syscall ABI 우회  with_relay_buf direct 진입  RELAY_BUF entry+exit zeroize 보장 (D-14)
    // SAFETY: BSP single-core; with_relay_buf + with_registry_mut 는 disjoint static borrow
    let relay_ok = unsafe {
        with_relay_buf(|buf| {
            let read_n = with_registry_mut(|r| match r.slot_bus_mut(src_slot) {
                Some(bus) => bus.read(&mut buf[..BLAKE3_OUT_LEN]).unwrap_or(0),
                None => 0,
            });
            if read_n != BLAKE3_OUT_LEN {
                return false;
            }
            let write_n = with_registry_mut(|r| match r.slot_bus_mut(dst_slot) {
                Some(bus) => bus.write(&buf[..BLAKE3_OUT_LEN]).unwrap_or(0),
                None => 0,
            });
            // dst.write 의 AesGcm arm 은 32B input + 28B overhead = 60B 반환
            write_n == BLAKE3_OUT_LEN + GCM_NONCE_SIZE + GCM_TAG_SIZE
        })
    };
    if !relay_ok {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (relay)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (5) in-kernel 재계산 + slice ct_eq  dst.ring[..60] == AES256GCM(key, nonce_1, BLAKE3(input))
    // RESEARCH §Risk #6  debug_aes_state / debug_ring 는 #[cfg(debug_assertions)] 노출  release 빌드 부재
    // 5a — BLAKE3(b"PHASE3_INPUT") 직접 호출
    let mut hasher = Blake3::new();
    hasher.update(write_input);
    let digest = match hasher.finalize() {
        Ok(d) => d,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (blake3 recompute)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let mut blake3_out = [0u8; BLAKE3_OUT_LEN];
    blake3_out.copy_from_slice(&digest.as_slice()[..BLAKE3_OUT_LEN]);

    // 5b — dst 의 fresh key + counter==1 직접 노출 + expected ciphertext 합성 + dst.ring 와 비교
    let mut expected: [u8; 60] = [0u8; 60]; // nonce(12) || ct(32) || tag(16)
    let mut got: [u8; 60] = [0u8; 60];
    // SAFETY: BSP 단일 코어; debug_assertions 만 진입 가능
    let mismatch: u8 = unsafe {
        with_registry_mut(|r| -> u8 {
            let bus = match r.slot_bus_mut(dst_slot) {
                Some(b) => b,
                None => return 1,
            };
            // BusInstance::Software 케이스 직접 매치  Phase 2 BUS-04 enum-dispatch 일관
            let sw = match bus {
                BusInstance::Software(sw) => sw,
                _ => return 1,
            };
            let state = match sw.debug_aes_state() {
                Some(s) => s,
                None => return 1,
            };
            // nonce 직렬화 (counter == 1; D-12)
            let mut nonce = [0u8; GCM_NONCE_SIZE];
            nonce[..8].copy_from_slice(&state.nonce_counter.to_le_bytes());
            // expected: encrypt(key, nonce, blake3_out)
            let cipher = AES256GCM::new(state.key.expose());
            let mut tag = [0u8; GCM_TAG_SIZE];
            expected[..GCM_NONCE_SIZE].copy_from_slice(&nonce);
            cipher.encrypt(
                &nonce,
                &[],
                &blake3_out,
                &mut expected[GCM_NONCE_SIZE..GCM_NONCE_SIZE + BLAKE3_OUT_LEN],
                &mut tag,
            );
            expected[GCM_NONCE_SIZE + BLAKE3_OUT_LEN..].copy_from_slice(&tag);
            // got: dst.ring[..60]
            got.copy_from_slice(&sw.debug_ring()[..60]);
            // slice CT-eq via XOR-OR fold (Phase 2 main.rs:1149-1157 패턴, RESEARCH §Risk #8)
            let mut diff: u8 = 0;
            let mut i = 0;
            while i < 60 {
                diff |= expected[i] ^ got[i];
                i += 1;
            }
            diff
        })
    };
    if mismatch != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (ciphertext mismatch)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (6) 성공 마커  qemu-test.sh CHAN_PHASE3_OK 게이트
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] CHAN_PHASE3_OK marker (Blake3 src -> AesGcm dst relay)",
            vga::Color::Green,
        );
    }

    // (7) detach 두 슬롯  registry 정리 후 다음 부팅 invariant 보존
    // SAFETY: BSP 단일 코어
    let _ = unsafe { with_registry_mut(|r| r.detach(&cap_src, HsmRights::REVOKE)) };
    let _ = unsafe { with_registry_mut(|r| r.detach(&cap_dst, HsmRights::REVOKE)) };
    let n_attached = unsafe { with_registry(|r| r.attached_count()) };
    if n_attached != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (detach cascade)",
                vga::Color::Red,
            );
        }
        return;
    }
}

//
// attest_phase5_smoke_test  Phase 5 attach with attestation gate 2-leg 검증  marker ATTEST_PHASE5_OK
//
// Leg 1 valid sig 흐름  dev sk 로 BLAKE3(pk||bus||BOOT_CHALLENGE) 서명 후
//                       attach_kernel_side_with_attest Ok(cap) 슬롯 1 개 부착
// Leg 2 mutated sig 흐름  sig[0] ^= 0xFF 후 동일 호출 Err(AttestFailed)
//                         attached_count 변동 0 RESEARCH 6.2 atomicity 회귀 가드
//
// 본 smoke 는 feature smoke 게이트 아래에서만 컴파일 closed 프로필 dev sk leak 0 보장
#[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
unsafe fn attest_phase5_smoke_test() {
    use crate::bus::BusKind;
    use blake::Blake3;
    use hsm_attest::{ACTIVE_TRUST_ROOT_PK, BOOT_CHALLENGE};
    use hsm_registry::{HsmRights, attach_kernel_side_with_attest, with_registry, with_registry_mut};
    use mldsa::MLDSA44;

    // Phase 5 D-02 dev sk 자료는 feature smoke 한정 include_bytes 로만 임베드
    // closed 프로필 빌드는 본 함수 자체가 cfg-out 되어 sk44 자료 leak 0
    const DEV_SK: &[u8; MLDSA44::SK_LEN] = include_bytes!("../keys/dev_trust_root.sk44");

    // (1) BOOT_CHALLENGE 와 ACTIVE_TRUST_ROOT_PK 스냅샷  init_trust_root 가 부팅 시 이미 채움
    // SAFETY BSP single-core 부팅 후 두 BSS static 의 단일 진입 read
    let pk: [u8; MLDSA44::PK_LEN] = unsafe { *(&raw const ACTIVE_TRUST_ROOT_PK) };
    let challenge: [u8; 32] = unsafe { *(&raw const BOOT_CHALLENGE) };

    // (2) Pre-image 재구성  hsm_attest 의 verify_attest body 와 byte-exact mirror
    // layout pk(1312) || bus_kind_octet(1) || BOOT_CHALLENGE(32) = 1345 옥텟
    let bus_kind = BusKind::Software;
    let mut pre = [0u8; MLDSA44::PK_LEN + 1 + 32];
    pre[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    pre[MLDSA44::PK_LEN] = bus_kind as u8;
    pre[MLDSA44::PK_LEN + 1..].copy_from_slice(&challenge);

    // (3) BLAKE3 digest  서명 평문은 32 옥텟 digest (D-07 amendment)
    let mut hasher = Blake3::new();
    hasher.update(&pre);
    let digest_buf = match hasher.finalize() {
        Ok(d) => d,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (blake3 digest)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&digest_buf.as_slice()[..32]);

    // (4) ML-DSA-44 sign  ctx b"ISO-K0-ENROLL-V1" 16 옥텟 D-08 도메인 분리 verify_attest 와 동일 ctx
    // rnd 인자는 결정적 smoke 회귀 일관성을 위해 고정 nonce [0xBB;32] 사용
    let rnd = [0xBB_u8; 32];
    let sig: [u8; MLDSA44::SIG_LEN] = match MLDSA44::sign(DEV_SK, &digest, b"ISO-K0-ENROLL-V1", &rnd) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (mldsa44 sign)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // (5) attest_payload 직렬화  pk(1312) || sig(2420) = 3732 옥텟 ATTEST_EXACT
    const ATTEST_LEN: usize = MLDSA44::PK_LEN + MLDSA44::SIG_LEN;
    let mut attest_payload = [0u8; ATTEST_LEN];
    attest_payload[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    attest_payload[MLDSA44::PK_LEN..].copy_from_slice(&sig);

    // (6) Leg 1 valid sig  attach 성공 Ok(cap) 슬롯 1 개 부착
    let baseline_attached = unsafe { with_registry(|r| r.attached_count()) };
    // SAFETY BSP single-core attach_kernel_side_with_attest 가 verify gate 활성
    let cap_leg1 = match unsafe {
        attach_kernel_side_with_attest(
            BusKind::Software,
            &[crate::bus::SoftHsmRole::Blake3 as u8],
            &attest_payload,
            HsmRights::USE | HsmRights::REVOKE,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 1 attach rejected)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let after_leg1_attached = unsafe { with_registry(|r| r.attached_count()) };
    if after_leg1_attached != baseline_attached + 1 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 1 slot count delta != 1)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (7) Leg 2 mutated sig  sig[0] ^= 0xFF 후 attach 실패 슬롯 변동 0 atomicity 회귀
    let mut tampered_payload = attest_payload;
    tampered_payload[MLDSA44::PK_LEN] ^= 0xFF;
    let before_leg2_attached = unsafe { with_registry(|r| r.attached_count()) };
    let leg2_result = unsafe {
        attach_kernel_side_with_attest(
            BusKind::Software,
            &[crate::bus::SoftHsmRole::Blake3 as u8],
            &tampered_payload,
            HsmRights::USE | HsmRights::REVOKE,
        )
    };
    if leg2_result.is_ok() {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 2 mutated sig accepted)",
                vga::Color::Red,
            );
        }
        return;
    }
    let after_leg2_attached = unsafe { with_registry(|r| r.attached_count()) };
    if after_leg2_attached != before_leg2_attached {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 2 slot count changed)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (8) 성공 마커  qemu-test.sh ATTEST_PHASE5_OK 게이트
    // SAFETY identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] ATTEST_PHASE5_OK marker (Leg 1 valid sig + Leg 2 mutated reject)",
            vga::Color::Green,
        );
    }

    // (9) Leg 1 슬롯 detach  registry 정리 다음 smoke 또는 Ring 3 spawn invariant 보존
    // SAFETY BSP 단일 코어
    let _ = unsafe { with_registry_mut(|r| r.detach(&cap_leg1, HsmRights::REVOKE)) };
}

//
// Phase 5.1 D-04 wire AttestSubmit fixture 정적 슬롯
//
// kernel 의 attest_phase5_1_wire_smoke_test 가 채우고
// lumen 의 SyscallNum AttestFixtureExport(13) 가 사용자 공간으로 복사
// feature smoke 한정 closed 빌드 BSS leak 0
//
// gate 정합  syscall variant / dispatch arm / handler 모두 #[cfg(feature = "smoke")]
//           smoke test 함수만 추가로 debug_assertions 게이트 release+smoke
//           빌드 시 fixture 는 BSS 슬롯으로 존재 (0 초기화), 채움 없음
#[used]
#[cfg(feature = "smoke")]
static mut WIRE_ATTEST_FIXTURE: [u8; 3733] = [0u8; 3733];

//
// attest_phase5_1_wire_smoke_test  Phase 5.1 wire AttestSubmit / Status round-trip 9-step
//                                  marker ATTEST_PHASE5_1_OK
//
// (1) BOOT_CHALLENGE 와 ACTIVE_TRUST_ROOT_PK 스냅샷 Phase 5 mirror
// (2) Pre-image (pk || bus_kind || challenge) 재구성 + BLAKE3 digest
// (3) ML-DSA-44 sign  ctx b"ISO-K0-ENROLL-V1"  rnd 결정적 [0xCC; 32]
// (4) wire AttestSubmit payload 3733 옥텟 조립 (pk || bus_kind || sig)
// (5) WIRE_ATTEST_FIXTURE 적재  lumen 의 sys_attest_fixture_export 수령 슬롯
// (6) Leg 1 valid  kernel-direct handle_attest_submit  resp status = Ok 응답 16B
// (7) Leg 2 mutated sig (sig 첫 옥텟 flip) handle_attest_submit  resp cmd 0xFFFF status 3
// (8) audit_ring delta == 2 후행 검증 (5 WireReattestOk + 6 WireReattestFail)
// (9) ATTEST_PHASE5_1_OK marker emit (Pitfall 6 substring 충돌 0)
#[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
unsafe fn attest_phase5_1_wire_smoke_test() {
    use crate::bus::{BusKind, WIRE_FRAME_MAX, handle_attest_submit};
    use blake::Blake3;
    use hsm_attest::{ACTIVE_TRUST_ROOT_PK, BOOT_CHALLENGE};
    use mldsa::MLDSA44;
    use zeroize::Zeroize;

    // dev sk 자료는 feature smoke 한정 include_bytes 로만 임베드  closed 빌드 leak 0
    const DEV_SK: &[u8; MLDSA44::SK_LEN] = include_bytes!("../keys/dev_trust_root.sk44");

    // (1) BOOT_CHALLENGE 와 ACTIVE_TRUST_ROOT_PK 스냅샷
    // SAFETY BSP single-core 부팅 후 두 BSS static 의 단일 진입 read
    let pk: [u8; MLDSA44::PK_LEN] = unsafe { *(&raw const ACTIVE_TRUST_ROOT_PK) };
    let challenge: [u8; 32] = unsafe { *(&raw const BOOT_CHALLENGE) };
    let bus_kind = BusKind::Software;

    // (2) Pre-image 재구성  hsm_attest verify_attest body 와 byte-exact mirror
    let mut pre = [0u8; MLDSA44::PK_LEN + 1 + 32];
    pre[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    pre[MLDSA44::PK_LEN] = bus_kind as u8;
    pre[MLDSA44::PK_LEN + 1..].copy_from_slice(&challenge);

    let mut hasher = Blake3::new();
    hasher.update(&pre);
    let digest_buf = match hasher.finalize() {
        Ok(d) => d,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (blake3 digest)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&digest_buf.as_slice()[..32]);

    // (3) ML-DSA-44 sign  ctx b"ISO-K0-ENROLL-V1" 16 옥텟 D-08 도메인 분리
    // rnd 인자 결정적 smoke 회귀 일관성 위해 고정 nonce [0xCC; 32] 사용 (Phase 5 0xBB 와 분리)
    let rnd = [0xCC_u8; 32];
    let sig: [u8; MLDSA44::SIG_LEN] = match MLDSA44::sign(DEV_SK, &digest, b"ISO-K0-ENROLL-V1", &rnd) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (mldsa44 sign)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // (4) wire AttestSubmit payload 3733 옥텟 조립 (pk(1312) || bus_kind(1) || sig(2420))
    //     handle_attest_submit 가 기대하는 wire layout (Pitfall 1 회피)
    const WIRE_ATTEST_LEN: usize = MLDSA44::PK_LEN + 1 + MLDSA44::SIG_LEN;
    let mut attest_wire = [0u8; WIRE_ATTEST_LEN];
    attest_wire[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    attest_wire[MLDSA44::PK_LEN] = bus_kind as u8;
    attest_wire[MLDSA44::PK_LEN + 1..].copy_from_slice(&sig);

    // (5) WIRE_ATTEST_FIXTURE 적재  lumen smoke 가 sys_attest_fixture_export 로 회수
    // SAFETY BSP single-core 부팅 초기 본 함수 단일 진입
    unsafe {
        (*(&raw mut WIRE_ATTEST_FIXTURE)).copy_from_slice(&attest_wire);
    }

    // (6) handle_attest_submit kernel-side direct call (Leg 1 valid)
    let baseline_total = unsafe { (*(&raw const crate::hsm_attest::AUDIT_RING)).total };
    let mut resp_buf = [0u8; WIRE_FRAME_MAX];
    let n1 = handle_attest_submit(1, &attest_wire, &mut resp_buf);
    let resp_status_leg1 = u16::from_le_bytes([resp_buf[14], resp_buf[15]]);
    if n1 != 16 || resp_status_leg1 != 0 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (Leg 1 dispatcher)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (7) Leg 2 mutated sig (sig 첫 옥텟 flip == fixture offset PK_LEN+1 == 1313)
    let mut tampered = attest_wire;
    tampered[MLDSA44::PK_LEN + 1] ^= 0xFF;
    let mut resp_buf2 = [0u8; WIRE_FRAME_MAX];
    let n2 = handle_attest_submit(2, &tampered, &mut resp_buf2);
    let resp_cmd_leg2 = u16::from_le_bytes([resp_buf2[6], resp_buf2[7]]);
    let resp_status_leg2 = u16::from_le_bytes([resp_buf2[14], resp_buf2[15]]);
    if n2 != 16 || resp_cmd_leg2 != 0xFFFF || resp_status_leg2 != 3 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (Leg 2 dispatcher)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (8) audit_ring delta == 2 (5 WireReattestOk + 6 WireReattestFail)
    let after_total = unsafe { (*(&raw const crate::hsm_attest::AUDIT_RING)).total };
    if after_total != baseline_total + 2 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (audit_ring delta != 2)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (9) ATTEST_PHASE5_1_OK marker  Pitfall 6 substring 충돌 0 검증됨
    // SAFETY identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] ATTEST_PHASE5_1_OK marker (wire AttestSubmit Leg1 ok + Leg2 denied + audit +2)",
            vga::Color::Green,
        );
    }

    // cleanup  비밀자료 stack-local 흔적 0
    pre.zeroize();
    digest.zeroize();
    attest_wire.zeroize();
    tampered.zeroize();
}

/// Phase 5.1 D-04 attest_payload 3733 옥텟 fixture export 핸들러 (feature smoke 한정)
///
/// SyscallNum AttestFixtureExport(13) 의 dispatch 본문 ABI
///   rdi = out_ptr (user-space dst)
///   rsi = out_len (== 3733 정확 정합)
///   반환 u64  성공 시 0, 음수 SyscallError as_rax
///
/// # Safety
/// 호출자 (lumen Ring 3) 가 ctx.arg1 == 3733 정확 정합 후 호출 권장 본 함수 자체가 검증
#[cfg(feature = "smoke")]
pub fn handle_attest_fixture_export(ctx: &mut syscall::SyscallContext) -> u64 {
    use syscall::{SyscallError, is_user_address};
    let out_ptr = ctx.arg0;
    let out_len = ctx.arg1 as usize;
    if out_len != 3733 {
        return SyscallError::BadArg.as_rax();
    }
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(3733)) {
        return SyscallError::BadAddress.as_rax();
    }
    // SAFETY out_ptr 가 user_space dual-range 통과 SMAP stac/clac 윈도우 최소화
    //        WIRE_ATTEST_FIXTURE 는 BSP single-core 부팅 초기 채워진 BSS read-only 진입
    unsafe {
        cpu::stac();
        core::ptr::copy_nonoverlapping(
            (&raw const WIRE_ATTEST_FIXTURE) as *const u8,
            out_ptr as *mut u8,
            3733,
        );
        cpu::clac();
    }
    0
}

/// Phase 6 GAP D-PHASE6 air-gap dual gate + sys_hsm_status + gap_self_check 통합 smoke test
///
/// # Safety
/// 부팅 시 단일 코어 init_audit_read_cap + init_network_cap (cfg) + gap_self_check 모두 완료 가정
/// debug + feature smoke 게이트로 release 빌드 부재
///
/// # Marker
/// VGA 4 line emit GAP_PHASE6_OK qemu-test.sh REQUIRE_GAP_PHASE6_OK env accumulator 가 잠금
#[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
unsafe fn gap_phase6_smoke_test() {
    // Leg 1 AUDIT_READ_CAP token != 0 sanity (gap_self_check 통과 확인)
    // SAFETY BSP single-core init_audit_read_cap 호출 완료 가정 read-only snapshot
    let audit_cap_token = unsafe { (&raw const air_gap::AUDIT_READ_CAP).read().token };
    if audit_cap_token == 0 {
        // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
        unsafe {
            vga::println(
                b"[iso-light-k0] GAP_PHASE6 FAIL AUDIT_READ_CAP token 0",
                vga::Color::Red,
            );
        }
        return;
    }
    // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
    unsafe {
        vga::println(
            b"[iso-light-k0] GAP_PHASE6 leg 1 AUDIT_READ_CAP token nonzero OK",
            vga::Color::Green,
        );
    }

    // Leg 2 (cfg tls-external) NETWORK_ATTACH_CAP token != 0 sanity
    #[cfg(feature = "tls-external")]
    {
        // SAFETY BSP single-core init_network_cap 호출 완료 가정 read-only snapshot
        let network_cap_token = unsafe { (&raw const air_gap::NETWORK_ATTACH_CAP).read().token };
        if network_cap_token == 0 {
            // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
            unsafe {
                vga::println(
                    b"[iso-light-k0] GAP_PHASE6 FAIL NETWORK_ATTACH_CAP token 0",
                    vga::Color::Red,
                );
            }
            return;
        }
        // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
        unsafe {
            vga::println(
                b"[iso-light-k0] GAP_PHASE6 leg 2 NETWORK_ATTACH_CAP token nonzero OK",
                vga::Color::Green,
            );
        }
    }

    // Leg 3 (cfg not tls-external) NETWORK_SYM_PRESENT cfg const fold sanity
    #[cfg(not(feature = "tls-external"))]
    {
        const _: () = assert!(!air_gap::NETWORK_SYM_PRESENT);
        // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
        unsafe {
            vga::println(
                b"[iso-light-k0] GAP_PHASE6 leg 2 NETWORK_SYM_PRESENT const fold OK",
                vga::Color::Green,
            );
        }
    }

    // 마지막 GAP_PHASE6_OK marker (4-line 의 마지막 라인) Plan 06-07 qemu-test.sh grep 입력
    // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
    unsafe {
        vga::println(
            b"[iso-light-k0] GAP_PHASE6_OK marker",
            vga::Color::Green,
        );
    }
}

/// 마이크로커널 메인 이벤트 루프.
///
/// IPC 요청, 타이머 인터럽트 대기 (hlt).
/// TODO: IPC 수신 큐 처리, Capability 검증, 스케줄러 연동
fn kernel_main_loop() -> ! {
    loop {
        crate::arch::active::cpu::wait_for_interrupt();
    }
}
