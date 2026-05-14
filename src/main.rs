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
pub mod boot;
pub mod boot_stub; // Multiboot2 헤더 + 32-bit 부팅 스텁 (global_asm)
pub mod capability; // Capability-based Access Control
pub mod cpu; // CPU 특수 레지스터 / SIMD·FPU 컨텍스트 활성화
pub mod crypto_service; // EP_CRYPTO 엔드포인트 암호화 서비스 디스패처
pub mod sign_service;   // EP_SIGN 엔드포인트 ML-DSA PQ 서명 서비스
pub mod elf; // ELF64 정적 실행 파일 파서
pub mod hsm; // HSM 추상 트레이트 + NullHsm
pub mod hsm_registry; // Phase 1: HSM 멀티 슬롯 레지스트리 (capability-backed)
pub mod idt;
pub mod ipc; // IPC 메시지 패싱 (동기 rendezvous)
pub mod keystore; // 소프트 PSK 키 저장소 (HSM 폴백)
pub mod memory_map;
pub mod mmu;
mod panic;
#[cfg(target_arch = "x86_64")]
pub mod process; // 정적 프로세스 슬롯 + Ring 3 진입
pub mod stack; // 커널 스택 + 가드 페이지 레이아웃
#[cfg(target_arch = "x86_64")]
pub mod syscall; // syscall/sysret 사용자 ↔ 커널 진입 경로
pub mod tls; // TLS 1.3 PSK (psk_dhe_ke / psk_pq_hybrid_ke)
pub mod tss;
pub mod vga;
// 보안 메모리 소거는 외부 `zeroize` 크레이트(elib-k0-nt) 사용

use mmu::{AddressSpace, KERNEL_VMA_BASE, Mmu, PageTableFlags, Uninitialized};

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
#[unsafe(no_mangle)]
pub extern "C" fn _kernel_start(mb2_addr: u64) -> ! {
    //
    // 1. 인터럽트 재확인 비활성화
    //
    // boot_stub._start에서 cli를 실행했지만, 64-bit 진입 후에도 명시적으로 보장
    #[cfg(target_arch = "x86_64")]
    // SAFETY: GDT/IDT 설정 전, 인터럽트 비활성화 안전
    unsafe {
        core::arch::asm!("cli", options(nostack, preserves_flags));
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
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
    // SAFETY: CLI 상태, TSS 초기화 완료, KERNEL_GDT 유효
    unsafe {
        vga::println(b"[iso-light-k0] GDT Init & Apply TSS...", vga::Color::Green);
        boot::init_gdt(tss::base_addr(), tss::limit());
        vga::println(b"[iso-light-k0] Done.", vga::Color::Green);
    }

    //
    // 4. IDT 초기화 + 8259 PIC 재매핑 + LIDT
    //
    #[cfg(target_arch = "x86_64")]
    // SAFETY: CLI 상태, GDT/TSS 로드 완료
    unsafe {
        vga::println(b"[iso-light-k0] IDT Init...", vga::Color::Green);
        idt::init_idt();
        vga::println(b"[iso-light-k0] Done.", vga::Color::Green);
    }

    //
    // 4.5. SIMD/FPU 최종 확정 (예외 핸들러 가용 상태에서 재검증)
    //
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
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
    // 5. Multiboot2 메모리 맵 파싱
    //
    // mb2_addr은 _kernel_start의 매개변수(RDI)로 안전하게 전달됨
    // boot_stub._start에서 ESI에 저장했고, _start64에서 RDI로 복사함
    #[cfg(target_arch = "x86_64")]
    let memory_map = unsafe {
        vga::println(
            b"[iso-light-k0] Multiboot2 Memory Map Parsing(1/2)...",
            vga::Color::Green,
        );
        memory_map::parse_multiboot2(mb2_addr).unwrap_or_else(|_| memory_map::MemoryMap::empty())
    };
    #[cfg(target_arch = "x86_64")]
    let kaslr_offset: Option<u64> = unsafe {
        vga::println(
            b"[iso-light-k0] Multiboot2 Memory Map Parsing(2/2)...",
            vga::Color::Green,
        );
        memory_map::parse_kaslr_offset(mb2_addr)
    };

    //
    // 6. 물리 프레임 할당자 초기화
    //
    // SAFETY: 부팅 초기 단일 코어, MMU 활성화 전
    #[cfg(target_arch = "x86_64")]
    unsafe {
        vga::println(
            b"[iso-light-k0] Physic Frame Allocator Init...",
            vga::Color::Green,
        );
        allocator::init(&memory_map);

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
        // (c) Multiboot2 info 구조체 보호
        //
        // total_size는 헤더 첫 4바이트; 4KiB 올림으로 안전하게 예약
        let mb2_total = (mb2_addr as *const u32).read() as u64;
        let mb2_size_aligned = (mb2_total + 0xFFF) & !0xFFF;
        allocator::mark_used(mb2_addr, mb2_size_aligned);

        vga::println(b"[iso-light-k0] Done.", vga::Color::Green);
    }

    //
    // 7. MMU Typestate 초기화 + KASLR 오프셋 주입
    //
    #[cfg(target_arch = "x86_64")]
    let mmu: Mmu<Uninitialized> = Mmu::new();
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
    let kernel_space = unsafe { &mut *(&raw mut KERNEL_ADDR_SPACE) };
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
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
    #[cfg(target_arch = "x86_64")]
    unsafe {
        match capability::init_prng() {
            Ok(()) => vga::println(
                b"[iso-light-k0] Capability DRBG Init Done. (Hash-DRBG-SHA256)",
                vga::Color::Green,
            ),
            Err(_) => vga::println(
                b"[iso-light-k0] FATAL: no hardware entropy (RDSEED/RDRAND).",
                vga::Color::Red,
            ),
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
    // 15. 인터럽트 활성화 + 커널 메인 이벤트 루프
    //
    // IDT, GDT, TSS, PIC 초기화 완료 후 STI로 인터럽트 수신 시작
    #[cfg(target_arch = "x86_64")]
    // SAFETY: IDT/GDT/TSS/PIC/IPC 초기화 완료, 이제 인터럽트 수신 안전
    unsafe {
        core::arch::asm!("sti", options(nostack, preserves_flags));
        vga::println(b"[iso-light-k0] All Task Done.", vga::Color::Green);
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
        attach_kernel_side(HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE)
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

/// 마이크로커널 메인 이벤트 루프.
///
/// IPC 요청, 타이머 인터럽트 대기 (hlt).
/// TODO: IPC 수신 큐 처리, Capability 검증, 스케줄러 연동
fn kernel_main_loop() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: hlt는 다음 인터럽트 발생 시 재개되는 안전한 CPU 대기 명령어
        unsafe {
            core::arch::asm!("hlt", options(nostack, preserves_flags));
        }

        #[cfg(target_arch = "aarch64")]
        // SAFETY: wfi는 다음 인터럽트 발생 시 재개되는 안전한 대기 명령어
        unsafe {
            core::arch::asm!("wfi", options(nostack, preserves_flags));
        }
    }
}
