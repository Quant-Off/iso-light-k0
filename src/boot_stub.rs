//! Multiboot2 헤더와 32-bit -> 64-bit Long Mode 전환 스텁(Higher-Half Kernel)
//! 을 제공하는 모듈입니다.
//!
//! 부팅 흐름:
//!   1. GRUB 이 Multiboot2 로 `_start` (32-bit, .boot32, phys ~0x100036) 에
//!      진입함. 여기서 PML4[0] = boot_pdpt_low (Identity 4GiB), PML4[511] =
//!      boot_pdpt_high (Higher-Half) 를 구성하고 EFER.LME | EFER.NXE 활성 후
//!      CR0.PG 를 켜서 페이징을 활성화하며, Far Jump (CS=0x08, 64-bit code
//!      segment) 로 Long Mode 로 전환함.
//!   2. `_start64` (64-bit 트램폴린, .boot32, phys ~0x1000F0) 에서 RSP =
//!      boot_stack_top (저주소, identity), RDI = mb2_info_ptr 을 설정하고,
//!      `jmp [.Lkernel_entry]` 로 64-bit 간접 점프를 수행함.
//!   3. `_kernel_start` (고주소 VMA, Rust) 가 호출되어 본격적인 커널 초기화가
//!      시작됨.
//!
//! 페이지 테이블 설계 (부팅 중 활성):
//!   - PML4[0]   -> boot_pdpt_low  -> 4 x 1 GiB Identity (0..4GiB -> 0..4GiB)
//!   - PML4[511] -> boot_pdpt_high -> PDPT[510]: 0xFFFFFFFF_8000_0000 -> phys 0
//!                                    PDPT[511]: 0xFFFFFFFF_C000_0000 -> phys 1GiB
//!
//! Higher-Half 점프 전략:
//!   `_start64` 는 .boot32(저주소) 에 있으므로 `_kernel_start`(고주소) 로의
//!   직접 call 이 불가합니다 (상대 오프셋이 32-bit 범위 초과). 따라서
//!   `.Lkernel_entry` 에 64-bit 절대 주소를 저장하고 `jmp rax` 간접 점프로
//!   전환합니다.

use core::arch::global_asm;

global_asm!(
    r#"
    /*
     * § 1. Multiboot2 헤더 (.multiboot2header)
     *     GRUB이 ELF 파일 첫 32 KiB를 스캔하여 magic(0xE85250D6) 탐색.
     */
    .section .multiboot2header, "a"
    .align 8
    mb2_hdr_start:
        .long 0xE85250D6                                           /* magic      */
        .long 0                                                    /* arch: i386 */
        .long (mb2_hdr_end - mb2_hdr_start)                       /* length     */
        .long (0 - 0xE85250D6 - (mb2_hdr_end - mb2_hdr_start))   /* checksum   */
        .word 0                                                    /* end tag type  */
        .word 0                                                    /* end tag flags */
        .long 8                                                    /* end tag size  */
    mb2_hdr_end:

    /*
     * § 2. Boot GDT (.boot32, VMA = phys)
     *     [0] Null  [1] 64-bit Code (L=1)  [2] 32/64-bit Data
     *     init_gdt() 호출 시 Rust KERNEL_GDT로 교체됨.
     */
    .section .boot32, "ax"
    .align 8
    boot_gdt64:
        .quad 0                     /* [0] Null                          */
        .quad 0x00AF9A000000FFFF    /* [1] 64-bit Code: P|DPL0|L=1       */
        .quad 0x00CF92000000FFFF    /* [2] Data: P|DPL0|G=1|D/B=1        */
    boot_gdt64_end:

    /* GDTR 구조체 (32-bit 보호 모드용): limit(u16) + base(u32) = 6 bytes */
    boot_gdt64_ptr:
        .word (boot_gdt64_end - boot_gdt64 - 1)
        .long boot_gdt64            /* 32-bit 물리 주소 (VMA = phys) */

    /*
     * § 3. Bootstrap 페이지 테이블 + 초기 스택 (.boot_bss, VMA = phys)
     *     @nobits: 파일에 저장 안 함, GRUB/ELF 로더가 paddr 기준 0-초기화.
     *     32-bit 코드에서 물리 주소로 직접 접근하므로 저주소 필수.
     */
    .section .boot_bss, "aw", @nobits
    .align 4096

    /* 4단계 페이지 맵 루트 (PML4): 512 엔트리 x 8 bytes = 4 KiB */
    boot_pml4:
        .skip 4096

    /* Identity Map용 PDPT: PML4[0] -> 4 x 1 GiB (0..4GiB -> 0..4GiB) */
    .align 4096
    boot_pdpt_low:
        .skip 4096

    /* Higher-Half Map용 PDPT: PML4[511] -> PDPT[510..511]
       PDPT[510]: 0xFFFFFFFF_8000_0000..0xBFFF_FFFF -> phys 0
       PDPT[511]: 0xFFFFFFFF_C000_0000..0xFFFF_FFFF -> phys 1GiB */
    .align 4096
    boot_pdpt_high:
        .skip 4096

    /*
      부트(BSP) 커널 스택
      레이아웃 (저주소 -> 고주소):
         boot_stack_guard_bottom  | guard 4 KiB  |<- 가드 영역 (CANARY 기록)
         boot_stack_bottom        |              |
                                  | stack 256 KiB|<- 본체 (스택은 위->아래로 자람)
         boot_stack_top           |              |

       - 256 KiB: elib-k0-nt 암호 프리미티브(ML-DSA, ML-KEM, SHAKE 등)가
         내부에 수십 KB 스택 프레임을 사용할 수 있어 충분한 여유 확보.
       - 4 KiB guard: MMU 활성 전에는 CANARY 패턴, 활성 후에는 미매핑으로
         스택 오버플로를 하드웨어 #PF로 전환시킴.
       - align 4096: 가드 페이지가 정확히 페이지 경계에 맞도록 강제.
    -----------------------------------------------------------------
      */
    .align 4096
    .global boot_stack_guard_bottom
    boot_stack_guard_bottom:
        .skip 4096                  /* guard 4 KiB */
    .global boot_stack_bottom
    boot_stack_bottom:
        .skip 262144                /* stack 256 KiB */
    .global boot_stack_top
    boot_stack_top:

    /*
     * § 4. 32-bit 진입점 (_start, .boot32)
     *     GRUB이 Multiboot2로 점프하는 첫 번째 커널 코드 (EIP = 물리 주소).
     *     진입 조건: EAX = 0x36D76289, EBX = mb2_info 물리 주소,
     *               CR0.PE=1, CR0.PG=0, EFER.LME=0
     */
    .code32
    .section .boot32, "ax"
    .global _start
    _start:
        cli
        mov edi, eax               /* EDI = Multiboot2 매직 보존 */
        mov esi, ebx               /* ESI = mb2_info 물리 주소 보존 */

        /* Boot GDT 로드 (GDTR.base = 32-bit 물리 주소) */
        lgdt [boot_gdt64_ptr]

        /* 세그먼트 -> flat 32-bit data descriptor (selector 0x10 = GDT[2]) */
        mov ax, 0x10
        mov ds, ax
        mov es, ax
        mov ss, ax
        xor ax, ax
        mov fs, ax
        mov gs, ax

        /*
      PML4[0] = boot_pdpt_low | P|W  (Identity Map)
      엔트리 플래그: Present(0) | Writable(1) = 0x3
        ------------------------------------------------------------------
      */
        mov eax, offset boot_pdpt_low
        or  eax, 3
        mov dword ptr [boot_pml4],     eax
        mov dword ptr [boot_pml4 + 4], 0

        /* boot_pdpt_low: 4 x 1 GiB 대용량 페이지 (PS|W|P = 0x83) */
        mov dword ptr [boot_pdpt_low +  0], 0x00000083  /* PDPT[0]: 0 GiB   */
        mov dword ptr [boot_pdpt_low +  4], 0
        mov dword ptr [boot_pdpt_low +  8], 0x40000083  /* PDPT[1]: 1 GiB   */
        mov dword ptr [boot_pdpt_low + 12], 0
        mov dword ptr [boot_pdpt_low + 16], 0x80000083  /* PDPT[2]: 2 GiB   */
        mov dword ptr [boot_pdpt_low + 20], 0
        mov dword ptr [boot_pdpt_low + 24], 0xC0000083  /* PDPT[3]: 3 GiB   */
        mov dword ptr [boot_pdpt_low + 28], 0

        /*
      PML4[511] = boot_pdpt_high | P|W  (Higher-Half Map)
      PML4[511] 오프셋 = 511 x 8 = 4088
        ------------------------------------------------------------------
      */
        mov eax, offset boot_pdpt_high
        or  eax, 3
        mov dword ptr [boot_pml4 + 4088], eax           /* PML4[511] low  */
        mov dword ptr [boot_pml4 + 4092], 0             /* PML4[511] high */

        /* boot_pdpt_high:
           PDPT[510] = phys 0x00000000 -> 0xFFFFFFFF_8000_0000..BFFF_FFFF
           PDPT[511] = phys 0x40000000 -> 0xFFFFFFFF_C000_0000..FFFF_FFFF
           오프셋: 510x8=4080, 511x8=4088 */
        mov dword ptr [boot_pdpt_high + 4080], 0x00000083  /* PDPT[510]: phys 0   */
        mov dword ptr [boot_pdpt_high + 4084], 0
        mov dword ptr [boot_pdpt_high + 4088], 0x40000083  /* PDPT[511]: phys 1GiB */
        mov dword ptr [boot_pdpt_high + 4092], 0

        /* CR4.PAE = 1 (Physical Address Extension) */
        mov eax, cr4
        or  eax, (1 << 5)
        mov cr4, eax

        /* CR3 <- PML4 물리 주소 (boot_pml4는 .boot_bss에 있어 VMA = phys) */
        mov eax, offset boot_pml4
        mov cr3, eax

        /* IA32_EFER:
             LME (bit 8)  = Long Mode Enable
             NXE (bit 11) = No-Execute Enable (PE 플래그 사용 위한 필수 조건)
           NXE를 미리 활성화해야 alloc_or_get_table의 NO_EXECUTE 비트가
           RESERVED 비트 위반 #PF를 유발하지 않음. */
        mov ecx, 0xC0000080
        rdmsr
        or  eax, (1 << 8) | (1 << 11)  /* LME | NXE */
        wrmsr

        /* CR0.PG(31) | CR0.PE(0) = 1 -> 페이징 활성화 -> Long Mode 전환 */
        mov eax, cr0
        or  eax, 0x80000001
        mov cr0, eax

        /* Far Jump -> 64-bit Long Mode (CS = boot_gdt64[1] = 0x08)
           opcode 0xEA = JMP FAR ptr16:32
           _start64는 .boot32에 있으므로 32-bit 절대 주소로 인코딩 가능. */
        .byte 0xEA
        .long _start64             /* 32-bit 물리 VMA (= phys, .boot32 소속) */
        .word 0x08                 /* CS: boot_gdt64[1] (64-bit code) */

    /*
     * § 5. 64-bit 트램폴린 (_start64, .boot32, 저주소)
     *     Far Jump 직후 Long Mode 진입. Higher-Half _kernel_start로 전환.

     *     GPR 상태 (Far Jump 이후):
     *       RDI = magic (from EDI saved in _start)
     *       RSI = mb2_info_ptr (from ESI saved in _start)
     */
    .code64
    .global _start64
    _start64:
        /* 세그먼트 레지스터 초기화 (64-bit mode: CS 외 대부분 무의미) */
        xor ax, ax
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov fs, ax
        mov gs, ax

        /* RSP = boot_stack_top (저주소 ~0x11XXXX, identity map으로 접근)
           boot_stack_top < 0x80000000 -> R_X86_64_32S 부호 확장 = 0-확장 -> 정상 */
        mov rsp, offset boot_stack_top
        and rsp, -16                /* 16-byte ABI 스택 정렬 */

        /* RDI = mb2_info_ptr (System V x86_64 ABI 1번째 인수)
           32-bit ESI -> EDI 이동: RAX 상위 32-bit 자동 0-확장 -> 올바른 RDI */
        mov edi, esi

        /* Higher-Half _kernel_start로 간접 점프
           _kernel_start VMA = 0xFFFFFFFF80XXXXXX (64-bit, 32-bit 범위 초과)
           -> direct call/jmp 불가 (상대 오프셋 32-bit 범위 초과)
           -> .Lkernel_entry에서 64-bit 절대 주소를 로드하여 간접 점프 */
        mov rax, qword ptr [rip + .Lkernel_entry]
        jmp rax                     /* _kernel_start -> ! (never returns) */

    /* _kernel_start의 64-bit 절대 VMA (R_X86_64_64 릴로케이션, -no-pie 허용) */
    .Lkernel_entry:
        .quad _kernel_start

    /* 안전장치: _kernel_start가 반환될 경우 (발생하면 안 됨) */
    .Lhalt64:
        cli
        hlt
        jmp .Lhalt64
"#
);
