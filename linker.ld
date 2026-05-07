/*
 * iso-light-k0 링커 스크립트 - Higher-Half Kernel (kernel code model)
 *
 * 주소 공간 설계
 *
 *   PHYS_LOAD_BASE   = 0x00100000          GRUB이 커널 ELF를 로드하는 물리 주소
 *   KERNEL_VMA_BASE  = 0xFFFFFFFF80000000  커널 코드 모델 상위 2 GiB 기저
 *
 *   저주소 섹션 (VMA = LMA = 물리 주소):
 *     .multiboot2header, .boot32, .boot_bss
 *
 *   고주소 섹션 (VMA = LMA + KERNEL_VMA_BASE):
 *     .text, .rodata, .data, .bss
 *
 *   ELF PT_LOAD:
 *     1. .multiboot2header + .boot32   (RX, low VMA=phys)
 *     2. .boot_bss                     (RW, low VMA=phys, filesz=0)
 *     3. .text + .rodata               (R/RX, high VMA, low phys)
 *     4. .data + .bss                  (RW,   high VMA, low phys)
 *
 *   부트 흐름:
 *     GRUB -> _start(phys 0x100036) -> 페이지 테이블 설정
 *          -> PML4[0]   = boot_pdpt_low  (Identity: 0..4GiB -> 0..4GiB)
 *          -> PML4[511] = boot_pdpt_high (0xFFFFFFFF80000000 -> phys 0)
 *          -> Far Jump -> _start64 -> [rip+.Lkernel_entry] -> _kernel_start
 */

KERNEL_VMA_BASE = 0xFFFFFFFF80000000;
PHYS_LOAD_BASE  = 0x100000;

ENTRY(_start)

SECTIONS
{
    /* 부트 섹션: VMA = LMA = 물리 주소
       32-bit 코드가 절대 물리 주소로 직접 참조하므로 VMA = LMA 필수. */
    . = PHYS_LOAD_BASE;

    /* Multiboot2 헤더: ELF 파일 앞 32 KiB 이내 위치 보장 */
    .multiboot2header :
    {
        KEEP(*(.multiboot2header))
    }

    /* 32-bit 부팅 스텁 + Boot GDT */
    .boot32 :
    {
        KEEP(*(.boot32))
    }

    /* 부트 전용 BSS: bootstrap PML4 / PDPT / 초기 스택
       @nobits → 파일에 저장 안 함, GRUB이 paddr 기준으로 0-초기화 */
    .boot_bss (NOLOAD) : ALIGN(0x1000)
    {
        *(.boot_bss)
    }

    . = ALIGN(0x1000);
    _boot_end_phys = .;         /* 부트 섹션 물리 끝 (커널 섹션 LMA 기준점) */

    /* 커널 섹션: VMA = phys + KERNEL_VMA_BASE
       AT(expr): 각 섹션의 LMA(물리 로드 주소)를 명시적으로 지정.
       GRUB은 p_paddr(=LMA) 기준으로 세그먼트를 메모리에 배치함. */
    . = _boot_end_phys + KERNEL_VMA_BASE;

    /* 실행 코드 (Read + Execute) */
    .text ALIGN(0x1000) : AT(ADDR(.text) - KERNEL_VMA_BASE)
    {
        _text_start = .;
        *(.text .text.*)
    }

    /* 읽기 전용 데이터 */
    .rodata ALIGN(0x1000) : AT(ADDR(.rodata) - KERNEL_VMA_BASE)
    {
        _rodata_start = .;
        *(.rodata .rodata.*)
    }

    /* 초기화된 읽기-쓰기 데이터 */
    .data ALIGN(0x1000) : AT(ADDR(.data) - KERNEL_VMA_BASE)
    {
        _data_start = .;
        *(.data .data.*)
    }

    /* 미초기화 데이터 (BSS): filesz=0, GRUB이 물리 paddr 기준 0-초기화
       KERNEL_TSS, IDT, FRAME_ALLOCATOR 비트맵 등 Rust static이 여기에 위치 */
    .bss ALIGN(0x1000) : AT(ADDR(.bss) - KERNEL_VMA_BASE)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
    }

    _kernel_end         = .;                   /* 커널 VMA 끝 (4KiB 미정렬 가능) */
    _kernel_end_phys    = . - KERNEL_VMA_BASE; /* 커널 물리(LMA) 끝              */
    _kernel_end_aligned = ALIGN(0x1000);       /* 커널 VMA 끝, 4KiB 올림 정렬    */

    /* 디버그/링커 내부 섹션 폐기 */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
    }
}
