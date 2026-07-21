/*
 * iso-light-k0 aarch64 링커 스크립트 - QEMU virt -kernel 직접 부팅
 *
 * 주소 공간 설계
 *
 *   . = 0x40080000    QEMU virt RAM base 0x4000_0000 + -kernel 로드 오프셋 0x80000 (A6)
 *
 *   x86 (linker.ld) 대비 divergence
 *     - Multiboot2 헤더 / .boot32 / .boot_bss 저주소 섹션 부재 (aarch64 는 GRUB 없음)
 *     - Higher-Half VMA/LMA 분리 부재 (직접 부팅, VMA = LMA)
 *     - 신규 .vector_table ALIGN(0x800) 섹션 (VBAR_EL1 2KiB 정렬 필수)
 *
 *   부트 흐름
 *     QEMU -kernel -> _start(EL1/EL2) -> EL2->EL1 강하 -> VBAR_EL1 = _vector_table
 *          -> MMU stage1 enable -> GICv3 wake -> 커널 진입
 *
 *   .vector_table
 *     ARMv8 예외 벡터 16 entry x 0x80 byte = 0x800 (2KiB)
 *     VBAR_EL1 은 하위 11 bit == 0 (2KiB 정렬) 를 강제하므로 ALIGN(0x800) 필수
 *     CI 검증 objdump -h .vector_table 주소 하위 11 bit == 0 (ARM-03 check-vector-align.sh)
 */

ENTRY(_start)

SECTIONS
{
    /* QEMU virt RAM base 0x4000_0000 + -kernel 오프셋 0x80000 (A6 assumption) */
    . = 0x40080000;

    /* 실행 코드 (Read + Execute) boot stub 우선 배치 */
    .text :
    {
        _text_start = .;
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    /* 예외 벡터 테이블 VBAR_EL1 = 2KiB 정렬 필수 (16 entry x 0x80 = 0x800) */
    .vector_table : ALIGN(0x800)
    {
        _vector_table = .;
        KEEP(*(.vector_table))
    }

    /* 읽기 전용 데이터 */
    .rodata : ALIGN(0x1000)
    {
        _rodata_start = .;
        *(.rodata .rodata.*)
    }

    /* 초기화된 읽기-쓰기 데이터 */
    .data : ALIGN(0x1000)
    {
        _data_start = .;
        *(.data .data.*)
    }

    /* 미초기화 데이터 (BSS) filesz=0 런타임 0-초기화 */
    .bss (NOLOAD) : ALIGN(0x1000)
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
    }

    _kernel_end         = .;
    _kernel_end_aligned = ALIGN(0x1000);

    /* 디버그/링커 내부 섹션 폐기 */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
    }
}
