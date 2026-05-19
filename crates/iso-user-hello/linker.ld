/*
 * iso-user-hello 사용자 ELF 링커 스크립트
 *
 * `iso-light-k0` 의 `process::DEFAULT_USER_ENTRY` (0x400000) 베이스에 R+X 텍스트
 * 섹션을 배치합니다. .rodata / .data / .bss 도 같은 PML4 슬롯 안의 인접 페이지
 * 에 위치합니다. 사용자 영역 (PML4[0..256]) 내부.
 */

ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);   /* R+X */
    rodata PT_LOAD FLAGS(4);   /* R   */
    data   PT_LOAD FLAGS(6);   /* R+W */
}

SECTIONS
{
    . = 0x400000;

    .text : ALIGN(0x1000) {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    .rodata : ALIGN(0x1000) {
        *(.rodata .rodata.*)
    } :rodata

    .data : ALIGN(0x1000) {
        *(.data .data.*)
    } :data

    .bss : ALIGN(0x1000) {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
        *(.gcc_except_table*)
    }
}
