/*
 * iso-user-lumen 사용자 ELF 링커 스크립트
 *
 * iso-user-hello 와 동일한 레이아웃 (DEFAULT_USER_ENTRY = 0x400000).
 * lumen 와이어 호환 검증 페이로드는 elib-k0-nt 의존성으로 다소 크므로
 * 추가 PT_LOAD 세그먼트가 필요할 수 있음.
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

    /* GOT 섹션 — elib-k0-nt 의존성이 정적 PIC 코드를 포함할 경우 LLVM 이
       생성하는 PLT/GOT 슬롯 처리. 정적 링킹이지만 코드 모델 small 의
       자체 참조를 위해 비워있더라도 placement 는 명시해야 함. */
    .got : ALIGN(0x10) {
        *(.got)
    } :rodata
    .got.plt : ALIGN(0x10) {
        *(.got.plt)
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
