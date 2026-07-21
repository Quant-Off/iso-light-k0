//! 본 모듈은 aarch64 QEMU virt `-kernel` 직접 부팅 진입 스텁을 제공합니다.
//!
//! # Features
//! `_start` 에서 `CurrentEL` 을 판정하여 EL2 진입(virtualization=on)이면 EL1 으로
//! 무조건 `eret` 강하하고(Pitfall 9), EL1 직접 진입이면 통과합니다. 강하 후
//! `el1_entry` 는 SPSel 을 SP_EL1 로 전환하고 boot 스택 SP_EL1 을 활성한 뒤
//! VBAR_EL1 에 `.vector_table` 을 로드하고 CPACR_EL1.FPEN 을 세팅합니다. 진입
//! 레지스터 x0(DTB phys addr, A4)은 강하 구간에서 x19 로 보존되어 커널 합류점에
//! 전달됩니다.
//!
//! x86_64 `boot_stub.rs` 의 Multiboot2 헤더 + Long Mode 전환 구조를 mirror 하되
//! asm 은 전량 divergent 합니다. GRUB/GDT/TSS 가 부재하며 EL 기반 특권 모델을
//! 사용합니다. 커널 arch-중립 합류점(BootInfo 디스패치)은 후속 wave(10-C 이후)가
//! 배선하며 본 wave 는 `el1_entry` 도달과 특권 레지스터 정규화가 목표입니다.

use core::arch::global_asm;

global_asm!(
    r#"
    //
    // § 1. 진입점 _start (.text.boot)
    //     QEMU virt -kernel 로드 후 진입 x0 = DTB phys addr (A4)
    //     진입 EL 은 EL1(기본) 또는 EL2(virtualization=on)
    //
    .section .text.boot,"ax",%progbits
    .global _start
_start:
    // DTB phys addr 를 EL 강하 구간 동안 보존 (x19 는 callee-saved)
    mov x19, x0

    // CurrentEL bits[3:2] 판정 EL2 면 강하 EL1 직접이면 통과
    mrs x1, CurrentEL
    lsr x1, x1, #2
    cmp x1, #2
    b.ne el1_entry

    //
    // § 2. EL2 -> EL1 무조건 강하 (Pitfall 9 ARM-02)
    //     HCR_EL2.RW=1 EL1 AArch64 실행 SPSR_EL2=0x3c5 EL1h + DAIF 전 mask
    //
    mrs x1, hcr_el2
    orr x1, x1, #(1 << 31)          // HCR_EL2.RW = 1
    msr hcr_el2, x1
    mov x1, #0x3c5                  // SPSR_EL2 = 0b11_1100_0101 EL1h + DAIF masked
    msr spsr_el2, x1
    adr x1, el1_entry
    msr elr_el2, x1
    eret                            // EL1h 로 강하

    //
    // § 3. el1_entry (EL1) 특권 레지스터 정규화
    //     SPSel #1 -> SP_EL1=boot_stack -> VBAR_EL1 -> CPACR_EL1.FPEN
    //
el1_entry:
    msr SPSel, #1                   // SP_EL1 선택 (panic 스택 분리 준비)
    adrp x1, __boot_stack_top
    add  x1, x1, :lo12:__boot_stack_top
    mov  sp, x1                     // SP_EL1 = boot 스택 최상단

    adrp x1, _vector_table          // vectors.rs 가 .vector_table 에 배치 (0x800 정렬)
    add  x1, x1, :lo12:_vector_table
    msr  vbar_el1, x1               // 예외 벡터 베이스 로드 (ARM-03)

    mrs  x1, cpacr_el1              // CPACR_EL1.FPEN = 0b11 FP/SIMD 트랩 해제
    orr  x1, x1, #(0b11 << 20)
    msr  cpacr_el1, x1
    isb

    //
    // § 4. MMU 전 early print PL011 physical MMIO 로 EL=1 마커 직접 출력 (ARM-07)
    //      PL011 은 MMU 무관 동작하므로 identity 물리 UARTDR(0x0900_0000+0x00)에
    //      바이트 스트림을 흘림 (A1 폴백 base 10-C console 백엔드와 동일 주소)
    //
    movz x2, #0x0900, lsl #16       // x2 = PL011 base 0x0900_0000 (UARTDR offset 0x00)
    adr  x3, .Lel1_marker_el1
.Lel1_emit:
    ldrb w5, [x3], #1               // 마커 바이트 로드 후 포인터 전진
    cbz  w5, .Lel1_emit_done        // NUL 종단이면 종료
    strb w5, [x2]                   // UARTDR 에 바이트 write (TX)
    b    .Lel1_emit
.Lel1_emit_done:

    mov  x0, x19                    // DTB phys addr 복원 (커널 합류점 1 번째 인수 A4)

    // TODO 10-C 이후 arch-중립 커널 합류점(BootInfo 디스패치 MMU stage1 enable)으로 분기
    //      본 wave 는 el1_entry 도달과 특권 정규화 + EL=1 early print 가 목표이므로 park

    //
    // § 5. 반환 방지 halt trap (x86 cli hlt jmp 대응)
    //
.Lel1_park:
    wfi
    b    .Lel1_park

    //
    // § 6. EL=1 early print 마커 문자열 (park 뒤 배치 실행 경로 미도달)
    //
.Lel1_marker_el1:
    .asciz "EL=1\r\n"

    //
    // § 7. boot 스택 (.bss NOLOAD 16-byte 정렬)
    //
    .section .bss.boot_stack,"aw",%nobits
    .align 4                        // 2^4 = 16 byte 정렬
__boot_stack_bottom:
    .skip 65536                     // 64 KiB boot 스택
__boot_stack_top:
"#
);
