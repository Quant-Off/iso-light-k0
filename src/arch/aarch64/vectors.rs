//! 본 모듈은 aarch64 예외 벡터 테이블(16-entry)과 VBAR_EL1 로드를 제공합니다.
//!
//! # Features
//! ARMv8 예외 벡터 16 엔트리(4 그룹 x 4 타입, 각 0x80 byte)를 `.vector_table`
//! 섹션에 배치하고 테이블 베이스를 2KiB(0x800) 정렬하여 VBAR_EL1 계약을
//! 충족합니다(ARM-03). x86_64 `idt.rs` 의 256-entry IDT + `lidt` 구조를 role
//! -match 하되 인코딩은 divergent 하며 각 엔트리는 디스크립터가 아니라 핸들러
//! 코드 자체입니다.
//!
//! # Safety
//! panic 재귀 synchronous exception 을 차단하기 위해(Pitfall 14 SC8) 각 벡터
//! 핸들러의 두 번째 명령을 `MSR SPSel, #1` 로 두어 SP_EL1 을 선택하고, dedicated
//! 16 KiB panic 스택을 `MSR SP_EL1` 로 활성한 뒤 상위 핸들러로 분기합니다. x86
//! IST(Interrupt Stack Table)에 대응하며 손상된 SP 사용으로 인한 재귀 fault
//! 무한 루프를 차단합니다. SVC(ESR_EL1.EC==0b010101, lower EL AArch64 sync)는
//! `aarch64_sync_lower_el` 심볼로 10-E syscall dispatch 분기 자리를 예약합니다.

use core::arch::global_asm;

global_asm!(
    r#"
    //
    // § 1. 예외 벡터 테이블 (.vector_table 2KiB 정렬 ARM-03)
    //     16 entry = 4 그룹(cur SP0 / cur SPx / lower A64 / lower A32) x 4 타입
    //     각 entry 0x80(128) byte 테이블 베이스 0x800(2KiB) 정렬
    //
    .section .vector_table,"ax",%progbits
    .align 11                           // 2^11 = 0x800 테이블 베이스 2KiB 정렬
    .global _vector_table
_vector_table:

    // Pitfall 14 (SC8) 벡터 진입 스텁
    //   1st  msr daifset #0xf  예외 진입 시 DAIF 전 mask 확정
    //   2nd  msr SPSel #1      SP_EL1 선택 (손상 SP 회피)
    //        msr sp_el1        dedicated 16 KiB panic 스택 활성
    //        b   handler       상위 핸들러 분기
.macro VEC handler
    .align 7                            // 2^7 = 0x80 entry 정렬
    msr daifset, #0xf
    msr SPSel, #1
    adrp x18, __panic_stack_top
    add  x18, x18, :lo12:__panic_stack_top
    msr  sp_el1, x18
    b    \handler
.endm

    // 복구 가능 IRQ 진입 스텁 (fail-stop 아님)
    //   panic 스택 clobber 없이 인터럽트된 SP_EL1 을 보존한 채 핸들러로 분기
    //   핸들러가 x0-x30 전량 save/restore 후 eret 로 인터럽트 지점 복귀 (Pitfall 14 무관)
.macro VEC_IRQ handler
    .align 7                            // 2^7 = 0x80 entry 정렬
    b    \handler
.endm

    // 그룹 A current EL with SP_EL0
    VEC aarch64_default_exception       // Synchronous
    VEC aarch64_default_exception       // IRQ
    VEC aarch64_default_exception       // FIQ
    VEC aarch64_default_exception       // SError
    // 그룹 B current EL with SP_ELx
    VEC aarch64_default_exception       // Synchronous
    VEC_IRQ aarch64_irq_current_el      // IRQ  (부팅 proof SGI delivery 경로)
    VEC aarch64_default_exception       // FIQ
    VEC aarch64_default_exception       // SError
    // 그룹 C lower EL AArch64 (SVC 진입 그룹)
    VEC aarch64_sync_lower_el           // Synchronous SVC EC=0b010101 10-E 분기 자리
    VEC aarch64_default_exception       // IRQ
    VEC aarch64_default_exception       // FIQ
    VEC aarch64_default_exception       // SError
    // 그룹 D lower EL AArch32
    VEC aarch64_default_exception       // Synchronous
    VEC aarch64_default_exception       // IRQ
    VEC aarch64_default_exception       // FIQ
    VEC aarch64_default_exception       // SError

    //
    // § 2. 기본 핸들러 예외 정보 캡처 후 fail-stop
    //     ESR_EL1 FAR_EL1 ELR_EL1 관측 후 wfi 무한 정지
    //     aarch64_sync_lower_el 은 10-E syscall dispatch 예약 심볼 (현재 기본 동작)
    //
    .section .text,"ax",%progbits
    .global aarch64_sync_lower_el
aarch64_sync_lower_el:
    b   aarch64_svc_entry              // 10-E SVC #0 dispatch (syscall.rs) EC 확인 후 분기
    .global aarch64_default_exception
aarch64_default_exception:
    mrs x0, esr_el1                     // 예외 syndrome
    mrs x1, far_el1                     // fault 주소
    mrs x2, elr_el1                     // 예외 반환 주소
.Lexc_park:
    wfi
    b   .Lexc_park

    //
    // § 2b. 복구 가능 IRQ 핸들러 (current EL SP_ELx IRQ)
    //     인터럽트된 SP_EL1 위에 x0-x30 전량 save 후 Rust 디스패처(gic::aarch64_irq_dispatch)
    //     를 bl 로 호출하여 ICC_IAR1_EL1 ACK -> IRQ N delivered 마커 -> ICC_EOIR1_EL1 통지
    //     한 뒤 컨텍스트 restore + eret 로 인터럽트 지점 복귀 (부팅 proof 1 회 delivery)
    //
    .global aarch64_irq_current_el
aarch64_irq_current_el:
    sub  sp, sp, #256
    stp  x0,  x1,  [sp, #16*0]
    stp  x2,  x3,  [sp, #16*1]
    stp  x4,  x5,  [sp, #16*2]
    stp  x6,  x7,  [sp, #16*3]
    stp  x8,  x9,  [sp, #16*4]
    stp  x10, x11, [sp, #16*5]
    stp  x12, x13, [sp, #16*6]
    stp  x14, x15, [sp, #16*7]
    stp  x16, x17, [sp, #16*8]
    stp  x18, x19, [sp, #16*9]
    stp  x20, x21, [sp, #16*10]
    stp  x22, x23, [sp, #16*11]
    stp  x24, x25, [sp, #16*12]
    stp  x26, x27, [sp, #16*13]
    stp  x28, x29, [sp, #16*14]
    str  x30,      [sp, #16*15]
    bl   aarch64_irq_dispatch
    ldp  x0,  x1,  [sp, #16*0]
    ldp  x2,  x3,  [sp, #16*1]
    ldp  x4,  x5,  [sp, #16*2]
    ldp  x6,  x7,  [sp, #16*3]
    ldp  x8,  x9,  [sp, #16*4]
    ldp  x10, x11, [sp, #16*5]
    ldp  x12, x13, [sp, #16*6]
    ldp  x14, x15, [sp, #16*7]
    ldp  x16, x17, [sp, #16*8]
    ldp  x18, x19, [sp, #16*9]
    ldp  x20, x21, [sp, #16*10]
    ldp  x22, x23, [sp, #16*11]
    ldp  x24, x25, [sp, #16*12]
    ldp  x26, x27, [sp, #16*13]
    ldp  x28, x29, [sp, #16*14]
    ldr  x30,      [sp, #16*15]
    add  sp, sp, #256
    eret

    //
    // § 3. dedicated panic 스택 (.bss NOLOAD 16-byte 정렬 16 KiB)
    //
    .section .bss.panic_stack,"aw",%nobits
    .align 4                            // 2^4 = 16 byte 정렬
__panic_stack_bottom:
    .skip 16384                         // 16 KiB dedicated panic 스택 (SC8)
__panic_stack_top:
"#
);

/// 예외 벡터 테이블을 VBAR_EL1 에 로드하고 초기 인터럽트 마스크를 세팅함.
///
/// boot_stub `el1_entry` 가 이미 VBAR_EL1 을 로드했더라도 재확인하며(HAL init
/// 표면 계약), GIC bring-up(10-D) 전 안전 기본값으로 IRQ 를 mask 함.
///
/// # Safety
/// 부팅 초기 단일 코어 시퀀스에서 1 회만 호출해야 함.
pub unsafe fn init() {
    // SAFETY VBAR_EL1 은 EL1 벡터 베이스 레지스터로 부팅 초기 1 회 세팅됨
    //        _vector_table 은 링커가 0x800 정렬 배치 (ARM-03)
    unsafe {
        core::arch::asm!(
            "adrp {t}, _vector_table",
            "add  {t}, {t}, :lo12:_vector_table",
            "msr  vbar_el1, {t}",
            "isb",
            "msr  daifset, #0b0010",        // 초기 IRQ mask GIC bring-up 전 기본값
            t = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}
