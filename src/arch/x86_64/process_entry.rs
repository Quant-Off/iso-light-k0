//! Ring 3 최초 진입 asm 시퀀스를 담는 모듈입니다.
//!
//! # Features
//! CR3 적재 후 swapgs, iretq 를 단일 atomic asm 블록으로 실행하여 Ring 0 에서
//! Ring 3 사용자 컨텍스트로 권한 강하합니다. BootEntry HAL trait 의 x86_64 구현
//! 표면입니다

use crate::arch::x86_64::gdt::{USER_CS, USER_DS};

/// 사용자 PML4 를 활성화하고 Ring 3 사용자 엔트리로 강하함. 결코 반환하지 않음.
///
/// # Arguments
/// `cr3` - 사용자 PML4 물리 주소
/// `rip` - 사용자 엔트리 포인트 가상 주소
/// `rsp` - 사용자 스택 최상단 가상 주소
///
/// # Safety
/// - `cr3` 는 커널 상위 절반 매핑을 inherit 한 유효 PML4 물리 주소여야 함.
/// - 호출 전에 `syscall::install()` + `tss::set_rsp0()` 가 완료되어 있어야 함.
/// - 인터럽트 비활성(CLI) 상태에서 호출 권장 (iretq 가 RFLAGS=0x202 로 IF=1 설정).
pub unsafe fn enter_user(cr3: u64, rip: u64, rsp: u64) -> ! {
    // SAFETY: 아래 asm 블록은 단일 atomic 시퀀스로 CR3 적재, swapgs, iretq 순으로
    //         실행하며 사이에 어떤 high-level 연산도 끼지 않고, iretq 가 RFLAGS =
    //         0x202 (IF=1, reserved=1) 와 CS:RIP, SS:RSP 를 적재하여 Ring 3 으로 강하함
    unsafe {
        core::arch::asm!(
            // 1. 사용자 PML4 활성화
            "mov cr3, {cr3}",
            // 2. swapgs: 커널 GS=&PerCpu 를 KERNEL_GS_BASE 로,
            //            KERNEL_GS_BASE(=0) 를 GS_BASE 로 (사용자 GS=0)
            "swapgs",
            // 3. iretq 스택 frame: 역순 push (SS, RSP, RFLAGS, CS, RIP)
            "push {ss}",
            "push {rsp}",
            "push 0x202",                       // RFLAGS = IF=1 + bit1
            "push {cs}",
            "push {rip}",
            "iretq",
            cr3 = in(reg) cr3,
            ss  = in(reg) USER_DS as u64,
            cs  = in(reg) USER_CS as u64,
            rsp = in(reg) rsp,
            rip = in(reg) rip,
            options(noreturn),
        );
    }
}
