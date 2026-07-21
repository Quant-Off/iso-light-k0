//! 본 모듈은 aarch64 `SVC #0` 기반 syscall 진입 경로와 디스패처를 구현합니다.
//!
//! # Features
//! x86_64 `syscall`/`sysret` naked stub 을 role-match 하되 인코딩은 divergent 합니다.
//! 예외 벡터 테이블의 "lower EL AArch64 synchronous" 엔트리(vectors.rs
//! `aarch64_sync_lower_el`)가 `aarch64_svc_entry` 로 분기하면 ESR_EL1.EC==0b010101
//! (SVC from AArch64)을 확인하고, 사용자 컨텍스트를 arch-중립 `SyscallContext`
//! 레이아웃(pc/flags/num/arg0..arg5)으로 스택에 저장한 뒤 `aarch64_dispatch(&mut ctx)`
//! 를 호출합니다. 복귀 시 반환값을 X0 에 적재하고 `eret`(x86 sysretq 대응)로 EL0 로
//! 돌아갑니다.
//!
//! # ABI 등가 (ARM-08)
//! X0=번호(x86 RAX), X1..X6=arg0..arg5(x86 RDI/RSI/RDX/R10/R8/R9), 반환 X0 으로
//! x86 syscall/sysret 과 byte-diff 0 arg 슬롯/errno 표면을 성립시킵니다.
//!
//! # DIVERGENCE (10-PATTERNS L395-399)
//!   - GS-base 컨텍스트 전환 부재: 예외 진입 시 SP_EL1(커널 스택)이 자동 전환됨.
//!   - `install()` 은 사실상 no-op: 벡터는 VBAR_EL1 로 이미 등록됨(MSR 설치 불요).
//!   - PerCpu(x86 gs:0x00/0x08): BSP 단일 코어이므로 정적/SP_EL1 기반.
//!
//! # Authors
//! Q. T. Felix

use core::arch::global_asm;

use zeroize::volatile::secure_zero;

// arch-중립 syscall 표면을 re-export 하여 `crate::syscall::{...}` 소비 경로를
// 보존함(x86 syscall.rs 와 대칭). SyscallContext 는 아래 aarch64_svc_entry 의
// store 순서와 동일 레이아웃으로 결합됨.
pub use crate::arch::common::syscall::{
    SyscallContext, SyscallError, SyscallNum, is_user_address,
};

//
// SVC #0 진입 asm (x86 naked syscall_entry 대응, 10-RESEARCH Pattern 4)
//
// 벡터 sync_lower_el 진입 -> ESR_EL1.EC==0b010101 확인 -> ctx save -> dispatch -> eret.
// SyscallContext 레이아웃: pc[+0] flags[+8] num[+16] arg0[+24] arg1[+32] arg2[+40]
//                          arg3[+48] arg4[+56] arg5[+64] (72 byte, 16-정렬 80 예약)
//
global_asm!(
    r#"
    .section .text,"ax",%progbits
    .global aarch64_svc_entry
aarch64_svc_entry:
    // ESR_EL1.EC[31:26] == 0b010101 (0x15, SVC from AArch64) 정당성 검증
    mrs  x9, esr_el1
    lsr  x9, x9, #26
    and  x9, x9, #0x3f
    cmp  x9, #0x15
    b.ne aarch64_default_exception     // SVC 아니면 기본 핸들러로 fail-stop

    // ctx save (SyscallContext 레이아웃)
    sub  sp, sp, #80
    mrs  x9, elr_el1
    str  x9, [sp, #0]                  // pc  <- ELR_EL1 (x86 RCX/RIP)
    mrs  x9, spsr_el1
    str  x9, [sp, #8]                  // flags <- SPSR_EL1 (x86 R11/RFLAGS)
    str  x0, [sp, #16]                 // num  <- X0 (x86 RAX)
    stp  x1, x2, [sp, #24]             // arg0 arg1 <- X1 X2 (x86 RDI RSI)
    stp  x3, x4, [sp, #40]             // arg2 arg3 <- X3 X4 (x86 RDX R10)
    stp  x5, x6, [sp, #56]             // arg4 arg5 <- X5 X6 (x86 R8 R9)

    mov  x0, sp                        // arg0 = &mut SyscallContext
    bl   aarch64_dispatch

    // ctx restore + eret (x86 sysretq 대응)
    ldr  x9, [sp, #0]
    msr  elr_el1, x9
    ldr  x9, [sp, #8]
    msr  spsr_el1, x9
    ldr  x0, [sp, #16]                 // 반환값 <- num 슬롯 (x86 RAX)
    ldp  x1, x2, [sp, #24]
    ldp  x3, x4, [sp, #40]
    ldp  x5, x6, [sp, #56]
    add  sp, sp, #80
    eret
"#
);

//
// syscall 인프라 설치 (x86 STAR/LSTAR/CSTAR/FMASK/KernelGsBase MSR 대응)
//

/// aarch64 syscall 진입 인프라 설치. x86 divergence 로 사실상 no-op.
///
/// SVC 진입 벡터는 boot_stub `el1_entry` + `vectors::init` 이 VBAR_EL1 로 이미
/// 등록하므로 별도 MSR 설치가 불요함. BSP 단일 코어 PerCpu 는 정적/SP_EL1 기반.
///
/// # Safety
/// 부팅 초기 단일 코어 시퀀스에서 1 회만 호출.
#[allow(dead_code)]
pub unsafe fn install(_kernel_stack_top: u64) {}

//
// 디스패처 (x86 dispatch 로직 재사용, arch/common SyscallNum 매칭)
//

/// 사용자 컨텍스트를 인자로 받아 syscall 번호별 핸들러를 호출함.
///
/// `ctx.num` 은 호출 시 syscall 번호이며, 반환 시 결과값으로 덮어씀. 음수 결과는
/// `SyscallError` 매핑. hsm_registry/air_gap 핸들러는 arch-중립 소비로 x86 과 공용.
#[unsafe(no_mangle)]
extern "C" fn aarch64_dispatch(ctx: &mut SyscallContext) {
    let num = ctx.num;
    let result: u64 = match num {
        x if x == SyscallNum::Exit as u64 => sys_exit(ctx.arg0),
        x if x == SyscallNum::Write as u64 => sys_write(ctx.arg0, ctx.arg1, ctx.arg2),
        x if x == SyscallNum::GetRandom as u64 => sys_getrandom(ctx.arg0, ctx.arg1),
        x if x == SyscallNum::HsmAttach as u64 => crate::hsm_registry::handle_attach(ctx),
        x if x == SyscallNum::HsmDetach as u64 => crate::hsm_registry::handle_detach(ctx),
        x if x == SyscallNum::HsmEnumerate as u64 => crate::hsm_registry::handle_enumerate(ctx),
        x if x == SyscallNum::HsmWrite as u64 => crate::hsm_registry::handle_write(ctx),
        x if x == SyscallNum::HsmRelay as u64 => crate::hsm_registry::handle_relay(ctx),
        x if x == SyscallNum::HsmRead as u64 => crate::hsm_registry::handle_read(ctx),
        #[cfg(feature = "smoke")]
        x if x == SyscallNum::AttestFixtureExport as u64 => {
            crate::handle_attest_fixture_export(ctx)
        }
        #[cfg(feature = "tls-external")]
        x if x == SyscallNum::NetworkCapTake as u64 => crate::air_gap::take_network_cap(ctx),
        x if x == SyscallNum::AuditCapTake as u64 => crate::air_gap::take_audit_read_cap(ctx),
        x if x == SyscallNum::HsmStatus as u64 => crate::air_gap::handle_status(ctx),
        x if x == SyscallNum::IpcCall as u64
            || x == SyscallNum::IpcRecv as u64
            || x == SyscallNum::IpcReply as u64
            || x == SyscallNum::CapRequest as u64 =>
        {
            SyscallError::Unknown.as_rax()
        }
        _ => SyscallError::Unknown.as_rax(),
    };
    ctx.num = result;
}

//
// 핸들러 (x86 sys_* 와 role-match, aarch64 백엔드)
//

/// 사용자 프로세스 종료. 현재는 BSP 단일 프로세스 가정으로 wfi 정지(x86 cli+hlt 대응).
fn sys_exit(_status: u64) -> u64 {
    crate::arch::aarch64::cpu::halt_loop()
}

/// `write(fd, buf_ptr, len)`. fd 는 현재 stderr(2) 만 지원하며 PL011 콘솔로 출력.
///
/// 사용자 메모리 검증: 주소 dual-range + 길이 한도(8 KiB) + PAN(stac/clac) 창 최소화.
fn sys_write(fd: u64, buf_ptr: u64, len: u64) -> u64 {
    if fd != 2 {
        return SyscallError::BadArg.as_rax();
    }
    const MAX_LEN: u64 = 8 * 1024;
    if len > MAX_LEN {
        return SyscallError::BadArg.as_rax();
    }
    if !is_user_address(buf_ptr) || !is_user_address(buf_ptr.saturating_add(len)) {
        return SyscallError::BadAddress.as_rax();
    }

    let mut stack_buf = [0u8; 256];
    let mut remaining = len as usize;
    let mut src = buf_ptr as *const u8;
    while remaining > 0 {
        let chunk = remaining.min(stack_buf.len());
        // SAFETY 주소/길이 검증 완료 PAN(user_access) 창 최소화 후 사용자 read
        unsafe {
            crate::arch::aarch64::cpu::stac();
            core::ptr::copy_nonoverlapping(src, stack_buf.as_mut_ptr(), chunk);
            crate::arch::aarch64::cpu::clac();
        }
        // 콘솔 출력은 debug 빌드에서만 (release 는 사일런트, x86 divergence 계승)
        #[cfg(debug_assertions)]
        // SAFETY stack_buf[..chunk] 는 방금 채워진 범위 PL011 콘솔 emit
        unsafe {
            crate::arch::aarch64::console::write_bytes(&stack_buf[..chunk]);
        }
        // SAFETY 인덱스만 전진
        src = unsafe { src.add(chunk) };
        remaining -= chunk;
    }
    len
}

/// `getrandom(buf_ptr, len)`. 커널 DRBG 출력.
fn sys_getrandom(buf_ptr: u64, len: u64) -> u64 {
    const MAX_LEN: u64 = 4096;
    if len == 0 || len > MAX_LEN {
        return SyscallError::BadArg.as_rax();
    }
    if !is_user_address(buf_ptr) || !is_user_address(buf_ptr.saturating_add(len)) {
        return SyscallError::BadAddress.as_rax();
    }
    let mut tmp = [0u8; 256];
    let mut remaining = len as usize;
    let mut dst = buf_ptr as *mut u8;
    while remaining > 0 {
        let chunk = remaining.min(tmp.len());
        // SAFETY 단일 코어 부팅 초기 또는 정적 동기화 보장 환경에서만 DRBG 접근
        match unsafe { crate::capability::rand_bytes(&mut tmp[..chunk]) } {
            Ok(()) => {}
            Err(_) => return SyscallError::Internal.as_rax(),
        }
        // SAFETY 사용자 메모리 write 검증 완료 PAN 창 최소화
        unsafe {
            crate::arch::aarch64::cpu::stac();
            core::ptr::copy_nonoverlapping(tmp.as_ptr(), dst, chunk);
            crate::arch::aarch64::cpu::clac();
            dst = dst.add(chunk);
        }
        remaining -= chunk;
    }
    // 임시 버퍼 zero 화 (entropy 보호)
    // SAFETY tmp 는 256B 스택 버퍼 슬라이스 길이만큼 유효
    unsafe {
        secure_zero(tmp.as_mut_ptr(), tmp.len());
    }
    len
}
