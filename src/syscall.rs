//! `syscall`/`sysret` 기반 시스템콜 진입 경로와 디스패처를 구현한 모듈입니다.
//!
//! # 보안 모델
//!   - GDT 레이아웃은 `boot.rs` 의 정의를 그대로 사용하며, `STAR` 는
//!     `SYSCALL_CS_BASE`/`SYSRET_CS_BASE` 두 상수로 결정됨.
//!   - `IA32_FMASK`(SFMASK) 는 syscall 진입 시 RFLAGS 에서 클리어할 비트
//!     마스크로, IF/TF/AC/DF/NT/IOPL 을 모두 0 으로 강제하여 사용자가 들고
//!     온 EFLAGS 가 커널 동작에 영향을 주지 못하게 함.
//!   - per-CPU 영역(`PerCpu`)은 `IA32_KERNEL_GS_BASE` 에 적재되어 있고,
//!     `swapgs` 후 GS-relative 로 접근됨. `kernel_stack_top`(gs:0x00) 과
//!     `user_rsp_save`(gs:0x08) 두 슬롯만 사용함.
//!   - 사용자 메모리는 SMAP 가 차단하므로, 디스패처가 사용자 포인터를 다룰
//!     때는 `cpu::stac()` 직후 `cpu::clac()` 로 즉시 닫고 항상 길이/주소
//!     검증을 거침.
//!
//! # 진입 시퀀스 (`syscall` 명령)
//!   1. CPU: CS = STAR[47:32] = `KERNEL_CS`, SS = `KERNEL_DS`, RCX = RIP,
//!      R11 = RFLAGS, RFLAGS &= !FMASK.
//!   2. asm stub: `swapgs` → `mov gs:[8], rsp` → `mov rsp, gs:[0]`.
//!   3. asm stub: 9 개 GPR + RIP/RFLAGS 를 push 하여 `SyscallContext` 구성.
//!   4. asm stub: `call dispatch(ctx_ptr)` (System V ABI).
//!   5. dispatch: `ctx.rax` 에 결과 작성.
//!   6. asm stub: 컨텍스트 pop → `mov rsp, gs:[8]` → `swapgs` → `sysretq`.
//!
//! # 사용자 ABI
//!   - 호출 번호: RAX
//!   - 인자 0..5: RDI, RSI, RDX, R10, R8, R9 (Linux 호환; RCX 는 RIP 보존)
//!   - 반환: RAX (음수: `SyscallError` 음수 매핑)
//!   - 보존: RBX, RBP, R12-R15 (System V callee-saved)
//!
//! # Authors
//! Q. T. Felix

use core::arch::naked_asm;

use zeroize::volatile::secure_zero;

use crate::boot::{SYSCALL_CS_BASE, SYSRET_CS_BASE};
use crate::cpu::{IA32_EFER, rdmsr, wrmsr};

//
// MSR 인덱스 (AMD64 APM Vol.2 §6.1)
//

/// `STAR`: SYSCALL/SYSRET 셀렉터 베이스 + 32-bit syscall EIP
const IA32_STAR: u32 = 0xC000_0081;
/// `LSTAR`: 64-bit 모드 syscall 진입 RIP
const IA32_LSTAR: u32 = 0xC000_0082;
/// `CSTAR`: compat-mode syscall 진입 RIP (32-bit 사용자, 본 커널은 미사용)
const IA32_CSTAR: u32 = 0xC000_0083;
/// `SFMASK` (IA32_FMASK): syscall 진입 시 RFLAGS 마스크
const IA32_FMASK: u32 = 0xC000_0084;
/// 현재 활성 GS_BASE (커널 모드에서는 `&PerCpu`, 사용자 모드에서는 사용자 TLS)
const IA32_GS_BASE: u32 = 0xC000_0101;
/// `swapgs` 명령으로 `IA32_GS_BASE` 와 교환되는 백업 슬롯
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// SFMASK 적용 비트: 사용자가 들고 온 위험 RFLAGS 비트를 syscall 진입에서
/// 즉시 클리어. (SDM Vol.3A §3.4.3.1, AMD64 APM Vol.2 §6.1.4)
///
/// 클리어 항목:
///   - bit  9 IF  : 인터럽트 활성. 0 = 진입 즉시 인터럽트 차단
///   - bit  8 TF  : 단일 스텝 트랩
///   - bit 18 AC  : SMAP 우회 플래그 (사용자가 임의로 설정 차단)
///   - bit 10 DF  : 문자열 명령 방향 (커널은 항상 forward 가정)
///   - bit 14 NT  : Nested Task
///   - bits 12..13 IOPL : I/O 권한 레벨 (사용자 = 0 강제)
const FMASK_BITS: u64 = (1 << 9)         // IF
    | (1 << 8)                            // TF
    | (1 << 18)                           // AC
    | (1 << 10)                           // DF
    | (1 << 14)                           // NT
    | (3 << 12); // IOPL

//
// per-CPU 영역
//

/// `swapgs` 로 GS:base 에 적재되는 BSP per-CPU 영역.
///
/// asm stub 이 `gs:0x00` / `gs:0x08` 오프셋에 의존하므로 필드 순서를 절대
/// 변경하지 말 것.
#[repr(C)]
pub struct PerCpu {
    /// gs:0x00 — 커널 스택 최상단 (syscall 진입 시 RSP 로 로드)
    pub kernel_stack_top: u64,
    /// gs:0x08 — 사용자 RSP 임시 저장소 (syscall stub 내부 전용)
    pub user_rsp_save: u64,
}

const _: () = assert!(core::mem::offset_of!(PerCpu, kernel_stack_top) == 0);
const _: () = assert!(core::mem::offset_of!(PerCpu, user_rsp_save) == 8);

/// BSP per-CPU 인스턴스. SMP 도입 시 코어별 배열로 확장.
// SAFETY: 부팅 초기 단일 코어, install() 에서 한 번만 채워짐.
static mut BSP_PER_CPU: PerCpu = PerCpu {
    kernel_stack_top: 0,
    user_rsp_save: 0,
};

//
// SyscallContext (asm 과 레이아웃 결합)
//

/// `syscall` 진입 stub 이 스택에 push 한 사용자 컨텍스트 스냅샷.
///
/// 필드는 push 순서의 *역순* 으로 선언되어 메모리 레이아웃 = stub 의 stack
/// 모양이 됨. asm 이 RSP+0 으로 전달하므로 `#[repr(C)]` 가 필수.
#[repr(C)]
pub struct SyscallContext {
    pub rip: u64,    // [+0]  RCX (사용자 RIP)
    pub rflags: u64, // [+8]  R11 (사용자 RFLAGS)
    pub rax: u64,    // [+16] syscall 번호 / 반환값
    pub rdi: u64,    // [+24] arg0
    pub rsi: u64,    // [+32] arg1
    pub rdx: u64,    // [+40] arg2
    pub r10: u64,    // [+48] arg3 (RCX 자리 대용)
    pub r8: u64,     // [+56] arg4
    pub r9: u64,     // [+64] arg5
}

//
// syscall 번호
//

/// 알려진 syscall 번호 목록.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum SyscallNum {
    /// 사용자 프로세스 정상 종료
    Exit = 0,
    /// `write(fd, buf, len)` — 현재는 fd=2(stderr) → VGA 출력만 지원
    Write = 1,
    /// `ipc_call(cap_ptr, msg_type, payload_ptr, payload_len, reply_buf, reply_cap)`
    IpcCall = 2,
    /// `ipc_recv(endpoint_id, buf_ptr, buf_cap)`
    IpcRecv = 3,
    /// `ipc_reply(endpoint_id, reply_type, payload_ptr, payload_len)`
    IpcReply = 4,
    /// `getrandom(buf, len, flags)` — 커널 DRBG 출력
    GetRandom = 5,
    /// `cap_request(endpoint_id, rights)` — 커널이 정책 검증 후 발급
    CapRequest = 6,
    HsmAttach = 7,    // Phase 1: 정적 HSM 슬롯 부착 (비인증; Phase 5 attestation gate 예정)
    HsmDetach = 8,    // Phase 1: HSM 슬롯 해제 + zeroize (post-attach CAP 검사)
    HsmEnumerate = 9, // Phase 1: 부착된 슬롯 enumerate (post-attach CAP 검사)
    HsmWrite = 10,    // Phase 3: USE cap → SoftHSM mode-aware write (D-02)
    HsmRelay = 11,    // Phase 3: src(RELAY_SRC) + dst(RELAY_DST) dual-cap kernel-internal transfer (D-03)
    HsmRead = 12,     // Phase 4: USE cap → wire frame response 회수 (D-06)
}

/// 사용자에 노출되는 음수 에러 코드 (Linux errno 와 호환되지 않음, 자체 ABI).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i64)]
pub enum SyscallError {
    Unknown = -1,
    BadArg = -2,
    BadAddress = -3,
    Denied = -4,
    NoMessage = -5,
    Internal = -6,
}

impl SyscallError {
    #[inline]
    pub const fn as_rax(self) -> u64 {
        self as i64 as u64
    }
}

//
// MSR 설치
//

/// syscall 인프라(STAR/LSTAR/CSTAR/FMASK + KernelGsBase)를 한 번 셋업.
///
/// 호출 전 보장 조건:
///   - `cpu::enable_security_bits()` 로 `IA32_EFER.SCE = 1` 가 설정되어 있을 것
///   - `kernel_stack_top` 이 16-byte 정렬된 유효한 커널 스택 최상단 VMA 일 것
///   - GDT 가 `boot::init_gdt()` 로 로드되어 있을 것
///
/// # Safety
/// 단일 코어 부팅 초기에서만 호출. SMP 전환 시에는 코어별 PerCpu 와
/// `IA32_KERNEL_GS_BASE` 를 코어마다 재설정해야 함.
pub unsafe fn install(kernel_stack_top: u64) {
    // 1. PerCpu 의 커널 스택 슬롯 채우기
    // SAFETY: 부팅 초기 단일 코어
    unsafe {
        (*(&raw mut BSP_PER_CPU)).kernel_stack_top = kernel_stack_top;
        (*(&raw mut BSP_PER_CPU)).user_rsp_save = 0;
    }

    // 2. STAR: SYSCALL/SYSRET 셀렉터 베이스
    //   - bits[31:0]  = 32-bit SYSCALL EIP (미사용, 0)
    //   - bits[47:32] = SYSCALL_CS_BASE
    //   - bits[63:48] = SYSRET_CS_BASE
    let star: u64 = ((SYSCALL_CS_BASE as u64) << 32) | ((SYSRET_CS_BASE as u64) << 48);

    // 3. LSTAR: 64-bit 모드 syscall 진입 주소
    let lstar: u64 = syscall_entry as *const () as u64;

    // 4. CSTAR: 32-bit 사용자는 미지원 → 안전하게 0 (compat-mode syscall 시 #UD)
    let cstar: u64 = 0;

    // 5. KernelGsBase: swapgs 로 교체될 BSP per-CPU 베이스
    let per_cpu_addr: u64 = (&raw const BSP_PER_CPU) as u64;

    // SAFETY: Ring 0 단일 코어 부팅 초기, EFER.SCE 활성 가정
    //
    // GS_BASE 모델:
    //   - 커널 모드: IA32_GS_BASE = &PerCpu  (현재 활성 GS)
    //                IA32_KERNEL_GS_BASE = 0  (사용자 모드의 GS 백업)
    //   - 사용자 모드 (iretq 직전 swapgs 후):
    //                IA32_GS_BASE = 0
    //                IA32_KERNEL_GS_BASE = &PerCpu
    //   - syscall stub 의 swapgs 가 두 값을 다시 교환하여 진입 즉시 GS = &PerCpu.
    unsafe {
        wrmsr(IA32_STAR, star);
        wrmsr(IA32_LSTAR, lstar);
        wrmsr(IA32_CSTAR, cstar);
        wrmsr(IA32_FMASK, FMASK_BITS);
        wrmsr(IA32_GS_BASE, per_cpu_addr);
        wrmsr(IA32_KERNEL_GS_BASE, 0);
        // EFER.SCE 가 정말 켜져 있는지 재확인 (방어적)
        let efer = rdmsr(IA32_EFER);
        debug_assert!(
            efer & 1 != 0,
            "EFER.SCE must be enabled before syscall::install()"
        );
    }
}

//
// naked syscall entry stub
//
// 호출 규약 (CPU 가 자동 수행):
//   - RCX  ← user RIP
//   - R11  ← user RFLAGS
//   - RFLAGS &= ~FMASK_BITS
//   - CS = STAR[47:32], SS = STAR[47:32] + 8
//   - RSP 는 사용자 RSP 그대로 유지 (스왑 안 됨)
//
// 반환 (`sysretq`):
//   - CS = STAR[63:48] + 16 (RPL=3), SS = STAR[63:48] + 8
//   - RIP ← RCX, RFLAGS ← R11
//

/// syscall 진입 stub. 사용자 컨텍스트를 스택에 saved 한 뒤 dispatch 호출.
///
/// # Safety
/// 본 함수는 LSTAR MSR 의 타깃이며 직접 호출 금지. naked function 이므로
/// 일반 함수 호출 규약을 따르지 않음.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_entry() -> ! {
    naked_asm!(
        // ── 1. GS 스왑 + 스택 전환 ─────────────────────────────────
        "swapgs",
        "mov gs:[8], rsp",          // user_rsp_save ← user RSP
        "mov rsp, gs:[0]",          // RSP ← kernel_stack_top

        // ── 2. SyscallContext 구성 (push 순서 = struct 역순) ───────
        // struct: rip, rflags, rax, rdi, rsi, rdx, r10, r8, r9
        // push   : r9, r8, r10, rdx, rsi, rdi, rax, r11, rcx
        "push r9",
        "push r8",
        "push r10",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rax",
        "push r11",                 // user RFLAGS
        "push rcx",                 // user RIP

        // ── 3. 16-byte 스택 정렬 유지 + dispatch 호출 ──────────────
        // 9 × 8B = 72B push 후 RSP 정렬은 호출자 정렬에 따라 결정.
        // 진입 시 사용자 RSP 가 임의 정렬일 수 있으나, 우리는 gs:[0] 로
        // 강제 전환했으므로 install() 의 16B 정렬을 신뢰함.
        "mov rdi, rsp",             // arg0 = ctx ptr
        "call {dispatch}",

        // ── 4. SyscallContext pop ─────────────────────────────────
        "pop rcx",                  // user RIP 복원
        "pop r11",                  // user RFLAGS 복원
        "pop rax",                  // syscall 반환값
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop r10",
        "pop r8",
        "pop r9",

        // ── 5. 스택 복원 + sysret ─────────────────────────────────
        "mov rsp, gs:[8]",          // user RSP 복원
        "swapgs",
        "sysretq",

        dispatch = sym dispatch,
    )
}

//
// 디스패처
//

/// 사용자 컨텍스트를 인자로 받아 syscall 번호별 핸들러를 호출함.
///
/// `ctx.rax` 는 호출 시 syscall 번호이며, 반환 시 결과값으로 덮어씀.
/// 음수 결과는 `SyscallError` 매핑.
#[unsafe(no_mangle)]
extern "C" fn dispatch(ctx: &mut SyscallContext) {
    let num = ctx.rax;
    let result: u64 = match num {
        x if x == SyscallNum::Exit as u64 => sys_exit(ctx.rdi),
        x if x == SyscallNum::Write as u64 => sys_write(ctx.rdi, ctx.rsi, ctx.rdx),
        x if x == SyscallNum::GetRandom as u64 => sys_getrandom(ctx.rsi, ctx.rdx),
        x if x == SyscallNum::HsmAttach as u64 => crate::hsm_registry::handle_attach(ctx),
        x if x == SyscallNum::HsmDetach as u64 => crate::hsm_registry::handle_detach(ctx),
        x if x == SyscallNum::HsmEnumerate as u64 => crate::hsm_registry::handle_enumerate(ctx),
        x if x == SyscallNum::HsmWrite as u64 => crate::hsm_registry::handle_write(ctx),
        x if x == SyscallNum::HsmRelay as u64 => crate::hsm_registry::handle_relay(ctx),
        x if x == SyscallNum::HsmRead as u64 => crate::hsm_registry::handle_read(ctx),
        // IpcCall/IpcRecv/IpcReply/CapRequest 는 Phase B 에서 와이어업.
        x if x == SyscallNum::IpcCall as u64
            || x == SyscallNum::IpcRecv as u64
            || x == SyscallNum::IpcReply as u64
            || x == SyscallNum::CapRequest as u64 =>
        {
            SyscallError::Unknown.as_rax()
        }
        _ => SyscallError::Unknown.as_rax(),
    };
    ctx.rax = result;
}

//
// 핸들러 — Phase A 범위
//

/// 사용자 프로세스 종료. 현재는 BSP 단일 프로세스 가정으로 단순 halt.
///
/// Phase B 에서 process slot 을 도입하면 슬롯을 free 하고 스케줄러로 양보함.
fn sys_exit(_status: u64) -> u64 {
    // SAFETY: VGA 직접 접근은 debug 빌드에서만 허용된 경로. 단일 코어 가정.
    #[cfg(all(target_arch = "x86_64", debug_assertions))]
    unsafe {
        crate::vga::println(
            b"[iso-light-k0] user process exit",
            crate::vga::Color::LightGray,
        );
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: cli + hlt 무한 루프는 항상 안전한 정지 명령
    unsafe {
        loop {
            core::arch::asm!("cli", "hlt", options(nostack, preserves_flags));
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    loop {}
}

/// `write(fd, buf_ptr, len)`. fd 는 현재 stderr(2) 만 지원하며 VGA 로 출력.
///
/// 사용자 메모리 검증:
///   - `buf_ptr` 가 사용자 가상 주소 범위(canonical lower half) 인지 확인
///   - `len` 이 합리적 한도(8 KiB) 이하인지 확인
///   - SMAP 활성 시 `stac()` ↔ `clac()` 로 접근 윈도우를 최소화
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

    // SAFETY: 사용자 메모리 read 만 수행. 길이/주소 검증 완료. SMAP 윈도우 최소화.
    let mut stack_buf = [0u8; 256];
    let mut remaining = len as usize;
    let mut src = buf_ptr as *const u8;
    while remaining > 0 {
        let chunk = remaining.min(stack_buf.len());
        // SAFETY: 위 검증 + SMAP stac/clac 윈도우
        unsafe {
            crate::cpu::stac();
            core::ptr::copy_nonoverlapping(src, stack_buf.as_mut_ptr(), chunk);
            crate::cpu::clac();
        }
        // VGA 출력은 debug 빌드에서만. release 빌드는 사일런트로 동작 (사용자
        // 메모리는 검증되었지만 VGA 자체가 release 에서 빌드되지 않음).
        // SAFETY: stack_buf[..chunk] 는 방금 채워진 범위
        #[cfg(debug_assertions)]
        unsafe {
            crate::vga::print(&stack_buf[..chunk], crate::vga::Color::White);
        }
        // SAFETY: 인덱스만 전진
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
        // SAFETY: 단일 코어 부팅 초기 또는 정적 동기화 보장 환경에서만
        //         DRBG 접근. 현 단계에서는 BSP 가 dispatch 함수를 직렬 실행함.
        match unsafe { crate::capability::rand_bytes(&mut tmp[..chunk]) } {
            Ok(()) => {}
            Err(_) => return SyscallError::Internal.as_rax(),
        }
        // SAFETY: 사용자 메모리 write. 검증 완료.
        unsafe {
            crate::cpu::stac();
            core::ptr::copy_nonoverlapping(tmp.as_ptr(), dst, chunk);
            crate::cpu::clac();
            dst = dst.add(chunk);
        }
        remaining -= chunk;
    }
    // 임시 버퍼는 zero 화 (entropy 보호)
    // SAFETY: tmp 는 256B 스택 버퍼, 슬라이스 길이만큼 유효
    unsafe {
        secure_zero(tmp.as_mut_ptr(), tmp.len());
    }
    len
}

//
// 사용자 주소 검증
//

/// `va` 가 사용자 가상 주소(canonical lower half, PML4[0..255]) 범위인지.
///
/// 사용자 매핑은 0x0..0x0000_8000_0000_0000 범위에 위치. 그 외(커널 직접
/// 선형 매핑·커널 세그먼트 등)는 차단.
#[inline]
pub fn is_user_address(va: u64) -> bool {
    va < 0x0000_8000_0000_0000
}
