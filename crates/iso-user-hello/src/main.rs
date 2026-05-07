//! iso-light-k0 의 Ring 3 진입을 검증하는 최소 사용자 프로그램입니다.
//!
//! 진입 직후:
//!   1. `sys_write(2, msg, msg_len)` — 커널이 VGA 로 메시지 출력
//!   2. `sys_getrandom(buf, 16)` — 커널 DRBG 에서 16 바이트 수신
//!   3. `sys_write(2, hex_buf, 32)` — 16-byte 엔트로피를 hex 16진수로 출력
//!   4. `sys_exit(0)` — 정상 종료
//!
//! 본 프로그램은 `no_std` + `no_alloc` Rust 정적 ELF 로 빌드되며 어떤 외부
//! 의존성도 없습니다. iso-light-k0 가 정의한 syscall ABI 만 사용합니다.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

//
// syscall 번호 (iso-light-k0 src/syscall.rs::SyscallNum 와 동기 유지)
//

const SYS_EXIT: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_GETRANDOM: u64 = 5;

const STDERR: u64 = 2;

//
// syscall wrappers
//

#[inline(always)]
unsafe fn syscall1(num: u64, a0: u64) -> u64 {
    let ret: u64;
    // SAFETY: syscall ABI 는 RCX/R11 만 clobber. 호출자가 num/a0 의 의미를 보장.
    unsafe {
        asm!(
            "syscall",
            in("rax") num,
            in("rdi") a0,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
unsafe fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    // SAFETY: 동상
    unsafe {
        asm!(
            "syscall",
            in("rax") num,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn write_stderr(buf: &[u8]) -> u64 {
    // SAFETY: buf 는 정적 슬라이스, syscall ABI 만족
    unsafe { syscall3(SYS_WRITE, STDERR, buf.as_ptr() as u64, buf.len() as u64) }
}

#[inline(always)]
fn getrandom(buf: &mut [u8]) -> u64 {
    // SAFETY: buf.as_mut_ptr() 는 사용자 영역 가변 슬라이스
    unsafe { syscall3(SYS_GETRANDOM, 0, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

#[inline(always)]
fn exit(code: u64) -> ! {
    // SAFETY: sys_exit 는 반환하지 않음. 만약 반환하면 무한 hlt-동등 루프.
    unsafe {
        let _ = syscall1(SYS_EXIT, code);
    }
    loop {
        // SAFETY: 사용자 모드 hlt 는 #GP 를 일으키지만, sys_exit 가 반환하지
        //         않는 것을 가정하므로 이 루프는 도달 불가. 도달 시 안전망.
        unsafe {
            asm!("nop", options(nostack, preserves_flags));
        }
    }
}

//
// 진입점
//

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn write_hex(bytes: &[u8], out: &mut [u8]) -> usize {
    let mut w = 0;
    for &b in bytes {
        if w + 2 > out.len() {
            break;
        }
        out[w] = HEX_DIGITS[(b >> 4) as usize];
        out[w + 1] = HEX_DIGITS[(b & 0xF) as usize];
        w += 2;
    }
    w
}

/// 사용자 프로세스 진입점. iso-light-k0 의 `process::enter_ring3()` 가 본
/// 함수의 가상 주소를 ELF entry RIP 로 사용하여 iretq 후 점프함.
///
/// # Safety
/// 직접 호출 금지 — 이 함수는 사용자 모드 RIP 로만 진입해야 함. 함수가 끝나면
/// `exit()` 가 sys_exit 으로 종료하므로 `_start` 는 결코 반환하지 않음.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    write_stderr(b"[iso-user-hello] Ring 3 entry OK, calling sys_write...\n");

    let mut entropy = [0u8; 16];
    let n = getrandom(&mut entropy) as i64;
    if n != 16 {
        write_stderr(b"[iso-user-hello] sys_getrandom returned != 16, exiting with code 1\n");
        exit(1);
    }

    let mut hex = [0u8; 33];
    let len = write_hex(&entropy, &mut hex[..32]);
    hex[len] = b'\n';
    write_stderr(b"[iso-user-hello] entropy = ");
    write_stderr(&hex[..=len]);

    write_stderr(b"[iso-user-hello] all syscalls OK, exit(0)\n");
    exit(0);
}

//
// panic handler
//

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    write_stderr(b"[iso-user-hello] panic\n");
    exit(2);
}
