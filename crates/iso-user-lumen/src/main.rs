//! `lumen` 프로젝트의 elib-k0-nt 와이어 호환성을 Ring 3 사용자 공간에서
//! 실증하는 검증 프로그램입니다.
//!
//! 본 프로그램은 `lumen` 자체에는 의존하지 않습니다. 대신 lumen 이 사용하는
//! 것과 *완전히 동일한* `elib-k0-nt` 크레이트(`blake`, `ed25519`, `x25519`,
//! `aes`)를 직접 호출하여, 같은 입력에 대해 같은 비트 출력을 얻는다는
//! 사실로 호환성을 보장합니다 (lumen `KERNEL-COMPAT.md` §3 회귀 테스트의
//! Ring 3 결합 검증).
//!
//! 검증 항목:
//!   1. BLAKE3(고정 입력) 이 32-byte 다이제스트 hex 출력
//!   2. BLAKE3 keyed_derive(고정 키 + 메시지) 가 32-byte 출력
//!   3. Ed25519 결정성, 고정 시드 와 고정 메시지 로 64-byte 서명 hex 출력 및
//!      verify roundtrip
//!   4. X25519 ECDH, Alice(seed=AAAA…) 와 Bob(seed=BBBB…) 양방향 공유 비밀 일치
//!   5. AES-256-GCM round-trip, encrypt 후 decrypt 성공 및 평문 일치
//!
//! sys_write(STDERR=2) 로 결과를 보고하고 sys_exit(0/1) 으로 종료합니다.
//!
//! # 보안 고려사항
//!   - 사용자 영역에서 실행되므로 어떠한 호스트 OS API 도 사용 불가.
//!   - elib-k0-nt 의 `Secret<T>` / `secure_zero` 가 비밀 자료를 자동 소거.
//!   - 모든 출력은 hex 문자열로만 표시되며 비밀키는 출력하지 않음 (시드 출력
//!     은 결정성 검증에 필요하므로 의도적으로 노출).

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

use aes::AES256GCM;
use blake::{Blake3, ct_eq_slice};

//
// syscall 번호 (iso-light-k0 src/syscall.rs::SyscallNum 와 동기 유지)
//
const SYS_EXIT: u64 = 0;
const SYS_WRITE: u64 = 1;
const STDERR: u64 = 2;

#[inline(always)]
unsafe fn syscall1(num: u64, a0: u64) -> u64 {
    let ret: u64;
    // SAFETY: syscall ABI, RCX/R11 만 clobber
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
unsafe fn syscall4(num: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    // sys_hsm_attach 의 4번째 인자 (out_ptr) 를 r8 로 전달
    // src/hsm_registry.rs::handle_attach line 483 `let out_ptr = ctx.r8;` 와 ABI 일관
    // Linux 의 r10 미사용, iso-light-k0 syscall ABI 가 r8 슬롯 채택
    let ret: u64;
    // SAFETY: syscall3 와 동일 RCX/R11 만 clobber sysret 후 정상 복귀
    unsafe {
        asm!(
            "syscall",
            in("rax") num,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r8") a3,
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
    // SAFETY: 정적/유효 슬라이스, syscall ABI 만족
    unsafe { syscall3(SYS_WRITE, STDERR, buf.as_ptr() as u64, buf.len() as u64) }
}

#[inline(always)]
fn exit(code: u64) -> ! {
    // SAFETY: sys_exit 는 반환하지 않음
    unsafe {
        let _ = syscall1(SYS_EXIT, code);
    }
    loop {
        // SAFETY: 도달 불가 fail-safe
        unsafe {
            asm!("nop", options(nostack, preserves_flags));
        }
    }
}

//
// hex 출력 헬퍼
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

/// `prefix` + 32 바이트 hex + '\n' 을 한 번에 출력.
fn print_hex32(prefix: &[u8], bytes: &[u8; 32]) {
    write_stderr(prefix);
    let mut hex = [0u8; 65];
    let n = write_hex(bytes, &mut hex[..64]);
    hex[n] = b'\n';
    write_stderr(&hex[..=n]);
}

/// `prefix` + 64 바이트 hex + '\n' 을 한 번에 출력.
fn print_hex64(prefix: &[u8], bytes: &[u8; 64]) {
    write_stderr(prefix);
    let mut hex = [0u8; 129];
    let n = write_hex(bytes, &mut hex[..128]);
    hex[n] = b'\n';
    write_stderr(&hex[..=n]);
}

//
// 검증 #1: BLAKE3 (정상 모드)
//
fn check_blake3() {
    let input = b"iso-lumen-wire-compat-v1";
    let mut hasher = Blake3::new();
    hasher.update(input);
    let buf = match hasher.finalize() {
        Ok(b) => b,
        Err(_) => {
            write_stderr(b"[iso-user-lumen] BLAKE3 finalize FAILED\n");
            exit(1);
        }
    };
    let out = buf.as_slice();
    if out.len() != 32 {
        write_stderr(b"[iso-user-lumen] BLAKE3 output length != 32\n");
        exit(1);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(out);
    print_hex32(b"[iso-user-lumen] BLAKE3                = ", &bytes);
}

//
// 검증 #2: BLAKE3 keyed (lumen-channel KDF 와이어 형식)
//
fn check_blake3_keyed() {
    let key = [0xA5u8; 32];
    let input = b"iso-lumen-wire-compat-keyed";
    let mut hasher = Blake3::new_keyed(&key);
    hasher.update(input);
    let buf = match hasher.finalize() {
        Ok(b) => b,
        Err(_) => {
            write_stderr(b"[iso-user-lumen] BLAKE3-keyed finalize FAILED\n");
            exit(1);
        }
    };
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(buf.as_slice());
    print_hex32(b"[iso-user-lumen] BLAKE3-keyed          = ", &bytes);
}

//
// 검증 #3: Ed25519 결정성 + verify
//
fn check_ed25519() {
    let seed = [0x42u8; 32];
    let mut sk = ed25519::SecretKey::default();
    sk.init(&seed);
    let pk = ed25519::PublicKey::from(&sk);
    let msg = b"iso-lumen-wire-compat-ed25519";
    let sig = ed25519::sign(msg, &sk);

    print_hex32(b"[iso-user-lumen] Ed25519 PublicKey     = ", pk.as_bytes());
    print_hex64(b"[iso-user-lumen] Ed25519 Signature     = ", sig.as_bytes());

    if ed25519::verify(msg, &sig, &pk).is_ok() {
        write_stderr(b"[iso-user-lumen] Ed25519 verify OK\n");
    } else {
        write_stderr(b"[iso-user-lumen] Ed25519 verify FAILED\n");
        exit(1);
    }

    // 결정성 한 번 더, 같은 시드 와 메시지 로 같은 서명
    let sig2 = ed25519::sign(msg, &sk);
    if sig.as_bytes() == sig2.as_bytes() {
        write_stderr(b"[iso-user-lumen] Ed25519 deterministic OK\n");
    } else {
        write_stderr(b"[iso-user-lumen] Ed25519 NON-DETERMINISTIC (RFC 8032 violation)\n");
        exit(1);
    }
}

//
// 검증 #4: X25519 ECDH
//
fn check_x25519() {
    let alice_seed = [0xAAu8; 32];
    let bob_seed = [0xBBu8; 32];

    let mut alice_sk = x25519::SecretKey::default();
    alice_sk.init(&alice_seed);
    let mut bob_sk = x25519::SecretKey::default();
    bob_sk.init(&bob_seed);
    let alice_pk = alice_sk.public_key();
    let bob_pk = bob_sk.public_key();

    // 제자리 계산: 공유비밀은 호출자가 둔 SharedSecret 버퍼에 직접 기록됨
    let mut s_ab = x25519::SharedSecret::default();
    let mut s_ba = x25519::SharedSecret::default();
    if alice_sk.diffie_hellman_into(&bob_pk, &mut s_ab).is_err()
        || bob_sk.diffie_hellman_into(&alice_pk, &mut s_ba).is_err()
    {
        write_stderr(b"[iso-user-lumen] x25519 ECDH LOW-ORDER REJECTED\n");
        exit(1);
    }

    if s_ab.as_bytes() == s_ba.as_bytes() {
        let mut shared = [0u8; 32];
        shared.copy_from_slice(s_ab.as_bytes());
        print_hex32(b"[iso-user-lumen] x25519 ECDH shared    = ", &shared);
    } else {
        write_stderr(b"[iso-user-lumen] x25519 ECDH MISMATCH\n");
        exit(1);
    }
}

//
// 검증 #5: AES-256-GCM round-trip
//
fn check_aes256_gcm() {
    let key = [0xC3u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"iso-lumen-wire-compat-aad";
    let plaintext = b"hello-from-ring3-iso-user-lumen";

    let mut cipher = AES256GCM::default();
    cipher.init(&key);

    let mut ciphertext = [0u8; 31];
    let mut tag = [0u8; 16];
    if cipher
        .encrypt(&nonce, aad, plaintext, &mut ciphertext, &mut tag)
        .is_err()
    {
        write_stderr(b"[iso-user-lumen] AES-256-GCM encrypt FAILED\n");
        exit(1);
    }

    print_hex32(b"[iso-user-lumen] AES-GCM tag(left 32B) = ", &{
        // 16-byte tag 만 표시, 위 헬퍼는 32-byte 전제라 prefix 와 tag hex 를 직접 구성
        let mut tagbuf = [0u8; 32];
        tagbuf[..16].copy_from_slice(&tag);
        tagbuf
    });

    let mut decrypted = [0u8; 31];
    if cipher
        .decrypt(&nonce, aad, &ciphertext, &tag, &mut decrypted)
        .is_err()
    {
        write_stderr(b"[iso-user-lumen] AES-256-GCM decrypt rejected (tag mismatch)\n");
        exit(1);
    }
    if decrypted == *plaintext {
        write_stderr(b"[iso-user-lumen] AES-256-GCM round-trip OK\n");
    } else {
        write_stderr(b"[iso-user-lumen] AES-256-GCM plaintext MISMATCH\n");
        exit(1);
    }
}

//
// 검증 #6 Wire Contract 종단 검증 (8-step)
//
/// 종단 검증으로 Ring 3 lumen 이 wire contract 의 실 클라이언트로 동작함을 실증한다.
///
/// 8-step 시퀀스:
///   1) cap_blake3 = sys_hsm_attach(Software, init=[ROLE_BLAKE3=1])
///   2) cap_wire   = sys_hsm_attach(Ring3Process, init=EP_LUMEN_WIRE.to_le_bytes())
///   3) wire frame Blake3Hash 빌드 (16B header + 16B cap_blake3 + 12B input)
///   4) sys_hsm_write(cap_wire, frame, 44)
///   5) sys_hsm_read(cap_wire, response, 4096)
///   6) response header parse (magic / cmd / status / payload_len 검증)
///   7) elib-k0-nt Blake3::hash(input) 직접 호출로 expected 32B digest
///   8) ct_eq_slice 동일 비트 일치 검증 후 WIRE_PHASE4_OK marker 또는 WIRE_PHASE4_FAIL
fn wire_blake3_phase4_test() {
    const SYS_HSM_ATTACH: u64 = 7;
    const SYS_HSM_WRITE: u64 = 10;
    const SYS_HSM_READ: u64 = 12;
    const BUS_SOFTWARE: u64 = 0;
    const BUS_RING3PROCESS: u64 = 1;
    const ROLE_BLAKE3: u8 = 1;
    const EP_LUMEN_WIRE_RAW: u16 = 0x0003;
    const WIRE_FRAME_MAX_LOCAL: usize = 4096;

    // BSS 거주 buffer 로 8 KiB 스택 부담 회피
    static mut FRAME_BUF: [u8; WIRE_FRAME_MAX_LOCAL] = [0u8; WIRE_FRAME_MAX_LOCAL];
    static mut RESPONSE_BUF: [u8; WIRE_FRAME_MAX_LOCAL] = [0u8; WIRE_FRAME_MAX_LOCAL];

    // (1) cap_blake3 attach
    let init_blake3 = [ROLE_BLAKE3];
    let mut cap_blake3 = [0u8; 16];
    // SAFETY: init_blake3 / cap_blake3 는 stack-local 유효 슬라이스
    let rax = unsafe {
        syscall4(
            SYS_HSM_ATTACH,
            BUS_SOFTWARE,
            init_blake3.as_ptr() as u64,
            init_blake3.len() as u64,
            cap_blake3.as_mut_ptr() as u64,
        )
    };
    if (rax as i64) < 0 {
        write_stderr(b"WIRE_PHASE4_FAIL: cap_blake3 attach\n");
        exit(1);
    }

    // (2) cap_wire attach 로 EP_LUMEN_WIRE endpoint_exists 게이트 통과
    let init_wire = EP_LUMEN_WIRE_RAW.to_le_bytes();
    let mut cap_wire = [0u8; 16];
    // SAFETY: 동상, init_wire 는 2 byte stack array
    let rax = unsafe {
        syscall4(
            SYS_HSM_ATTACH,
            BUS_RING3PROCESS,
            init_wire.as_ptr() as u64,
            init_wire.len() as u64,
            cap_wire.as_mut_ptr() as u64,
        )
    };
    if (rax as i64) < 0 {
        write_stderr(b"WIRE_PHASE4_FAIL: cap_wire attach\n");
        exit(1);
    }

    // (3) Wire frame Blake3Hash build, postcard 우회 수동 byte layout
    let input: &[u8] = b"PHASE4_INPUT";
    let payload_len: u16 = 16 + input.len() as u16; // 28
    let frame_len: usize = 16 + payload_len as usize; // 44

    // SAFETY: BSP 단일 Ring 3 process, FRAME_BUF 동시 접근 없음
    unsafe {
        let buf = &mut *(&raw mut FRAME_BUF);
        buf[0..4].copy_from_slice(b"LWK0");
        buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // version = 1
        buf[6..8].copy_from_slice(&0x0010u16.to_le_bytes()); // cmd = Blake3Hash
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // req_id
        buf[12..14].copy_from_slice(&payload_len.to_le_bytes());
        buf[14..16].copy_from_slice(&0u16.to_le_bytes()); // request status = 0
        buf[16..32].copy_from_slice(&cap_blake3);
        buf[32..32 + input.len()].copy_from_slice(input);
    }

    // (4) sys_hsm_write(cap_wire, frame, 44)
    // SAFETY: FRAME_BUF 의 frame_len 길이 슬라이스만 노출, cap_wire 는 16 byte
    let rax = unsafe {
        let buf_ptr = (&raw const FRAME_BUF) as *const u8;
        syscall3(
            SYS_HSM_WRITE,
            cap_wire.as_ptr() as u64,
            buf_ptr as u64,
            frame_len as u64,
        )
    };
    if (rax as i64) < 0 {
        write_stderr(b"WIRE_PHASE4_FAIL: hsm_write\n");
        exit(1);
    }

    // (5) sys_hsm_read(cap_wire, response, 4096)
    // SAFETY: RESPONSE_BUF 의 WIRE_FRAME_MAX 윈도우만 노출
    let n = unsafe {
        let resp_ptr = (&raw mut RESPONSE_BUF) as *mut u8;
        syscall3(
            SYS_HSM_READ,
            cap_wire.as_ptr() as u64,
            resp_ptr as u64,
            WIRE_FRAME_MAX_LOCAL as u64,
        )
    };
    if (n as i64) < 0 {
        write_stderr(b"WIRE_PHASE4_FAIL: hsm_read\n");
        exit(1);
    }
    let n = n as usize;

    // (6) Response header parse, magic / cmd / status / payload_len 검증
    // SAFETY: 동상, RESPONSE_BUF 첫 16 byte read-only
    let (resp_magic, resp_cmd, resp_status, resp_payload_len) = unsafe {
        let buf = &*(&raw const RESPONSE_BUF);
        let m = [buf[0], buf[1], buf[2], buf[3]];
        let c = u16::from_le_bytes([buf[6], buf[7]]);
        let pl = u16::from_le_bytes([buf[12], buf[13]]);
        let s = u16::from_le_bytes([buf[14], buf[15]]);
        (m, c, s, pl)
    };
    if &resp_magic != b"LWK0"
        || resp_cmd != (0x0010u16 | 0x8000u16)
        || resp_status != 0
        || resp_payload_len != 32
        || n != 48
    {
        write_stderr(b"WIRE_PHASE4_FAIL: response header mismatch\n");
        exit(1);
    }

    // (7) elib-k0-nt::blake::Blake3 직접 호출로 expected 32B digest
    let mut hasher = Blake3::new();
    hasher.update(input);
    let expected = match hasher.finalize() {
        Ok(d) => d,
        Err(_) => {
            write_stderr(b"WIRE_PHASE4_FAIL: blake3 host\n");
            exit(1);
        }
    };
    let exp_slice = expected.as_slice();
    if exp_slice.len() != 32 {
        write_stderr(b"WIRE_PHASE4_FAIL: blake3 len\n");
        exit(1);
    }

    // (8) ct_eq_slice 동일 비트 일치 검증
    // SAFETY: RESPONSE_BUF[16..48] read-only 32 byte slice
    let eq: u8 = unsafe {
        let buf = &*(&raw const RESPONSE_BUF);
        ct_eq_slice(&buf[16..48], exp_slice).unwrap_u8()
    };
    if eq != 1 {
        write_stderr(b"WIRE_PHASE4_FAIL: digest mismatch\n");
        exit(1);
    }
    write_stderr(b"WIRE_PHASE4_OK\n");
}

//
// wire AttestSubmit / Status round-trip smoke (lumen client)
//
// 8-step 시퀀스:
//   (1) cap_wire attach (None-attest path, syscall arity 4 유지)
//   (2) sys_attest_fixture_export 로 kernel WIRE_ATTEST_FIXTURE 3733 옥텟 회수
//   (3) Leg 1 wire frame 빌드 (cmd 0x0040 AttestSubmit, payload 3733B)
//   (4) Leg 1 write+read 응답 cmd=0x8040 status=0 payload_len=0 n=16
//   (5) Leg 2 fixture[1313] ^= 0xFF (sig 첫 옥텟 flip) 응답 cmd=0xFFFF status=3
//   (6) Leg 3 wire frame 빌드 (cmd 0x0080 Status, payload empty)
//   (7) Leg 3 write+read 응답 cmd=0x8080 payload_len ≥ 8
//   (8) Marker emit write_stderr(b"ATTEST_PHASE5_1_OK\n")
fn wire_attest_phase5_1_test() {
    const SYS_HSM_ATTACH: u64 = 7;
    const SYS_HSM_WRITE: u64 = 10;
    const SYS_HSM_READ: u64 = 12;
    const SYS_ATTEST_FIXTURE_EXPORT: u64 = 13;
    const BUS_RING3PROCESS: u64 = 1;
    const EP_LUMEN_WIRE_RAW: u16 = 0x0003;
    const WIRE_FRAME_MAX_LOCAL: usize = 4096;
    const ATTEST_WIRE_LEN: usize = 3733;
    const CMD_ATTEST_SUBMIT: u16 = 0x0040;
    const CMD_STATUS: u16 = 0x0080;
    const SIG_FLIP_OFFSET: usize = 1313; // pk(1312) + bus_kind(1)

    // BSS 거주 buffer 로 스택 부담 0
    static mut FRAME_BUF: [u8; WIRE_FRAME_MAX_LOCAL] = [0u8; WIRE_FRAME_MAX_LOCAL];
    static mut RESPONSE_BUF: [u8; WIRE_FRAME_MAX_LOCAL] = [0u8; WIRE_FRAME_MAX_LOCAL];
    static mut FIXTURE_BUF: [u8; ATTEST_WIRE_LEN] = [0u8; ATTEST_WIRE_LEN];

    // (1) cap_wire attach 로 EP_LUMEN_WIRE endpoint_exists 게이트 (None-attest path)
    let init_wire = EP_LUMEN_WIRE_RAW.to_le_bytes();
    let mut cap_wire = [0u8; 16];
    // SAFETY init_wire 와 cap_wire 모두 stack-local 유효 슬라이스
    let rax = unsafe {
        syscall4(
            SYS_HSM_ATTACH,
            BUS_RING3PROCESS,
            init_wire.as_ptr() as u64,
            init_wire.len() as u64,
            cap_wire.as_mut_ptr() as u64,
        )
    };
    if (rax as i64) < 0 {
        write_stderr(b"WIRE_PHASE5_1_FAIL: cap_wire attach\n");
        exit(1);
    }

    // (2) sys_attest_fixture_export 로 kernel WIRE_ATTEST_FIXTURE 3733 옥텟 회수
    // SAFETY FIXTURE_BUF 는 단일 진입 BSS, syscall 진입 시 SMAP 윈도우만 user write
    let rax = unsafe {
        syscall3(
            SYS_ATTEST_FIXTURE_EXPORT,
            (&raw mut FIXTURE_BUF) as u64,
            ATTEST_WIRE_LEN as u64,
            0,
        )
    };
    if (rax as i64) < 0 {
        write_stderr(b"WIRE_PHASE5_1_FAIL: fixture_export\n");
        exit(1);
    }

    // (3) Leg 1 wire frame build, cmd 0x0040 AttestSubmit
    let payload_len: u16 = ATTEST_WIRE_LEN as u16;
    let frame_len: usize = 16 + payload_len as usize;
    // SAFETY BSP 단일 Ring 3 process, FRAME_BUF/FIXTURE_BUF 동시 접근 없음
    unsafe {
        let buf = &mut *(&raw mut FRAME_BUF);
        let fix = &*(&raw const FIXTURE_BUF);
        buf[0..4].copy_from_slice(b"LWK0");
        buf[4..6].copy_from_slice(&1u16.to_le_bytes()); // version = 1
        buf[6..8].copy_from_slice(&CMD_ATTEST_SUBMIT.to_le_bytes());
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // req_id = 1
        buf[12..14].copy_from_slice(&payload_len.to_le_bytes());
        buf[14..16].copy_from_slice(&0u16.to_le_bytes()); // request status 0
        buf[16..16 + ATTEST_WIRE_LEN].copy_from_slice(fix);
    }

    // (4) Leg 1 write + read, 응답 cmd=0x8040 status=0 payload_len=0 n=16
    // SAFETY FRAME_BUF 의 frame_len 길이 슬라이스만 노출
    let rax = unsafe {
        let buf_ptr = (&raw const FRAME_BUF) as *const u8;
        syscall3(
            SYS_HSM_WRITE,
            cap_wire.as_ptr() as u64,
            buf_ptr as u64,
            frame_len as u64,
        )
    };
    if (rax as i64) < 0 {
        write_stderr(b"WIRE_PHASE5_1_FAIL: Leg1 hsm_write\n");
        exit(1);
    }
    // SAFETY RESPONSE_BUF WIRE_FRAME_MAX 윈도우만 노출
    let n = unsafe {
        let resp_ptr = (&raw mut RESPONSE_BUF) as *mut u8;
        syscall3(
            SYS_HSM_READ,
            cap_wire.as_ptr() as u64,
            resp_ptr as u64,
            WIRE_FRAME_MAX_LOCAL as u64,
        )
    };
    if (n as i64) < 0 {
        write_stderr(b"WIRE_PHASE5_1_FAIL: Leg1 hsm_read\n");
        exit(1);
    }
    let n = n as usize;
    // SAFETY RESPONSE_BUF 첫 16 byte read-only
    let (resp_magic, resp_cmd, resp_status, resp_pl) = unsafe {
        let b = &*(&raw const RESPONSE_BUF);
        (
            [b[0], b[1], b[2], b[3]],
            u16::from_le_bytes([b[6], b[7]]),
            u16::from_le_bytes([b[14], b[15]]),
            u16::from_le_bytes([b[12], b[13]]),
        )
    };
    if &resp_magic != b"LWK0"
        || resp_cmd != (CMD_ATTEST_SUBMIT | 0x8000)
        || resp_status != 0
        || resp_pl != 0
        || n != 16
    {
        write_stderr(b"WIRE_PHASE5_1_FAIL: Leg1 header mismatch\n");
        exit(1);
    }

    // (5) Leg 2, sig 첫 옥텟 flip (fixture offset 1313 = pk(1312) + bus_kind(1))
    //     req_id 2 로 재구성, 응답 cmd=0xFFFF status=3 (Denied)
    // SAFETY FIXTURE_BUF 단일 진입
    unsafe {
        (*(&raw mut FIXTURE_BUF))[SIG_FLIP_OFFSET] ^= 0xFF;
    }
    unsafe {
        let buf = &mut *(&raw mut FRAME_BUF);
        let fix = &*(&raw const FIXTURE_BUF);
        buf[8..12].copy_from_slice(&2u32.to_le_bytes()); // req_id = 2
        buf[16..16 + ATTEST_WIRE_LEN].copy_from_slice(fix);
    }
    // SAFETY 동상
    let _ = unsafe {
        let buf_ptr = (&raw const FRAME_BUF) as *const u8;
        syscall3(
            SYS_HSM_WRITE,
            cap_wire.as_ptr() as u64,
            buf_ptr as u64,
            frame_len as u64,
        )
    };
    let _ = unsafe {
        let resp_ptr = (&raw mut RESPONSE_BUF) as *mut u8;
        syscall3(
            SYS_HSM_READ,
            cap_wire.as_ptr() as u64,
            resp_ptr as u64,
            WIRE_FRAME_MAX_LOCAL as u64,
        )
    };
    // SAFETY RESPONSE_BUF 첫 16 byte read-only
    let (resp_cmd_leg2, resp_status_leg2) = unsafe {
        let b = &*(&raw const RESPONSE_BUF);
        (
            u16::from_le_bytes([b[6], b[7]]),
            u16::from_le_bytes([b[14], b[15]]),
        )
    };
    if resp_cmd_leg2 != 0xFFFF || resp_status_leg2 != 3 {
        write_stderr(b"WIRE_PHASE5_1_FAIL: Leg2 not denied\n");
        exit(1);
    }

    // (6) Leg 3 Status frame build, cmd 0x0080 payload empty
    // SAFETY 동상
    unsafe {
        let buf = &mut *(&raw mut FRAME_BUF);
        buf[0..4].copy_from_slice(b"LWK0");
        buf[4..6].copy_from_slice(&1u16.to_le_bytes());
        buf[6..8].copy_from_slice(&CMD_STATUS.to_le_bytes());
        buf[8..12].copy_from_slice(&3u32.to_le_bytes()); // req_id = 3
        buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // payload_len = 0
        buf[14..16].copy_from_slice(&0u16.to_le_bytes());
    }
    // (7) Leg 3 write + read, 응답 cmd=0x8080 payload_len ≥ 8
    let _ = unsafe {
        let buf_ptr = (&raw const FRAME_BUF) as *const u8;
        syscall3(
            SYS_HSM_WRITE,
            cap_wire.as_ptr() as u64,
            buf_ptr as u64,
            16u64,
        )
    };
    let _ = unsafe {
        let resp_ptr = (&raw mut RESPONSE_BUF) as *mut u8;
        syscall3(
            SYS_HSM_READ,
            cap_wire.as_ptr() as u64,
            resp_ptr as u64,
            WIRE_FRAME_MAX_LOCAL as u64,
        )
    };
    // SAFETY RESPONSE_BUF 첫 16 byte read-only
    let (resp_cmd_leg3, resp_pl_leg3) = unsafe {
        let b = &*(&raw const RESPONSE_BUF);
        (
            u16::from_le_bytes([b[6], b[7]]),
            u16::from_le_bytes([b[12], b[13]]),
        )
    };
    if resp_cmd_leg3 != (CMD_STATUS | 0x8000) || resp_pl_leg3 < 8 {
        write_stderr(b"WIRE_PHASE5_1_FAIL: Leg3 status header\n");
        exit(1);
    }

    // (8) marker
    write_stderr(b"ATTEST_PHASE5_1_OK\n");
}

//
// 진입점
//
/// 사용자 진입점. `process::enter_ring3()` 가 ELF entry RIP 로 점프함.
///
/// # Safety
/// 직접 호출 금지. 사용자 모드 RIP 로만 진입.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    write_stderr(b"[iso-user-lumen] Ring 3 entry, elib-k0-nt wire-compat suite begin\n");

    check_blake3();
    check_blake3_keyed();
    check_ed25519();
    check_x25519();
    check_aes256_gcm();
    wire_blake3_phase4_test();
    // wire AttestSubmit / Status round-trip smoke marker ATTEST_PHASE5_1_OK
    wire_attest_phase5_1_test();

    write_stderr(b"[iso-user-lumen] all wire-compat checks passed\n");
    exit(0);
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    write_stderr(b"[iso-user-lumen] panic\n");
    exit(2);
}
