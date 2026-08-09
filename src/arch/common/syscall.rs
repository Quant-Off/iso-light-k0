//! 본 모듈은 아키텍처 중립 syscall ABI 표면(번호, 에러, 컨텍스트, 주소 판정)을 정의합니다.
//!
//! # Features
//! x86_64 `syscall`/`sysret` 와 aarch64 `SVC #0` 두 진입 경로가 동일하게 소비하는
//! arch-중립 4 표면을 제공합니다. `SyscallNum`(호출 번호 카탈로그), `SyscallError`
//! (음수 errno 표면), `SyscallContext`(레지스터 스냅샷), `is_user_address`(사용자
//! 주소 경계)를 정의하며 두 아키텍처가 이 표면 뒤에서 합류하여 wire byte-diff 0
//! ABI 등가를 성립시킵니다.
//!
//! # ABI 레지스터 매핑
//! `SyscallContext` 필드는 x86 레지스터명을 벗어난 중립 슬롯(`num` + `arg0..arg5`)
//! 이며 두 아키텍처의 동일 arg 슬롯으로 매핑됩니다.
//!
//! | 중립 슬롯 | x86_64 SysV | aarch64 AAPCS64 |
//! |-----------|-------------|-----------------|
//! | num       | RAX         | X0              |
//! | arg0      | RDI         | X1              |
//! | arg1      | RSI         | X2              |
//! | arg2      | RDX         | X3              |
//! | arg3      | R10         | X4              |
//! | arg4      | R8          | X5              |
//! | arg5      | R9          | X6              |
//!
//! `num` 슬롯은 진입 시 호출 번호, 복귀 시 반환값을 담습니다(x86 RAX / aarch64 X0
//! 동일 규약). `pc`/`flags` 는 x86 RCX 와 R11(RIP 와 RFLAGS), aarch64 ELR_EL1 과 SPSR_EL1
//! 스냅샷입니다.
//!
//! # Authors
//! Q. T. Felix

//
// syscall 번호
//

/// 알려진 syscall 번호 목록.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum SyscallNum {
    /// 사용자 프로세스 정상 종료
    Exit = 0,
    /// `write(fd, buf, len)` 현재는 fd=2(stderr) 인 경우 콘솔 출력만 지원
    Write = 1,
    /// `ipc_call(cap_ptr, msg_type, payload_ptr, payload_len, reply_buf, reply_cap)`
    IpcCall = 2,
    /// `ipc_recv(endpoint_id, buf_ptr, buf_cap)`
    IpcRecv = 3,
    /// `ipc_reply(endpoint_id, reply_type, payload_ptr, payload_len)`
    IpcReply = 4,
    /// `getrandom(buf, len, flags)` 커널 DRBG 출력
    GetRandom = 5,
    /// `cap_request(endpoint_id, rights)` 커널이 정책 검증 후 발급
    CapRequest = 6,
    HsmAttach = 7,    // 정적 HSM 슬롯 부착 (비인증)
    HsmDetach = 8,    // HSM 슬롯 해제 + zeroize (post-attach CAP 검사)
    HsmEnumerate = 9, // 부착된 슬롯 enumerate (post-attach CAP 검사)
    HsmWrite = 10,    // USE cap 으로 SoftHSM mode-aware write
    HsmRelay = 11,    // src(RELAY_SRC) + dst(RELAY_DST) dual-cap kernel-internal transfer
    HsmRead = 12,     // USE cap 으로 wire frame response 회수
    /// attest_payload 3733 옥텟 fixture export (feature smoke 한정)
    ///
    /// lumen 측 mldsa 의존 부재 우회 kernel 이 attest_phase5_1_wire_smoke_test 에서
    /// 채운 WIRE_ATTEST_FIXTURE BSS 를 사용자 공간으로 복사 closed 빌드 cfg-out
    #[cfg(feature = "smoke")]
    AttestFixtureExport = 13,
    /// NETWORK_ATTACH cap one-shot Ring 3 인도 (tls-external 한정)
    ///
    /// out_ptr 16 옥텟 HsmCapability 응답 first-caller-wins after-take Denied
    /// closed 빌드 cfg-out variant 자체 부재 호출 시 Unknown 폴백 (RAX -1)
    #[cfg(feature = "tls-external")]
    NetworkCapTake = 14,
    /// AUDIT_READ cap one-shot Ring 3 인도 (양 프로필 공통)
    ///
    /// out_ptr 16 옥텟 HsmCapability 응답 first-caller-wins after-take Denied
    /// audit query 보유자만 sys_hsm_status 진입 가능
    AuditCapTake = 15,
    /// sys_hsm_status atomic 456 옥텟 응답 (AUDIT_READ cap 보유자만)
    ///
    /// out_ptr arg0 out_len arg1 caller_cap_token arg2 ABI 잠금
    /// 호출 자체는 AUDIT_RING 미기록 (audit-of-audit 회피)
    HsmStatus = 16,
}

//
// syscall 에러
//

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
    /// 음수 에러 코드를 반환 레지스터(x86 RAX / aarch64 X0) 폭 u64 로 변환함.
    ///
    /// 반환 규약(errno 표면)은 두 아키텍처에서 byte-diff 0 으로 동일함.
    #[inline]
    pub const fn as_rax(self) -> u64 {
        self as i64 as u64
    }
}

//
// SyscallContext (asm 과 레이아웃 결합)
//

/// 진입 stub 이 스택에 저장한 사용자 컨텍스트 스냅샷.
///
/// 필드 순서 = 진입 stub 의 스택 레이아웃이므로 `#[repr(C)]` 가 필수이며 순서를
/// 절대 변경하지 말 것. x86 naked syscall_entry 의 push 순서와 aarch64
/// aarch64_svc_entry 의 store 순서가 이 레이아웃에 동일하게 정합함.
#[repr(C)]
pub struct SyscallContext {
    pub pc: u64,    // [+0]  x86 RCX(RIP) / aarch64 ELR_EL1
    pub flags: u64, // [+8]  x86 R11(RFLAGS) / aarch64 SPSR_EL1
    pub num: u64,   // [+16] 호출 번호 / 반환값 (x86 RAX / aarch64 X0)
    pub arg0: u64,  // [+24] x86 RDI / aarch64 X1
    pub arg1: u64,  // [+32] x86 RSI / aarch64 X2
    pub arg2: u64,  // [+40] x86 RDX / aarch64 X3
    pub arg3: u64,  // [+48] x86 R10 / aarch64 X4
    pub arg4: u64,  // [+56] x86 R8  / aarch64 X5
    pub arg5: u64,  // [+64] x86 R9  / aarch64 X6
}

const _: () = assert!(core::mem::size_of::<SyscallContext>() == 72);
const _: () = assert!(core::mem::offset_of!(SyscallContext, num) == 16);
const _: () = assert!(core::mem::offset_of!(SyscallContext, arg0) == 24);

//
// 사용자 주소 검증
//

/// `va` 가 사용자 가상 주소 범위인지.
///
/// 사용자 매핑은 첫 페이지(NULL 페이지)를 제외한 `USER_MIN..USER_MAX` 범위에
/// 위치. NULL 페이지와 그 외(커널 직접 선형 매핑, 커널 세그먼트 등)는 차단.
/// NULL 하한은 미매핑 0 페이지로의 copy 가 fatal fault 를 유발하는 경로를 조기
/// 차단함.
#[inline]
pub fn is_user_address(va: u64) -> bool {
    const USER_MIN: u64 = 0x1000;
    // x86_64: canonical lower half(PML4[0..255]) 경계
    #[cfg(target_arch = "x86_64")]
    const USER_MAX: u64 = 0x0000_8000_0000_0000;
    // aarch64: TTBR0 하위 절반 경계 (TTBR0/TTBR1 split, 커널은 상위 TTBR1)
    #[cfg(target_arch = "aarch64")]
    const USER_MAX: u64 = 0x0000_8000_0000_0000;
    // 호스트 테스트 표면 등 그 외 타깃은 x86 경계를 폴백으로 사용
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const USER_MAX: u64 = 0x0000_8000_0000_0000;
    (USER_MIN..USER_MAX).contains(&va)
}
