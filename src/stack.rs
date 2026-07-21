//! 커널 스택 레이아웃과 가드 페이지/캐너리 관리를 수행하는 모듈입니다.
//!
//! elib-k0-nt 의 암호 프리미티브(ML-DSA, ML-KEM, BLAKE3, SHA-3 XOF 등) 는
//! 내부적으로 수 KB 단위의 상태 버퍼와 루프 전개로 인한 깊은 스택 프레임을
//! 사용합니다. 또한 `#[inline(never)]` 경로와 배리어(mfence) 가 존재하여
//! no_std 커널 컨텍스트에서도 단일 호출이 수 KB 를 소비할 수 있습니다.
//!
//! 따라서 부팅 초기 스택을 최소 256 KiB 이상으로 확장하고, 저주소 끝에
//! 4 KiB 가드 영역을 배치합니다.
//!   - MMU 활성화 전: 가드 영역에 32-byte 고유 캐너리를 기록해두고 주기적으로
//!     또는 핸들러 진입 시 무결성을 검증하는 소프트웨어 가드.
//!   - MMU 활성화 후: 가드 페이지를 미매핑(PRESENT=0)하여 스택 오버플로가
//!     하드웨어 수준에서 즉시 #PF 로 전환되도록 함.
//!
//! IST 전용 스택(#DF/#NMI/#MC/#PF) 역시 동일한 레이아웃을 적용해 각 치명
//! 예외 핸들러가 독립적인 보호 구간에서 실행되도록 합니다.

use core::sync::atomic::{Ordering, compiler_fence};

//
// 스택 크기 상수
//

/// 페이지 / 가드 페이지 크기 (4 KiB).
pub const GUARD_SIZE: usize = 4096;

/// #DF(Double Fault) 핸들러 스택 크기.
pub const STACK_DF_SIZE: usize = 64 * 1024;

/// #NMI 핸들러 스택 크기.
pub const STACK_NMI_SIZE: usize = 32 * 1024;

/// #MC(Machine Check) 핸들러 스택 크기.
pub const STACK_MC_SIZE: usize = 32 * 1024;

/// #PF(Page Fault) 전용 스택 크기 (주 스택 오버플로 수용).
pub const STACK_PF_SIZE: usize = 64 * 1024;

//
// 캐너리 패턴
//

/// 가드 영역에 쓰이는 32-byte 고유 패턴 (8바이트 단위 4회 반복).
const CANARY_QWORD: u64 = 0xDEAD_BEEF_CAFE_F00D;

//
// IST 스택 레이아웃
//
// `align(4096)` 으로 페이지 정렬을 강제하여 guard 영역이 정확히 페이지 경계
// (4 KiB)에 맞도록 한다. 구조체 선두(저주소)에 guard를 배치하여 스택이
// 아래로 자라면서 guard 영역을 먼저 침범하도록 설계함

/// 가드 페이지 + 스택 본체로 구성된 IST 스택.
///
/// 메모리는 저주소에서 고주소 방향으로 4 KiB 가드 영역과 N 바이트 스택 본체가
/// 인접하게 배치됨. 가드 영역의 끝(= 본체 시작) 이 사용 하한(bottom) 이며
/// 본체의 끝(= 고주소 경계) 이 초기 RSP 가 되는 top 임.
#[repr(C, align(4096))]
pub struct IstStack<const N: usize> {
    /// 스택 오버플로 감지용 가드 영역 (4 KiB).
    /// `install_canaries()` 이전에는 @nobits 로 0이며, 이후 CANARY 패턴으로 채워짐.
    guard: [u8; GUARD_SIZE],
    /// 스택 본체 (스택 포인터는 `top()`에서 시작해 아래로 자람).
    stack: [u8; N],
}

#[allow(clippy::new_without_default)]
impl<const N: usize> IstStack<N> {
    pub const fn new() -> Self {
        Self {
            guard: [0u8; GUARD_SIZE],
            stack: [0u8; N],
        }
    }

    /// 스택 본체 최상단(초기 RSP로 사용) 선형 주소.
    #[inline]
    pub fn top(&self) -> u64 {
        // SAFETY: stack 배열의 한 칸 뒤(= end) 주소 계산만 수행, 역참조 없음
        unsafe { self.stack.as_ptr().add(N) as u64 }
    }

    /// 스택 본체 하한(사용 가능한 최저 주소) 선형 주소.
    #[inline]
    pub fn bottom(&self) -> u64 {
        self.stack.as_ptr() as u64
    }

    /// 가드 영역 [start, end) 반환 (VMA 기준).
    #[inline]
    pub fn guard_range(&self) -> (u64, u64) {
        let start = self.guard.as_ptr() as u64;
        // SAFETY: start + GUARD_SIZE는 guard 배열 한 칸 뒤 주소
        let end = unsafe { self.guard.as_ptr().add(GUARD_SIZE) as u64 };
        (start, end)
    }
}

//
// boot_stub 스택 심볼 (확장된 BSP 스택)
//
// boot_stub.rs의 .boot_bss 섹션에 정의된 심볼들
// BSP 스택은 256 KiB, 저주소 끝에 4 KiB 가드 영역이 배치됨

unsafe extern "C" {
    /// 부트 스택 가드 영역의 시작(저주소).
    static boot_stack_guard_bottom: u8;
    /// 부트 스택 본체 시작 = 가드 영역 종료.
    static boot_stack_bottom: u8;
    /// 부트 스택 본체 최상단(초기 RSP 값).
    static boot_stack_top: u8;
}

/// BSP 부트 스택 가드 영역 [start, end) (VMA).
#[inline]
pub fn boot_guard_range() -> (u64, u64) {
    let s = (&raw const boot_stack_guard_bottom) as u64;
    let e = (&raw const boot_stack_bottom) as u64;
    (s, e)
}

/// BSP 부트 스택 본체 [bottom, top) (VMA).
#[inline]
pub fn boot_stack_range() -> (u64, u64) {
    let b = (&raw const boot_stack_bottom) as u64;
    let t = (&raw const boot_stack_top) as u64;
    (b, t)
}

//
// 캐너리 설치 / 검증
//

/// 부트 스택과 모든 IST 스택의 가드 영역에 CANARY 패턴을 volatile 쓰기로 기록.
///
/// # Safety
/// - 부팅 초기 단일 코어에서 한 번만 호출.
/// - 인터럽트 비활성(CLI) 상태 권장.
pub unsafe fn install_canaries() {
    // BSP 부트 스택 가드
    let (bs, be) = boot_guard_range();
    // SAFETY: .boot_bss의 boot_stack_guard는 @nobits로 쓰기 가능한 4 KiB 영역
    unsafe {
        fill_canary(bs, be);
    }

    // IST 가드 영역 4종 (x86 TSS/IST 전용, aarch64 는 SP_EL1 dedicated panic 스택으로 대체)
    #[cfg(target_arch = "x86_64")]
    for (s, e) in crate::tss::ist_guard_ranges().iter() {
        // SAFETY: 각 IstStack.guard 배열은 쓰기 가능한 4 KiB 정적 배열
        unsafe {
            fill_canary(*s, *e);
        }
    }

    compiler_fence(Ordering::SeqCst);
}

/// 모든 스택 가드 영역의 CANARY 무결성을 검사.
/// 하나라도 변조되어 있으면 `Err(변조된 가드의 시작 VMA)` 반환.
///
/// # Safety
/// 부팅 이후 읽기 전용 검사. 단일 코어 권장.
pub unsafe fn validate_canaries() -> Result<(), u64> {
    let (bs, be) = boot_guard_range();
    // SAFETY: 가드 영역은 항상 유효한 4 KiB 메모리
    unsafe {
        if !check_canary(bs, be) {
            return Err(bs);
        }
    }
    // x86 TSS/IST 가드 (aarch64 는 SP_EL1 panic 스택으로 대체 IST 개념 부재)
    #[cfg(target_arch = "x86_64")]
    for (s, e) in crate::tss::ist_guard_ranges().iter() {
        unsafe {
            if !check_canary(*s, *e) {
                return Err(*s);
            }
        }
    }
    Ok(())
}

//
// MMU 매핑 보조 (guard 페이지 스킵)
//

/// 주어진 VMA가 가드 영역 중 하나에 속하는지 확인.
/// 커널 `.bss` W^X 매핑 시 이 함수를 통해 IST 가드 페이지를 건너뛰어
/// 하드웨어 #PF에 의한 스택 오버플로 감지를 활성화함.
#[inline]
pub fn is_in_any_guard(va: u64, ranges: &[(u64, u64)]) -> bool {
    for (s, e) in ranges {
        if va >= *s && va < *e {
            return true;
        }
    }
    false
}

//
// 저수준 헬퍼
//

/// [start, end) 범위에 CANARY_QWORD 패턴을 volatile 쓰기로 채움.
///
/// # Safety
/// - 범위가 8-byte 정렬된 유효한 쓰기 가능 메모리여야 함.
#[inline]
unsafe fn fill_canary(start: u64, end: u64) {
    let mut p = start as *mut u64;
    let end_ptr = end as *mut u64;
    while (p as u64) < end_ptr as u64 {
        // SAFETY: 호출자가 유효 범위 보장
        unsafe {
            core::ptr::write_volatile(p, CANARY_QWORD);
            p = p.add(1);
        }
    }
}

/// [start, end) 범위가 모두 CANARY_QWORD 패턴으로 유지되고 있는지 검사.
#[inline]
unsafe fn check_canary(start: u64, end: u64) -> bool {
    let mut p = start as *const u64;
    let end_ptr = end as *const u64;
    while (p as u64) < end_ptr as u64 {
        // SAFETY: 호출자가 유효 범위 보장
        let v = unsafe { core::ptr::read_volatile(p) };
        if v != CANARY_QWORD {
            return false;
        }
        // SAFETY: 반복자 한 칸 전진
        unsafe {
            p = p.add(1);
        }
    }
    true
}
