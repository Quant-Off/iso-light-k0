//! VGA 텍스트 버퍼 비상 디버그 출력을 수행하는 모듈입니다.
//!
//! EAL4+ 보안 요구사항:
//!   - 프로덕션(release) 빌드에서 모든 출력 기능은 컴파일 단계에서 제거됨
//!   - 디버그 빌드에서만 CPU 예외 정보를 VGA 텍스트 모드로 출력하여
//!     정보 유출 공격 표면을 최소화함
//!
//! VGA 텍스트 버퍼 레이아웃 (Intel VGA 표준):
//!   물리 주소 : 0xB8000
//!   크기      : 80 columns × 25 rows × 2 bytes/char = 4000 bytes
//!   엔트리    : [attribute(u8) | ASCII(u8)] - attribute = (bg << 4) | fg

#[cfg(debug_assertions)]
const VGA_COLS: usize = 80;
#[cfg(debug_assertions)]
const VGA_ROWS: usize = 25;
const VGA_PHYS_BASE: u64 = 0xB8000;

/// VGA 4-bit 색상 코드 (BIOS 표준)
#[allow(dead_code)]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightRed = 12,
    Yellow = 14,
    White = 15,
}

/// VGA 버퍼 기저 가상 주소.
/// 선형 매핑 활성화 전: 부트로더 identity 매핑(0xB8000)
/// 선형 매핑 활성화 후: update_base()로 갱신된 가상 주소
static mut VGA_BASE: *mut u16 = VGA_PHYS_BASE as *mut u16;

/// 현재 커서 위치 (행, 열)
static mut VGA_ROW: usize = 0;
static mut VGA_COL: usize = 0;

/// CR3 재로드(선형 매핑 활성화) 직후 VGA 기저 가상 주소를 갱신함.
///
/// 이 함수를 호출하지 않으면 부트로더 identity mapping(0xB8000)으로 계속 동작함.
///
/// # Safety
/// - `activate()` 호출 직후, 선형 매핑이 0xB8000을 포함하도록 구축된 이후에만 호출해야 함.
/// - 단일 코어 환경에서만 안전함.
pub unsafe fn update_base(virt_base: *mut u16) {
    // SAFETY: 호출자가 선형 매핑 활성화 이후 올바른 가상 주소를 전달함을 보장
    unsafe {
        VGA_BASE = virt_base;
        VGA_ROW = 0;
        VGA_COL = 0;
    }
}

/// VGA 텍스트 버퍼를 검은 배경으로 지움 (커서를 좌상단으로 리셋).
///
/// # Safety
/// VGA_BASE가 유효한 포인터를 가리켜야 함.
#[cfg(debug_assertions)]
pub unsafe fn clear() {
    let blank = color_attr(Color::Black, Color::LightGray) | b' ' as u16;
    for i in 0..(VGA_COLS * VGA_ROWS) {
        // SAFETY: 범위 내 VGA 버퍼 접근
        unsafe {
            VGA_BASE.add(i).write_volatile(blank);
        }
    }
    unsafe {
        VGA_ROW = 0;
        VGA_COL = 0;
    }
}

/// 배경/전경 색에서 VGA attribute 상위 바이트를 조합함.
#[cfg(debug_assertions)]
#[inline]
fn color_attr(bg: Color, fg: Color) -> u16 {
    ((bg as u16) << 12) | ((fg as u16) << 8)
}

/// 단일 ASCII 문자를 현재 커서 위치에 기록함 (개행 및 스크롤 처리 포함).
///
/// # Safety
/// VGA_BASE 및 커서 변수가 유효한 상태여야 함.
#[cfg(debug_assertions)]
unsafe fn put_char(c: u8, fg: Color) {
    // SAFETY: 호출자가 VGA_BASE 유효성을 보장
    let base = unsafe { VGA_BASE };

    if c == b'\n' {
        unsafe {
            VGA_COL = 0;
        }
        // SAFETY: base는 호출자가 유효성을 보장하는 VGA 버퍼 포인터
        unsafe {
            advance_row(base);
        }
        return;
    }

    // SAFETY: VGA_COL/VGA_ROW는 항상 범위 내로 유지됨
    let (_row, col) = unsafe { (VGA_ROW, VGA_COL) };

    if col >= VGA_COLS {
        unsafe {
            VGA_COL = 0;
        }
        // SAFETY: base는 호출자가 유효성을 보장하는 VGA 버퍼 포인터
        unsafe {
            advance_row(base);
        }
    }

    let (row, col) = unsafe { (VGA_ROW, VGA_COL) };
    let attr = color_attr(Color::Black, fg);
    // SAFETY: row < VGA_ROWS, col < VGA_COLS 불변식 유지
    unsafe {
        base.add(row * VGA_COLS + col)
            .write_volatile(attr | c as u16);
        VGA_COL += 1;
    }
    let _ = row; // suppress unused warning
}

/// 다음 행으로 이동. 마지막 행이면 스크롤 업.
#[cfg(debug_assertions)]
unsafe fn advance_row(base: *mut u16) {
    // SAFETY: 호출자가 base 유효성을 보장
    unsafe {
        VGA_ROW += 1;
        if VGA_ROW >= VGA_ROWS {
            // 전체 버퍼를 한 줄 위로 복사
            for row in 1..VGA_ROWS {
                for col in 0..VGA_COLS {
                    let src = base.add(row * VGA_COLS + col).read_volatile();
                    base.add((row - 1) * VGA_COLS + col).write_volatile(src);
                }
            }
            // 마지막 줄 공백으로 초기화
            let blank = color_attr(Color::Black, Color::LightGray) | b' ' as u16;
            for col in 0..VGA_COLS {
                base.add((VGA_ROWS - 1) * VGA_COLS + col)
                    .write_volatile(blank);
            }
            VGA_ROW = VGA_ROWS - 1;
        }
    }
}

/// 바이트 슬라이스를 VGA 버퍼에 출력함.
///
/// # Safety
/// VGA 버퍼가 유효한 상태에서만 호출해야 함.
#[cfg(debug_assertions)]
pub unsafe fn print(s: &[u8], fg: Color) {
    for &c in s {
        // SAFETY: 내부적으로 VGA 버퍼 범위 검사 수행
        unsafe {
            put_char(c, fg);
        }
    }
}

/// 바이트 슬라이스를 VGA 버퍼에 출력하고 개행 문자를 추가함.
///
/// # Safety
/// VGA 버퍼가 유효한 상태에서만 호출해야 함.
#[cfg(debug_assertions)]
pub unsafe fn println(s: &[u8], fg: Color) {
    // SAFETY: 호출자가 VGA 버퍼 유효성을 보장해야 하며, 내부 print 함수가 버퍼 범위를 검사함
    unsafe {
        print(s, fg);
        print(b"\n", fg);
    }
}

/// u64를 `0xXXXXXXXXXXXXXXXX` 형식으로 VGA에 출력함.
///
/// # Safety
/// VGA 버퍼가 유효한 상태에서만 호출해야 함.
#[cfg(debug_assertions)]
pub unsafe fn print_hex(val: u64, fg: Color) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    unsafe {
        put_char(b'0', fg);
        put_char(b'x', fg);
    }
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        // SAFETY: nibble < 16, HEX 인덱스 범위 내
        unsafe {
            put_char(HEX[nibble], fg);
        }
    }
}

/// CPU 예외 발생 시 VGA에 진단 화면을 출력함 (디버그 빌드 전용).
///
/// 출력 정보: 예외 이름, 오류 코드, RIP, CS, RSP, RFLAGS
///
/// # Safety
/// VGA 버퍼가 유효한 상태에서만 호출해야 함.
#[cfg(debug_assertions)]
pub unsafe fn print_exception(
    name: &[u8],
    error_code: Option<u64>,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
) {
    unsafe {
        clear();
        print(b"[KERNEL EXCEPTION] ", Color::LightRed);
        print(name, Color::Yellow);
        print(b"\n", Color::White);

        if let Some(ec) = error_code {
            print(b"  Error Code : ", Color::LightGray);
            print_hex(ec, Color::White);
            print(b"\n", Color::White);
        }

        print(b"  RIP        : ", Color::LightGray);
        print_hex(rip, Color::White);
        print(b"\n", Color::White);

        print(b"  CS         : ", Color::LightGray);
        print_hex(cs, Color::White);
        print(b"\n", Color::White);

        print(b"  RFLAGS     : ", Color::LightGray);
        print_hex(rflags, Color::White);
        print(b"\n", Color::White);

        print(b"  RSP        : ", Color::LightGray);
        print_hex(rsp, Color::White);
        print(b"\n", Color::White);

        print(
            b"\nSystem halted. (EAL4+ panic.rs hlt loop active)",
            Color::DarkGray,
        );
    }
}
