//! 본 모듈은 aarch64 PL011 UART MMIO 직렬 콘솔을 제공합니다.
//!
//! # Features
//! `arm-pl011-uart` 0.5.0 드라이버에 UARTDR 바이트 write 를 위임하여 부팅 직렬
//! 콘솔을 구성합니다. PL011 은 MMU 유무 무관 동작하므로 boot_stub 의 MMU 전 early
//! print(`EL=1`)와 MMU 활성 후 `MMU=ON` 마커를 동일 백엔드로 낼 수 있습니다. 백엔드
//! base 는 `static mut PL011_BASE` 로 유지하며 물리 0x0900_0000(폴백 기본값, DTB 우선)로
//! 시작하고, MMU 활성 후 `update_base` 로 커널 선형 매핑 VA 로 갱신합니다.
//!
//! x86_64 `vga.rs` 의 Console 표면(write_str/clear + update_base)을 mirror 하되 VGA
//! 프레임버퍼 커서/스크롤 로직은 부재합니다. PL011 은 UARTDR(offset 0x00) 단일
//! 레지스터에 바이트를 스트림으로 흘리는 구조입니다. boot proof 마커(EL=1 MMU=ON)는
//! release 빌드에서도 반드시 관측되어야 하므로 `write_bytes` 는 무조건 emit 하고,
//! 일반 진단 콘솔 `write_str` 는 vga.rs 관례대로 debug 실체 / release no-op 로 이원화합니다.

use arm_pl011_uart::{PL011Registers, Uart, UniqueMmioPointer};
use core::ptr::NonNull;

/// QEMU virt PL011 UART MMIO 물리 기본 주소 (폴백 기본값, DTB/BootInfo 우선)
const PL011_PHYS_BASE: usize = 0x0900_0000;

/// PL011 register block 기저 포인터
///
/// MMU 활성 전에는 물리 0x0900_0000 을 identity 로 가리키며, `update_base` 로 커널
/// 선형 매핑 VA(KERNEL_VMA_BASE + 0x0900_0000)로 갱신됨 (x86 vga::VGA_BASE 대응)
static mut PL011_BASE: *mut PL011Registers = PL011_PHYS_BASE as *mut PL011Registers;

/// 콘솔 백엔드 base 를 MMU 활성 후 커널 선형 매핑 가상 주소로 갱신함.
///
/// 이 함수를 호출하지 않으면 MMU 전 identity 물리 주소(0x0900_0000)로 계속 동작함
/// (TTBR0 identity 매핑 유지 시에도 유효하나 커널 고주소 매핑 일원화를 위해 갱신).
///
/// # Safety
/// `mmu_enable` 완료 후, 선형 매핑이 UART MMIO 페이지를 Device-nGnRE 로 포함하도록
/// 구축된 이후에만 호출해야 함
pub unsafe fn update_base(virt_base: *mut u8) {
    // SAFETY 부팅 초기 단일 코어 시퀀스에서만 갱신되는 백엔드 base
    unsafe {
        *(&raw mut PL011_BASE) = virt_base as *mut PL011Registers;
    }
}

/// 바이트 슬라이스를 PL011 UARTDR 로 흘림 (release 포함 무조건 emit).
///
/// boot proof 마커(EL=1 MMU=ON)는 release 빌드에서도 관측되어야 하므로 debug 게이트
/// 없이 항상 동작함. 각 바이트는 arm-pl011-uart 드라이버의 `write_word`(UARTDR offset
/// 0x00 volatile write)에 위임되며 TX FIFO full 이면 여유가 날 때까지 spin 함.
///
/// # Safety
/// `PL011_BASE` 가 유효한 PL011 register block(물리 identity 또는 선형 매핑 VA)을
/// 가리켜야 함. 미매핑 주소 호출은 UB
pub unsafe fn write_bytes(bytes: &[u8]) {
    // SAFETY 호출자가 PL011_BASE 유효성을 승계 base 가 null 이면 no-op 로 안전 강등
    unsafe {
        let base = *(&raw const PL011_BASE);
        let Some(nn) = NonNull::new(base) else {
            return;
        };
        // arm-pl011-uart 위임 UniqueMmioPointer 는 base 를 device MMIO 로 취급
        let mut uart = Uart::new(UniqueMmioPointer::new(nn));
        for &b in bytes {
            while uart.is_tx_fifo_full() {
                core::hint::spin_loop();
            }
            uart.write_word(b);
        }
    }
}

/// 문자열을 콘솔에 출력함 (debug 실체 / release no-op 이원화 vga.rs 관례).
///
/// # Safety
/// 콘솔 백엔드(`PL011_BASE`)가 유효하게 초기화된 상태에서만 호출해야 함
#[cfg(debug_assertions)]
pub unsafe fn write_str(s: &str) {
    // SAFETY write_bytes 의 base 유효성 계약을 그대로 승계
    unsafe { write_bytes(s.as_bytes()) }
}

/// release 빌드 진단 콘솔 축약 no-op (boot proof 마커는 write_bytes 로 별도 emit).
///
/// # Safety
/// 백엔드 상태 무관하게 no-op 이므로 안전하나 trait 계약 정합을 위해 unsafe 유지
#[cfg(not(debug_assertions))]
#[allow(clippy::missing_safety_doc)]
pub unsafe fn write_str(_s: &str) {}

/// 화면 소거. PL011 직렬은 프레임버퍼가 없으므로 no-op.
///
/// # Safety
/// 백엔드 상태 무관 no-op 이나 Console trait 계약 정합을 위해 unsafe 유지
#[allow(clippy::missing_safety_doc)]
pub unsafe fn clear() {}
