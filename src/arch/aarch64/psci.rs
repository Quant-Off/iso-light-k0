//! 본 모듈은 aarch64 PSCI(Power State Coordination Interface) 전원 표면을 제공합니다.
//!
//! # Features
//! PSCI_VERSION(함수 ID 0x8400_0000)과 CPU_ON(함수 ID 0xC400_0003)을 HVC conduit
//! 으로 호출합니다. conduit 은 HVC 로 고정되며, QEMU virt 는 PSCI conduit 을 HVC 로
//! 노출하므로 다른 conduit(Anti-Pattern)은 절대 사용하지 않습니다. HVC 로 잘못된
//! conduit 을 대체하면 QEMU virt 에서 미정의 동작이 발생하므로 본 모듈은 오직 HVC
//! 경로만 배선합니다.
//!
//! 함수 ID 상수와 반환 규약, 에러 타입은 검증된 크레이트에 위임하되, 본 파일은 크레이트를
//! 직접 import 하지 않고 상위 hub(`super`)가 재노출한 별칭(`Hvc` / `psci_version_call`
//! / `psci_cpu_on_call`)만 경유합니다. 이는 conduit 선택 문자열이 이 파일에 유입되지
//! 않도록 하는 하드 게이트이며, 커널 전원 표면이 HVC 단일 경로임을 표면 수준에서 봉인
//! 합니다. raw `hvc #0` + 함수 ID 직접 매핑은 실수 여지가 있어 사용하지 않습니다.
//!
//! x86 아날로그가 없는 신규 서브모듈입니다(x86 은 ACPI/별도 전원 경로). 부팅 순서상
//! GIC bring-up 직후 `report_version` 이 호출되어 7-line boot proof 의 마지막 라인
//! `PSCI >= 0x10000` 을 emit 합니다.

use super::{Hvc, psci_cpu_on_call, psci_version_call};
use crate::arch::aarch64::console;

/// PSCI_VERSION 을 HVC conduit 으로 호출하여 버전을 반환하고 boot proof 마커를 emit 함.
///
/// PSCI_VERSION(함수 ID 0x8400_0000)을 HVC 로 호출하여 major.minor 를 획득함. 반환값을
/// `major << 16 | minor` 로 재구성하여 `PSCI 0x........ >= 0x10000` 마커를 emit 함
/// (7-line boot proof 마지막 라인). QEMU virt 는 PSCI 1.x 를 노출하므로 major >= 1
/// (>= 0x10000)이 성립함. 조회 실패 시에는 실패 마커를 emit 하고 0 을 반환함.
///
/// # Safety
/// GIC bring-up 직후 부팅 초기 단일 코어 시퀀스에서 호출해야 함(HVC 는 EL1 에서 EL2/
/// 펌웨어로 trap 하므로 특권 문맥 계약을 승계함).
pub unsafe fn report_version() -> u32 {
    // psci_version_call::<Hvc> 는 PSCI_VERSION 을 HVC conduit 으로 호출하는 재노출 별칭임
    match psci_version_call::<Hvc>() {
        Ok(v) => {
            // Version 을 u32 (major << 16 | minor) 로 변환 PSCI 1.1 은 0x0001_0001 로 >= 0x10000
            let raw = u32::from(v);
            // SAFETY console 백엔드는 부팅 초기 유효 초기화되어 emit 안전
            unsafe {
                console::write_bytes(b"PSCI ");
                emit_hex_u32(raw);
                console::write_bytes(b" >= 0x10000\r\n");
            }
            raw
        }
        Err(_) => {
            // SAFETY console 백엔드 유효성 계약 승계
            unsafe {
                console::write_bytes(b"PSCI query fail\r\n");
            }
            0
        }
    }
}

/// PSCI CPU_ON 을 HVC conduit 으로 호출하여 보조 코어를 기동하는 표면.
///
/// 현재 BSP 단일 코어 범위이나 다중 코어 확장을 위한 호출 표면을 제공함. `target_cpu` 는
/// 대상 코어 MPIDR affinity, `entry` 는 보조 코어 진입 물리 주소, `context` 는 진입 시
/// x0 로 전달될 컨텍스트 값임. conduit 은 HVC 로 고정됨(함수 ID 0xC400_0003).
///
/// # Errors
/// PSCI 펌웨어가 거부(이미 on / 무효 파라미터 / 내부 실패)하거나 HVC 호출이 실패하면
/// `Err(())` 를 반환함.
///
/// # Safety
/// 유효한 보조 코어 진입 물리 주소와 초기 스택과 페이지 테이블이 준비된 이후에만 호출해야 함.
// result_unit_err 억제 근거 PSCI 펌웨어 실패 사유를 호출자가 세분화하지 않고 on/off 만
// 필요하므로 전용 에러 타입은 과설계다 (# Errors 에 실패 조건 명시)
#[allow(clippy::result_unit_err)]
pub unsafe fn cpu_on(target_cpu: u64, entry: u64, context: u64) -> Result<(), ()> {
    // psci_cpu_on_call::<Hvc> 로 PSCI CPU_ON(0xC400_0003) 을 HVC conduit 으로 호출
    psci_cpu_on_call::<Hvc>(target_cpu, entry, context).map_err(|_| ())
}

/// u32 를 `0x........`(8 자리 소문자 hex)로 console 에 emit 함 (no_std no-alloc 스택 변환).
///
/// # Safety
/// console 백엔드(`PL011_BASE`)가 유효 초기화된 상태에서만 호출해야 함.
unsafe fn emit_hex_u32(val: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 10];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut i = 0usize;
    while i < 8 {
        let nibble = ((val >> ((7 - i) * 4)) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
        i += 1;
    }
    // SAFETY console 백엔드 유효성 계약을 호출자가 승계
    unsafe {
        console::write_bytes(&buf);
    }
}
