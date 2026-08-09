//! x86_64 Task State Segment(TSS) 와 IST 스택 레이아웃을 관리하는 모듈입니다.
//!
//! IST 구성:
//!   - IST1 은 #DF (Double Fault) 전용, 64 KiB + 4 KiB Guard
//!   - IST2 는 #NMI (Non-Maskable Interrupt) 전용, 32 KiB + 4 KiB Guard
//!   - IST3 은 #MC (Machine Check) 전용, 32 KiB + 4 KiB Guard
//!   - IST4 는 #PF (Page Fault, 커널 스택 오버플로 포함) 전용, 64 KiB + 4 KiB
//!
//! 치명 예외 전용 스택을 독립적으로 분리하여, 커널 주 스택이 망가진 상태
//! (스택 오버플로, 가드 페이지 진입, 래치-업 등) 에서도 핸들러가 안전한
//! 컨텍스트에서 실행되도록 합니다.
//!
//! 각 스택 최하단(저주소) 에 4 KiB 가드 영역을 둠으로써:
//!   1) 커널 주소 공간이 4 KiB 페이지로 매핑된 이후에는 이 영역을 미매핑하여
//!      스택 오버플로 시 즉시 #PF 를 유발함 (활성화 경로는 main.rs).
//!   2) MMU 활성 이전에는 `install_canaries()` 로 기록된 고유 패턴을 주기적
//!      으로 검증하여 소프트웨어 레벨에서 스택 오염을 탐지함.
//!
//! TSS 레이아웃 (Intel SDM Vol.3A Section 7.7, 104 bytes):
//!   Offset   Field
//!     0      Reserved (u32)
//!     4      RSP0 (u64)      (Ring 0 전환 스택)
//!    12      RSP1 (u64)
//!    20      RSP2 (u64)
//!    28      Reserved (u64)
//!    36      IST1 (u64)
//!    44      IST2 (u64)
//!    52      IST3 (u64)
//!    60      IST4 (u64)
//!    68      IST5 (u64)
//!    76      IST6 (u64)
//!    84      IST7 (u64)
//!    92      Reserved (u64)
//!   100      Reserved (u16)
//!   102      IOPB Offset (u16)

use core::mem::size_of;

use crate::stack::{IstStack, STACK_DF_SIZE, STACK_MC_SIZE, STACK_NMI_SIZE, STACK_PF_SIZE};

//
// IST 인덱스 상수 (1-based, IDT 게이트 디스크립터 ist 필드용)
//

pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
pub const IST_PAGE_FAULT: u8 = 4;

const IST_DF_IDX: usize = (IST_DOUBLE_FAULT - 1) as usize;
const IST_NMI_IDX: usize = (IST_NMI - 1) as usize;
const IST_MC_IDX: usize = (IST_MACHINE_CHECK - 1) as usize;
const IST_PF_IDX: usize = (IST_PAGE_FAULT - 1) as usize;

//
// IST 전용 독립 스택 (가드 페이지 포함)
//
// 각 스택은 `.bss`(고주소 VMA)에 정적 배치되어 커널 이미지의 일부로 매핑
// W^X 매핑 시 가드 영역은 제외되어 실제 #PF를 유발하도록 main.rs에서 처리

/// #DF 핸들러 전용 스택
static mut STACK_DOUBLE_FAULT: IstStack<STACK_DF_SIZE> = IstStack::new();

/// #NMI 핸들러 전용 스택
static mut STACK_NMI: IstStack<STACK_NMI_SIZE> = IstStack::new();

/// #MC 핸들러 전용 스택
static mut STACK_MACHINE_CHECK: IstStack<STACK_MC_SIZE> = IstStack::new();

/// #PF 핸들러 전용 스택 (커널 주 스택 오버플로 수용)
static mut STACK_PAGE_FAULT: IstStack<STACK_PF_SIZE> = IstStack::new();

//
// TSS 구조체
//

/// x86_64 Task State Segment (Intel SDM Vol.3A Section 7.7).
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct TaskStateSegment {
    _reserved0: u32,
    /// 권한 수준별 스택 포인터 (Ring 0/1/2)
    pub rsp: [u64; 3],
    _reserved1: u64,
    /// Interrupt Stack Table (IST1..IST7, 1-based 인덱스)
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// I/O Permission Bitmap 오프셋 (TSS 크기 이상이면 모든 포트 차단)
    pub iomap_base: u16,
}

const _: () = assert!(size_of::<TaskStateSegment>() == 104);

/// 커널 전역 TSS.
// SAFETY: 부팅 초기 단일 코어, init()에서 한 번만 초기화됨
pub static mut KERNEL_TSS: TaskStateSegment = TaskStateSegment {
    _reserved0: 0,
    rsp: [0; 3],
    _reserved1: 0,
    ist: [0; 7],
    _reserved2: 0,
    _reserved3: 0,
    iomap_base: size_of::<TaskStateSegment>() as u16,
};

//
// 초기화
//

/// TSS.IST1~IST4에 각 치명 예외 전용 스택의 최상단 주소를 기록함.
///
/// 반드시 `init_gdt()` 호출 이전에 수행해야 함.
///
/// # Safety
/// - 인터럽트 비활성화 상태에서 호출해야 함.
/// - 부팅 초기 단일 코어 환경 전용.
pub unsafe fn init() {
    // SAFETY: 각 정적 스택 영역에 대한 최상단 주소 산출 (읽기 전용)
    //         &raw const로 static mut 공유 참조를 회피
    unsafe {
        let df = (*(&raw const STACK_DOUBLE_FAULT)).top();
        let nmi = (*(&raw const STACK_NMI)).top();
        let mc = (*(&raw const STACK_MACHINE_CHECK)).top();
        let pf = (*(&raw const STACK_PAGE_FAULT)).top();

        // SAFETY: KERNEL_TSS는 단일 코어 초기화 구간에서만 접근됨
        (*(&raw mut KERNEL_TSS)).ist[IST_DF_IDX] = df;
        (*(&raw mut KERNEL_TSS)).ist[IST_NMI_IDX] = nmi;
        (*(&raw mut KERNEL_TSS)).ist[IST_MC_IDX] = mc;
        (*(&raw mut KERNEL_TSS)).ist[IST_PF_IDX] = pf;
    }
}

/// KERNEL_TSS의 선형 주소 반환 (GDT TSS 디스크립터 구성에 사용).
pub fn base_addr() -> u64 {
    (&raw const KERNEL_TSS) as u64
}

/// Ring 3 에서 Ring 0 으로 전환 시 자동 로드되는 커널 스택 포인터(RSP0)를 설정함.
///
/// 인터럽트/예외가 사용자 모드(CPL=3)에서 발생하거나 IRETQ 가 사용자 모드
/// 진입을 수행할 때 CPU 가 본 RSP0 값을 RSP 에 자동 적재함. (Intel SDM
/// Vol.3A §6.14.2). `syscall` 명령은 RSP0 를 사용하지 않으므로 syscall
/// 진입 stub 은 별도로 GS-relative per-CPU 변수에서 커널 스택을 로드함.
///
/// # Safety
/// 단일 코어 부팅 초기에서 호출하며, `rsp` 는 16-byte 정렬된 유효한 커널
/// 스택 최상단 VMA 여야 함.
pub unsafe fn set_rsp0(rsp: u64) {
    // SAFETY: 부팅 초기 단일 코어 접근
    unsafe {
        (*(&raw mut KERNEL_TSS)).rsp[0] = rsp;
    }
}

/// TSS 크기 - 1 (GDT 디스크립터 limit 필드에 사용).
pub fn limit() -> u16 {
    (size_of::<TaskStateSegment>() - 1) as u16
}

//
// 외부에서 가드 캐너리 검증을 위한 스택 접근자
//

/// IST 스택들의 가드 영역 시작 주소(읽기 전용)를 반환.
///
/// `stack::validate_canaries()`가 이 주소를 사용해 가드 패턴 무결성을 확인함.
pub fn ist_guard_ranges() -> [(u64, u64); 4] {
    // SAFETY: 정적 배열의 시작/끝 주소만 읽음
    unsafe {
        [
            (*(&raw const STACK_DOUBLE_FAULT)).guard_range(),
            (*(&raw const STACK_NMI)).guard_range(),
            (*(&raw const STACK_MACHINE_CHECK)).guard_range(),
            (*(&raw const STACK_PAGE_FAULT)).guard_range(),
        ]
    }
}

/// IST 스택들의 가드 영역 VMA 시작/끝(W^X 매핑 시 guard는 제외용)을 반환.
pub fn ist_guard_vmas() -> [(u64, u64); 4] {
    ist_guard_ranges()
}
