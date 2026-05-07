//! IDT(Interrupt Descriptor Table), CPU 예외 핸들러, 8259 PIC 초기화를
//! 수행하는 모듈입니다.
//!
//! 인터럽트/예외 벡터 배치는 다음과 같습니다.
//!   - 0x00..0x1F  CPU 예외 (Intel SDM Vol.3A Chapter 6)
//!   - 0x20..0x27  IRQ 0..7  (8259 Master PIC, 재매핑 후)
//!   - 0x28..0x2F  IRQ 8..15 (8259 Slave PIC, 재매핑 후)
//!   - 0x30..0xFF  예약 (IPC, 시스템 콜용 향후 확장)
//!
//! EAL4+ 보안 고려사항:
//!   - 모든 미정의 벡터에 default_handler를 설치하여 빈 IDT 엔트리로 인한
//!     Triple Fault를 예방함.
//!   - 치명 예외(#DF, #MC)는 즉시 CLI + HLT 루프로 시스템을 정지함.
//!   - 디버그 정보(RIP, RSP 등)는 debug 빌드에서만 VGA에 출력함.
//!   - 8259 PIC는 초기화 직후 모든 IRQ를 마스킹하여 외부 인터럽트를 차단함.

use core::mem::size_of;

use crate::boot::KERNEL_CS;
use crate::tss::{IST_DOUBLE_FAULT, IST_MACHINE_CHECK, IST_NMI, IST_PAGE_FAULT};
#[cfg(debug_assertions)]
use crate::vga;

//
// PIC 8259 I/O 포트 상수
//

const PIC1_CMD: u16 = 0x20; // Master PIC 명령 포트
const PIC1_DATA: u16 = 0x21; // Master PIC 데이터(마스크) 포트
const PIC2_CMD: u16 = 0xA0; // Slave  PIC 명령 포트
const PIC2_DATA: u16 = 0xA1; // Slave  PIC 데이터(마스크) 포트

const PIC_EOI: u8 = 0x20; // End-Of-Interrupt 명령

/// IRQ 벡터 오프셋: IRQ0 -> INT 0x20 (32)으로 재매핑.
/// CPU 예외(0x00..0x1F)와의 충돌 방지.
pub const IRQ_BASE: u8 = 0x20;

//
// IDT 게이트 디스크립터 타입
//

/// 64비트 인터럽트 게이트 타입/속성 바이트 (P=1, DPL=0, S=0, Type=0xE).
/// CLI(IF=0)를 자동으로 수행하여 핸들러 실행 중 재진입을 차단함.
const GATE_INTERRUPT: u8 = 0x8E;

/// 64비트 트랩 게이트 타입/속성 바이트 (P=1, DPL=0, S=0, Type=0xF).
/// IF 플래그를 보존하여 핸들러 실행 중 인터럽트 허용 (소프트웨어 예외용).
const GATE_TRAP: u8 = 0x8F;

//
// IDT 게이트 디스크립터 (16 bytes)
//
// Intel SDM Vol.3A Figure 6-7 의 게이트 디스크립터 포맷은 다음 필드로
// 구성됨: Reserved (bits 96..127), Offset[63:32] (bits 64..95),
// Offset[31:16] (bits 48..63), Type (bits 40..47), Reserved (bits 32..39),
// CS (bits 16..31), Offset[15:0] (bits 0..15)

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct GateDescriptor {
    offset_low: u16,  // 핸들러 주소 bits[15:0]
    selector: u16,    // 코드 세그먼트 셀렉터 (KERNEL_CS)
    ist: u8,          // bits[2:0] = IST 인덱스, bits[7:3] = 0 (예약)
    type_attr: u8,    // P | DPL[1:0] | 0 | Type[3:0]
    offset_mid: u16,  // 핸들러 주소 bits[31:16]
    offset_high: u32, // 핸들러 주소 bits[63:32]
    _reserved: u32,   // 반드시 0
}

impl GateDescriptor {
    /// 사용하지 않는 엔트리 (Present=0 이면 CPU가 이 벡터 수신 시 #GP 발생).
    const fn absent() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    /// 커널 링0 인터럽트/트랩 게이트 생성.
    /// `handler`는 `fn_ptr as usize` 형식으로 전달해야 함.
    /// `usize`를 사용하는 이유: `extern "x86-interrupt"` fn 포인터는
    /// `*const ()`로 직접 캐스트가 불가능하며, `usize` 경유가 필요함.
    fn new(handler: usize, gate_type: u8, ist_index: u8) -> Self {
        let handler = handler as u64;
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: KERNEL_CS,
            ist: ist_index & 0x07,
            type_attr: gate_type,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _reserved: 0,
        }
    }
}

// 컴파일 타임 크기 검증
const _: () = assert!(size_of::<GateDescriptor>() == 16);

//
// LIDT 포인터 구조체
//

#[repr(C, packed)]
struct IdtPointer {
    limit: u16, // IDT 크기 - 1 (bytes)
    base: u64,  // IDT 물리(선형) 기저 주소
}

//
// 정적 IDT (256 엔트리 x 16 bytes = 4 KiB)
//

// SAFETY: 부팅 초기 단일 코어, init_idt()에서 한 번만 초기화됨
static mut IDT: [GateDescriptor; 256] = [GateDescriptor::absent(); 256];

//
// CPU 인터럽트 스택 프레임
//

/// CPU가 인터럽트/예외 진입 시 자동으로 스택에 push하는 컨텍스트.
/// Intel SDM Vol.3A Figure 6-9 참조.
#[repr(C)]
pub struct InterruptStackFrame {
    pub instruction_pointer: u64, // RIP: 재개할 명령어 주소
    pub code_segment: u64,        // CS
    pub cpu_flags: u64,           // RFLAGS
    pub stack_pointer: u64,       // RSP: 예외 발생 시 스택 포인터
    pub stack_segment: u64,       // SS
}

//
// I/O 포트 헬퍼
//

/// x86 I/O 포트에 1바이트 출력.
///
/// # Safety
/// 지정한 포트에 바이트를 기록하는 IN/OUT 명령어를 실행함.
/// 잘못된 포트/값은 하드웨어 동작을 예기치 않게 변경할 수 있음.
#[inline]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: 호출자가 포트 유효성을 보장
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// I/O 대기 (약 1~4 μs): PIC 초기화 명령 사이에 필요한 딜레이.
/// 포트 0x80(POST 코드 포트)은 대부분의 시스템에서 안전하게 쓸 수 있음.
#[inline]
unsafe fn io_wait() {
    // SAFETY: 포트 0x80은 POST 진단용으로, 쓰기만 수행하며 부작용이 없음
    unsafe {
        outb(0x80, 0x00);
    }
}

//
// 8259 PIC 초기화
//

/// 8259 PIC를 초기화하고 IRQ 벡터를 0x20..0x2F로 재매핑한 뒤 전체 마스킹함.
///
/// 초기화 절차 (ICW1 ~ ICW4):
///   1. ICW1: 초기화 시작 (cascade 모드, ICW4 예정)
///   2. ICW2: 벡터 오프셋 설정 (Master=0x20, Slave=0x28)
///   3. ICW3: 계단식 연결 설정 (Master: IRQ2에 Slave, Slave: 식별자=2)
///   4. ICW4: 8086 모드 설정
///
/// 초기화 완료 후 모든 IRQ를 마스킹하여 커널이 명시적으로 허용하기 전까지
/// 하드웨어 인터럽트를 차단함 (EAL4+ 최소 권한 원칙).
///
/// # Safety
/// - 인터럽트 비활성화(CLI) 상태에서 호출해야 함.
/// - PIC가 시스템에 존재하는 x86 환경에서만 안전함.
#[cfg(target_arch = "x86_64")]
unsafe fn init_pic() {
    // SAFETY: CLI 상태에서 PIC I/O 포트 접근 - 호출자가 보장

    // ICW1: 초기화 명령 (0x11 = Init + Cascade + ICW4 expected)
    unsafe {
        outb(PIC1_CMD, 0x11);
        io_wait();
        outb(PIC2_CMD, 0x11);
        io_wait();

        // ICW2: 벡터 오프셋
        // Master: IRQ0 -> INT 0x20 (32)
        outb(PIC1_DATA, IRQ_BASE);
        io_wait();
        // Slave:  IRQ8 -> INT 0x28 (40)
        outb(PIC2_DATA, IRQ_BASE + 8);
        io_wait();

        // ICW3: 계단식 연결
        // Master: 비트 마스크로 IRQ2에 Slave 연결됨 (0b00000100 = 0x04)
        outb(PIC1_DATA, 0x04);
        io_wait();
        // Slave: Slave ID = 2 (IRQ2에 연결)
        outb(PIC2_DATA, 0x02);
        io_wait();

        // ICW4: 8086/88 모드
        outb(PIC1_DATA, 0x01);
        io_wait();
        outb(PIC2_DATA, 0x01);
        io_wait();

        // OCW1: 전체 마스킹 (모든 IRQ 차단)
        // 커널이 명시적으로 enable_irq()를 호출하기 전까지 외부 인터럽트 차단
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Master PIC에 EOI(End-Of-Interrupt) 신호를 전송함.
/// IRQ0..7 핸들러 종료 시 호출해야 함.
///
/// # Safety
/// IRQ0..7 핸들러 내부에서만 호출해야 함.
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn pic_eoi_master() {
    // SAFETY: 핸들러 컨텍스트에서 PIC 명령 포트 접근
    unsafe {
        outb(PIC1_CMD, PIC_EOI);
    }
}

/// Master + Slave PIC 양쪽에 EOI 신호를 전송함.
/// IRQ8..15 핸들러 종료 시 호출해야 함.
///
/// # Safety
/// IRQ8..15 핸들러 내부에서만 호출해야 함.
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn pic_eoi_slave() {
    // SAFETY: 핸들러 컨텍스트에서 PIC 명령 포트 접근
    unsafe {
        outb(PIC2_CMD, PIC_EOI);
        outb(PIC1_CMD, PIC_EOI);
    }
}

/// 지정한 IRQ 라인의 마스크를 해제하여 인터럽트를 허용함 (0-based IRQ 번호, 0..15).
///
/// IRQ 0..7   -> Master PIC 마스크 레지스터(0x21) 비트 해제
/// IRQ 8..15  -> Slave  PIC 마스크 레지스터(0xA1) 비트 해제 + Slave 연결 IRQ2 자동 해제
///
/// # Safety
/// - 해당 IRQ에 유효한 핸들러가 IDT에 등록된 이후에 호출해야 함.
/// - irq < 16 이어야 함.
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_irq(irq: u8) {
    // SAFETY: 호출자가 핸들러 설치 이후 호출을 보장, PIC 마스크 포트 RMW
    unsafe {
        if irq < 8 {
            // IRQ 0..7: Master PIC 마스크에서 해당 비트 클리어
            let mut mask: u8;
            core::arch::asm!(
                "in al, dx",
                in("dx") PIC1_DATA,
                out("al") mask,
                options(nomem, nostack, preserves_flags),
            );
            mask &= !(1u8 << irq);
            outb(PIC1_DATA, mask);
        } else if irq < 16 {
            // IRQ 8..15: Slave PIC 마스크에서 해당 비트 클리어
            // Slave는 Master의 IRQ2를 통해 연결되므로 IRQ2도 활성화해야 함
            let mut slave_mask: u8;
            core::arch::asm!(
                "in al, dx",
                in("dx") PIC2_DATA,
                out("al") slave_mask,
                options(nomem, nostack, preserves_flags),
            );
            slave_mask &= !(1u8 << (irq - 8));
            outb(PIC2_DATA, slave_mask);

            // Master IRQ2(Slave 캐스케이드 라인) 마스크 해제
            let mut master_mask: u8;
            core::arch::asm!(
                "in al, dx",
                in("dx") PIC1_DATA,
                out("al") master_mask,
                options(nomem, nostack, preserves_flags),
            );
            master_mask &= !(1u8 << 2);
            outb(PIC1_DATA, master_mask);
        }
    }
}

//
// 치명 예외 공통 정지 루틴
//

/// 치명 예외 발생 시 디버그 정보를 출력하고 시스템을 안전하게 정지시킴.
///
/// EAL4+ 요구사항:
///   - Release 빌드: 정보 출력 없이 즉각 CLI + HLT 루프 (panic.rs와 동일한 정책).
///   - Debug 빌드: VGA에 예외 정보 출력 후 CLI + HLT 루프.
///
/// # Safety
/// 인터럽트 게이트에서 호출되므로 이미 IF=0 상태임.
#[cfg(target_arch = "x86_64")]
unsafe fn fatal_halt(
    #[cfg_attr(not(debug_assertions), allow(unused_variables))] name: &[u8],
    #[cfg_attr(not(debug_assertions), allow(unused_variables))] error_code: Option<u64>,
    #[cfg_attr(not(debug_assertions), allow(unused_variables))] frame: &InterruptStackFrame,
) -> ! {
    // Debug 빌드: VGA 진단 출력
    #[cfg(debug_assertions)]
    // SAFETY: VGA 버퍼 접근 - 예외 컨텍스트, 단일 출력 경로
    unsafe {
        vga::print_exception(
            name,
            error_code,
            frame.instruction_pointer,
            frame.code_segment,
            frame.cpu_flags,
            frame.stack_pointer,
        );
    }

    // Release/Debug 공통: 인터럽트 비활성화 + CPU Halt 무한 루프
    // panic.rs의 정책과 동일하게, 어떠한 상황에서도 커널이 계속 실행되지 않도록 함
    loop {
        // SAFETY: 치명 예외 후 CPU 정지 - IF는 인터럽트 게이트에서 이미 0
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags),);
        }
    }
}

// CPU 예외 핸들러
//
// x86-interrupt ABI: CPU가 핸들러 진입 전에 스택 프레임(InterruptStackFrame)을
// 자동으로 push. 오류 코드가 있는 예외는 프레임 아래에 u64 오류 코드가 추가됨
// 핸들러 반환 시 IRET로 이전 컨텍스트를 복원함

// #DE: Divide Error (벡터 0, Fault)
extern "x86-interrupt" fn divide_error_handler(frame: InterruptStackFrame) {
    // SAFETY: 예외 핸들러 컨텍스트, 단일 코어 부팅 환경
    unsafe {
        fatal_halt(b"#DE Divide Error", None, &frame);
    }
}

// #DB: Debug (벡터 1, Fault/Trap)
extern "x86-interrupt" fn debug_handler(frame: InterruptStackFrame) {
    // 디버그 예외는 소프트웨어 브레이크포인트 등에서 발생
    // 현재는 치명 처리; 향후 디버거 지원 시 별도 분기 필요
    unsafe {
        fatal_halt(b"#DB Debug", None, &frame);
    }
}

// #NMI: Non-Maskable Interrupt (벡터 2)
extern "x86-interrupt" fn nmi_handler(frame: InterruptStackFrame) {
    // NMI는 하드웨어 오류(ECC 메모리 오류, watchdog 등) 신호
    // 복구 불가능한 하드웨어 오류로 간주하고 즉시 정지
    unsafe {
        fatal_halt(b"#NMI Non-Maskable Interrupt", None, &frame);
    }
}

// #BP: Breakpoint (벡터 3, Trap)
extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    // 향후 커널 디버거 연동 시 이 핸들러를 확장함
    // 현재는 디버그 출력 후 계속 진행(IRET)하지 않고 정지
    unsafe {
        fatal_halt(b"#BP Breakpoint", None, &frame);
    }
}

// #OF: Overflow (벡터 4, Trap)
extern "x86-interrupt" fn overflow_handler(frame: InterruptStackFrame) {
    unsafe {
        fatal_halt(b"#OF Overflow", None, &frame);
    }
}

// #BR: Bound Range Exceeded (벡터 5, Fault)
extern "x86-interrupt" fn bound_range_handler(frame: InterruptStackFrame) {
    unsafe {
        fatal_halt(b"#BR Bound Range Exceeded", None, &frame);
    }
}

// #UD: Invalid Opcode (벡터 6, Fault)
extern "x86-interrupt" fn invalid_opcode_handler(frame: InterruptStackFrame) {
    unsafe {
        fatal_halt(b"#UD Invalid Opcode", None, &frame);
    }
}

// #NM: Device Not Available (벡터 7, Fault)
extern "x86-interrupt" fn device_not_available_handler(frame: InterruptStackFrame) {
    // x87 FPU / SSE 명령어 실행 시 CR0.TS=1이면 발생
    // 현재 커널은 부동소수점을 사용하지 않으므로 치명 오류로 처리
    unsafe {
        fatal_halt(b"#NM Device Not Available", None, &frame);
    }
}

// #DF: Double Fault (벡터 8, Abort, 오류코드=0)
// 반드시 IST를 사용해야 함: 스택 오버플로 등으로 커널 스택이 손상된 상태에서도
// 안전하게 실행되도록 tss.rs의 DOUBLE_FAULT_STACK을 IST1로 등록함
extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, error_code: u64) -> ! {
    // #DF는 Abort: IRET로 복구 불가능. 반드시 발산(diverge)해야 함
    // SAFETY: 치명 예외, IST1 스택에서 실행 중
    unsafe { fatal_halt(b"#DF Double Fault", Some(error_code), &frame) }
}

// #TS: Invalid TSS (벡터 10, Fault, 오류코드 있음)
extern "x86-interrupt" fn invalid_tss_handler(frame: InterruptStackFrame, error_code: u64) {
    unsafe {
        fatal_halt(b"#TS Invalid TSS", Some(error_code), &frame);
    }
}

// #NP: Segment Not Present (벡터 11, Fault, 오류코드 있음)
extern "x86-interrupt" fn segment_not_present_handler(frame: InterruptStackFrame, error_code: u64) {
    unsafe {
        fatal_halt(b"#NP Segment Not Present", Some(error_code), &frame);
    }
}

// #SS: Stack-Segment Fault (벡터 12, Fault, 오류코드 있음)
extern "x86-interrupt" fn stack_segment_handler(frame: InterruptStackFrame, error_code: u64) {
    unsafe {
        fatal_halt(b"#SS Stack-Segment Fault", Some(error_code), &frame);
    }
}

// #GP: General Protection Fault (벡터 13, Fault, 오류코드 있음)
extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, error_code: u64) {
    unsafe {
        fatal_halt(b"#GP General Protection Fault", Some(error_code), &frame);
    }
}

// #PF: Page Fault (벡터 14, Fault, 오류코드 있음)
// 오류코드 비트: P(0)=존재, W(1)=쓰기, U(2)=사용자, R(3)=예약비트, I(4)=명령어
// CR2 레지스터: 폴트를 일으킨 가상 주소
extern "x86-interrupt" fn page_fault_handler(frame: InterruptStackFrame, error_code: u64) {
    // CR2에서 폴트 주소 읽기 (디버그 빌드에서만 VGA 출력에 사용)
    #[cfg(debug_assertions)]
    let cr2: u64;
    #[cfg(debug_assertions)]
    // SAFETY: CR2 읽기는 항상 안전한 읽기 전용 작업
    unsafe {
        core::arch::asm!(
            "mov {cr2}, cr2",
            cr2 = out(reg) cr2,
            options(nomem, nostack, preserves_flags),
        );
    }

    // 디버그 빌드에서 CR2 추가 출력
    #[cfg(debug_assertions)]
    // SAFETY: VGA 출력, 예외 컨텍스트
    unsafe {
        vga::print_exception(
            b"#PF Page Fault",
            Some(error_code),
            frame.instruction_pointer,
            frame.code_segment,
            frame.cpu_flags,
            frame.stack_pointer,
        );
        vga::print(b"  CR2 (Fault): ", vga::Color::LightGray);
        vga::print_hex(cr2, vga::Color::Yellow);
        vga::print(b"\n", vga::Color::White);
    }

    // SAFETY: 치명 예외 처리
    unsafe {
        fatal_halt(b"#PF Page Fault", Some(error_code), &frame);
    }
}

// #MF: x87 Floating-Point Error (벡터 16, Fault)
extern "x86-interrupt" fn x87_fpu_handler(frame: InterruptStackFrame) {
    unsafe {
        fatal_halt(b"#MF x87 FP Error", None, &frame);
    }
}

// #AC: Alignment Check (벡터 17, Fault, 오류코드=0)
extern "x86-interrupt" fn alignment_check_handler(frame: InterruptStackFrame, error_code: u64) {
    unsafe {
        fatal_halt(b"#AC Alignment Check", Some(error_code), &frame);
    }
}

// #MC: Machine Check (벡터 18, Abort)
// 복구 불가능한 하드웨어 오류 (ECC 불가 메모리 오류, CPU 마이크로아키텍처 오류)
extern "x86-interrupt" fn machine_check_handler(frame: InterruptStackFrame) -> ! {
    // SAFETY: Abort 예외, 복구 불가능, 발산 필수
    unsafe { fatal_halt(b"#MC Machine Check (HW Error)", None, &frame) }
}

// #XM: SIMD Floating-Point Error (벡터 19, Fault)
extern "x86-interrupt" fn simd_fp_handler(frame: InterruptStackFrame) {
    unsafe {
        fatal_halt(b"#XM SIMD FP Error", None, &frame);
    }
}

// #VE: Virtualization Exception (벡터 20, Fault)
extern "x86-interrupt" fn virtualization_handler(frame: InterruptStackFrame) {
    unsafe {
        fatal_halt(b"#VE Virtualization Exception", None, &frame);
    }
}

// 기본 핸들러 (미정의/예약 벡터)
// 0x30..0xFF 범위의 모든 예약 벡터에 설치하여 Triple Fault를 방지함
extern "x86-interrupt" fn default_handler(frame: InterruptStackFrame) {
    unsafe {
        fatal_halt(b"Unexpected Interrupt/Exception", None, &frame);
    }
}

// IRQ 스텁 핸들러 (0x20..0x2F)
// PIC를 초기화 직후 모든 IRQ가 마스킹되어 있으므로, 이 핸들러들은 향후
// 특정 IRQ가 enable_irq()로 활성화될 때의 기본 처리 경로임

extern "x86-interrupt" fn irq0_handler(_frame: InterruptStackFrame) {
    // IRQ0: PIT(Programmable Interval Timer) - 향후 스케줄러와 연동
    // SAFETY: IRQ 핸들러, EOI 필수
    unsafe {
        pic_eoi_master();
    }
}

extern "x86-interrupt" fn irq_default_handler(_frame: InterruptStackFrame) {
    // IRQ1..7: 기본 처리 - EOI 후 무시
    // SAFETY: IRQ 핸들러, EOI 필수
    unsafe {
        pic_eoi_master();
    }
}

extern "x86-interrupt" fn irq_slave_default_handler(_frame: InterruptStackFrame) {
    // IRQ8..15: 기본 처리 - Slave + Master EOI 후 무시
    // SAFETY: IRQ 핸들러, Slave + Master EOI 필수
    unsafe {
        pic_eoi_slave();
    }
}

// IDT 초기화
/// IDT를 구성하고 LIDT 명령으로 CPU에 로드함.
///
/// 수행 작업:
///   1. 8259 PIC 초기화 및 IRQ 재매핑 (모든 IRQ 마스킹)
///   2. CPU 예외 핸들러 (벡터 0..20) IDT에 등록
///   3. IRQ 스텁 핸들러 (벡터 32..47) IDT에 등록
///   4. 기본 핸들러 (나머지 벡터) IDT에 등록
///   5. LIDT로 IDT 포인터를 CPU IDTR에 로드
///
/// # Safety
/// - 인터럽트 비활성화(CLI) 상태에서 호출해야 함.
/// - GDT와 TSS가 유효하게 로드된 이후에 호출해야 함.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_idt() {
    // 1. 8259 PIC 초기화
    // SAFETY: CLI 상태에서 PIC I/O 포트 접근
    unsafe {
        init_pic();
    }

    // 2. IDT 엔트리 등록
    // SAFETY: IDT는 정적 배열로 유효한 메모리, 단일 코어 초기화 구간
    unsafe {
        // CPU 예외: 오류코드 없음
        IDT[0x00] = GateDescriptor::new(
            divide_error_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );
        IDT[0x01] = GateDescriptor::new(debug_handler as *const () as usize, GATE_TRAP, 0);
        // #NMI: IST2 사용 — 주 스택 오염 상태에서도 안전한 NMI 처리 보장
        IDT[0x02] = GateDescriptor::new(nmi_handler as *const () as usize, GATE_INTERRUPT, IST_NMI);
        IDT[0x03] = GateDescriptor::new(breakpoint_handler as *const () as usize, GATE_TRAP, 0);
        IDT[0x04] = GateDescriptor::new(overflow_handler as *const () as usize, GATE_TRAP, 0);
        IDT[0x05] =
            GateDescriptor::new(bound_range_handler as *const () as usize, GATE_INTERRUPT, 0);
        IDT[0x06] = GateDescriptor::new(
            invalid_opcode_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );
        IDT[0x07] = GateDescriptor::new(
            device_not_available_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );

        // #DF: IST1 사용 (독립 스택 보장)
        IDT[0x08] = GateDescriptor::new(
            double_fault_handler as *const () as usize,
            GATE_INTERRUPT,
            IST_DOUBLE_FAULT,
        );

        // 벡터 9: Coprocessor Segment Overrun (386 전용, 더 이상 발생 안 함)
        IDT[0x09] = GateDescriptor::new(default_handler as *const () as usize, GATE_INTERRUPT, 0);

        // CPU 예외: 오류코드 있음
        IDT[0x0A] =
            GateDescriptor::new(invalid_tss_handler as *const () as usize, GATE_INTERRUPT, 0);
        IDT[0x0B] = GateDescriptor::new(
            segment_not_present_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );
        IDT[0x0C] = GateDescriptor::new(
            stack_segment_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );
        IDT[0x0D] = GateDescriptor::new(
            general_protection_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );
        // #PF: IST4 사용 — 커널 스택 가드 페이지 트리거 시 안전한 핸들러 스택으로 전환
        IDT[0x0E] = GateDescriptor::new(
            page_fault_handler as *const () as usize,
            GATE_INTERRUPT,
            IST_PAGE_FAULT,
        );
        // 0x0F: 예약
        IDT[0x10] = GateDescriptor::new(x87_fpu_handler as *const () as usize, GATE_INTERRUPT, 0);
        IDT[0x11] = GateDescriptor::new(
            alignment_check_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );
        // #MC: IST3 사용 — 복구 불가 하드웨어 오류 시 독립 스택에서 진단 수행
        IDT[0x12] = GateDescriptor::new(
            machine_check_handler as *const () as usize,
            GATE_INTERRUPT,
            IST_MACHINE_CHECK,
        );
        IDT[0x13] = GateDescriptor::new(simd_fp_handler as *const () as usize, GATE_INTERRUPT, 0);
        IDT[0x14] = GateDescriptor::new(
            virtualization_handler as *const () as usize,
            GATE_INTERRUPT,
            0,
        );
        // 0x15..0x1F: 예약 예외 -> 기본 핸들러
        let mut v = 0x0Fu8;
        while v <= 0x1F {
            if IDT[v as usize].type_attr == 0 {
                IDT[v as usize] =
                    GateDescriptor::new(default_handler as *const () as usize, GATE_INTERRUPT, 0);
            }
            v += 1;
        }

        // IRQ 스텁 핸들러 (벡터 0x20..0x2F)
        IDT[0x20] = GateDescriptor::new(irq0_handler as *const () as usize, GATE_INTERRUPT, 0);
        let mut irq = 0x21u8;
        while irq <= 0x27 {
            IDT[irq as usize] =
                GateDescriptor::new(irq_default_handler as *const () as usize, GATE_INTERRUPT, 0);
            irq += 1;
        }
        let mut irq = 0x28u8;
        while irq <= 0x2F {
            IDT[irq as usize] = GateDescriptor::new(
                irq_slave_default_handler as *const () as usize,
                GATE_INTERRUPT,
                0,
            );
            irq += 1;
        }

        // 나머지 벡터: 기본 핸들러로 채움 (Triple Fault 방지)
        let mut v = 0x30u8;
        while v != 0 {
            // 0xFF + 1 = 0 (u8 wrap)
            if IDT[v as usize].type_attr == 0 {
                IDT[v as usize] =
                    GateDescriptor::new(default_handler as *const () as usize, GATE_INTERRUPT, 0);
            }
            v = v.wrapping_add(1);
        }

        // 5. LIDT: IDT 포인터를 CPU IDTR에 로드
        let ptr = IdtPointer {
            limit: (size_of::<[GateDescriptor; 256]>() - 1) as u16,
            // &raw은 static mut에서 공유 참조 없이 원시 포인터를 생성함
            base: (&raw const IDT) as *const GateDescriptor as u64,
        };

        // SAFETY: IDT는 유효한 정적 메모리, 포인터 구조체는 스택에 임시 배치
        core::arch::asm!(
            "lidt [{ptr}]",
            ptr = in(reg) &ptr,
            options(readonly, nostack, preserves_flags),
        );
    }
}
