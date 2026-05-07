//! x86_64 초기 부팅 시퀀스를 수행하는 모듈입니다.
//!
//! 부팅 직후(부트로더 -> 커널 핸드오프) 수행해야 할 하드웨어 초기화는
//!   1. GDT(Global Descriptor Table) 로드로 세그먼트 기반 보호 모드 설정.
//!   2. TSS(Task State Segment) 디스크립터를 GDT에 등록 + LTR로 로드.
//!   3. CS/DS/SS/FS/GS 세그먼트 레지스터 갱신.
//!
//! GDT는 플랫 메모리 모델을 제공하며, 실질적인 메모리 보호는 이후
//! 페이징(4단계 페이지 테이블)이 담당합니다.
//!
//! GDT 레이아웃 (40 bytes = 5 x 8):
//!   [0] 0x00  Null 디스크립터 (8 bytes)
//!   [1] 0x08  커널 코드 64비트 (8 bytes)  (KERNEL_CS)
//!   [2] 0x10  커널 데이터       (8 bytes)  (KERNEL_DS)
//!   [3] 0x18  TSS Low          (8 bytes)  (TSS_SELECTOR, 64비트 시스템 디스크립터 하위)
//!   [4] 0x20  TSS High         (8 bytes)  (64비트 시스템 디스크립터 상위)
//!
//! 64비트 TSS 시스템 디스크립터는 16바이트(2 GDT 슬롯)를 사용합니다
//! (Intel SDM Vol.3A Fig 7-4).

use core::mem::size_of;

//
// GDT 셀렉터 상수
//

/// Ring 0 코드 세그먼트 셀렉터: GDT[1], RPL=0
pub const KERNEL_CS: u16 = 0x08;
/// Ring 0 데이터 세그먼트 셀렉터: GDT[2], RPL=0
pub const KERNEL_DS: u16 = 0x10;
/// TSS 셀렉터: GDT[3], RPL=0 (64-bit 시스템 디스크립터 하위 8바이트)
pub const TSS_SELECTOR: u16 = 0x18;

//
// 정적 커널 GDT (가변, TSS 디스크립터 런타임 패칭 필요)
//

/// 커널 GDT (5 × 8 bytes = 40 bytes).
///
/// GDT[3..4]는 TSS 디스크립터(16바이트)를 위해 예약된 두 슬롯으로,
/// `init_gdt()`에서 런타임에 TSS 주소/크기로 채워짐.
/// TSS 주소는 컴파일 타임 상수가 아니므로 `static mut`으로 선언함.
///
/// # Safety
/// `init_gdt()` 호출 전까지 GDT[3..4]는 0(Null)이므로 LTR 이전에 유효함.
// SAFETY: 부팅 초기 단일 코어, init_gdt()에서 한 번만 초기화됨
static mut KERNEL_GDT: [u64; 5] = [
    0,                     // [0] Null 디스크립터
    0x00AF_9A00_0000_FFFF, // [1] 커널 코드 64비트 (P=1, DPL=0, L=1, Type=Execute/Read)
    0x00CF_9200_0000_FFFF, // [2] 커널 데이터      (P=1, DPL=0, G=1, D/B=1, Type=Read/Write)
    0,                     // [3] TSS Low  (런타임 패칭)
    0,                     // [4] TSS High (런타임 패칭)
];

//
// LGDT 명령어 피연산자
//

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct GdtPointer {
    /// GDT 크기 - 1 (bytes)
    limit: u16,
    /// GDT 물리(선형) 기저 주소
    base: u64,
}

//
// TSS 디스크립터 빌더
//
// 64비트 시스템 디스크립터 레이아웃 (Intel SDM Vol.3A Figure 7-4):
//
//  Low 8 bytes:
//    bits[15: 0] = Limit[15:0]
//    bits[39:16] = Base[23:0]
//    bits[43:40] = Type = 0x9 (64-bit TSS Available)
//    bits[44]    = S    = 0   (시스템 세그먼트)
//    bits[46:45] = DPL  = 0   (Ring 0 전용)
//    bits[47]    = P    = 1   (Present)
//    bits[51:48] = Limit[19:16]
//    bits[55:52] = AVL/L/D/G  = 0
//    bits[63:56] = Base[31:24]
//
//  High 8 bytes:
//    bits[31: 0] = Base[63:32]
//    bits[63:32] = 0 (예약, 반드시 0)

/// TSS 디스크립터 하위 8바이트(Low GDT 슬롯) 생성.
const fn tss_desc_low(base: u64, limit: u16) -> u64 {
    let limit = limit as u64;
    // Limit[15:0]
    (limit & 0xFFFF)
    // Base[23:0] -> bits[39:16]
    | ((base & 0x00FF_FFFF) << 16)
    // P=1, DPL=0, S=0, Type=0x9 -> type_attr=0x89 -> bits[47:40]
    | (0x89u64 << 40)
    // Limit[19:16] -> bits[51:48]
    | (((limit >> 16) & 0xF) << 48)
    // AVL/L/D/G = 0 (bits[55:52])
    // Base[31:24] -> bits[63:56]
    | (((base >> 24) & 0xFF) << 56)
}

/// TSS 디스크립터 상위 8바이트(High GDT 슬롯) 생성.
const fn tss_desc_high(base: u64) -> u64 {
    // Base[63:32] -> bits[31:0], 상위 32비트는 예약(0)
    (base >> 32) & 0xFFFF_FFFF
}

//
// 초기화 함수
//

/// GDT에 TSS 디스크립터를 등록하고, CPU에 GDT를 로드하고, TSS를 TR에 로드함.
///
/// 수행 순서:
///   1. TSS 기저 주소/크기로 GDT[3..4] 패칭
///   2. LGDT로 새 GDT 로드
///   3. far return으로 CS = KERNEL_CS(0x08) 재로드
///   4. DS/ES/SS/FS/GS = KERNEL_DS(0x10) 갱신
///   5. LTR로 TR = TSS_SELECTOR(0x18) 로드
///
/// # Safety
/// - 반드시 인터럽트 비활성화(`cli`) 상태에서 호출해야 함.
/// - `tss::init()`이 먼저 호출되어 IST가 유효한 상태여야 함.
/// - `tss_base`가 유효한 물리 주소여야 함.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_gdt(tss_base: u64, tss_limit: u16) {
    // SAFETY: 단일 코어 부팅 초기, CLI 상태
    unsafe {
        // 1. TSS 디스크립터 패칭
        KERNEL_GDT[3] = tss_desc_low(tss_base, tss_limit);
        KERNEL_GDT[4] = tss_desc_high(tss_base);

        // 2. LGDT + 세그먼트 재로드
        let ptr = GdtPointer {
            limit: (size_of::<[u64; 5]>() - 1) as u16,
            // &raw은 static mut에서 공유 참조 없이 원시 포인터를 생성함
            base: (&raw const KERNEL_GDT) as *const u64 as u64,
        };

        // SAFETY:
        // 1. KERNEL_GDT는 올바른 64비트 플랫 세그먼트 + TSS 디스크립터를 포함함
        // 2. lgdt 이후 far return(retfq)으로 CS를 KERNEL_CS(0x08)로 안전하게 재로드함
        // 3. mov를 통해 나머지 세그먼트 레지스터를 KERNEL_DS(0x10)으로 설정함
        // 4. ltr로 TR을 TSS_SELECTOR(0x18)로 설정함
        core::arch::asm!(
            // GDT 로드
            "lgdt [{ptr}]",
            // CS 재로드: far return을 통해 새 코드 세그먼트 셀렉터 적용
            "push 8",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            // 데이터/스택 세그먼트 레지스터 갱신 (KERNEL_DS = 0x10)
            "mov ax, 16",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            // FS/GS 초기화 (TLS는 별도 MSR 설정)
            "xor eax, eax",
            "mov fs, ax",
            "mov gs, ax",
            // TSS 로드: TR = TSS_SELECTOR (0x18)
            // ltr 명령어는 TSS를 Busy(0xB)로 표시함
            "mov ax, {tss_sel}",
            "ltr ax",
            ptr     = in(reg) &ptr,
            tmp     = lateout(reg) _,
            tss_sel = const TSS_SELECTOR,
            lateout("eax") _,
        );
    }
}
