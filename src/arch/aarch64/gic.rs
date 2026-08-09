//! 본 모듈은 aarch64 GICv3 인터럽트 컨트롤러 bring-up 을 제공합니다.
//!
//! # Features
//! `arm-gic` 0.8.1 `gicv3::GicV3` 위임으로 redistributor 를 distributor 보다 먼저
//! 깨웁니다. GICv3 는 CPU-affine redistributor 를 통해 SGI/PPI 를
//! 라우팅하므로 redistributor 가 sleep 이면 distributor 를 enable 해도 인터럽트가
//! 코어에 도달하지 않습니다. 따라서 부팅 순서는 (1) GICR_WAKER.ProcessorSleep=0 후
//! ChildrenAsleep==0 poll 까지 block 하는 redistributor wake 를 선행하고, (2) 이후
//! GRP1 을 활성합니다.
//!
//! 디바이스 MMIO(GICD distributor / GICR redistributor)는 검증된 arm-gic 크레이트에
//! 위임하고, CPU-affine 시스템 레지스터(ICC_SRE_EL1 / ICC_IGRPEN1_EL1 / ICC_PMR_EL1 /
//! ICC_EOIR1_EL1)는 raw asm 으로 직접 배선합니다(경계 커널
//! 특권 시퀀스는 손에 쥐고 디바이스 프로토콜은 신뢰 크레이트에 위임). x86_64 `idt.rs`
//! 의 8259 PIC(init_pic / pic_eoi / enable_irq)에 role-match 하되 GICv3 는 전혀 다른
//! 모델이라 인코딩은 전량 divergent 합니다.
//!
//! boot proof 마커(GICR wake OK / ChildrenAsleep=0 / GRP1 enabled / IRQ N delivered)는
//! release 빌드에서도 관측되어야 하므로 `console::write_bytes` 로 무조건 emit 합니다.

use arm_gic::{
    InterruptGroup, IntId, UniqueMmioPointer,
    gicv3::{
        GicCpuInterface, GicV3, Group, SgiTarget, SgiTargetGroup,
        registers::{Gicd, GicrSgi},
    },
};
use core::ptr::NonNull;

use crate::arch::aarch64::{console, cpu};

/// QEMU virt GICv3 distributor MMIO 물리 기본 주소 (폴백 기본값, DTB/BootInfo 우선)
const GICD_PHYS_BASE: usize = 0x0800_0000;

/// QEMU virt GICv3 redistributor MMIO 물리 기본 주소 (폴백 기본값, DTB/BootInfo 우선)
const GICR_PHYS_BASE: usize = 0x080A_0000;

/// GICv3 distributor register block 기저 포인터 (MMU 전 identity 물리, 후 선형 VA)
static mut GICD_BASE: *mut Gicd = GICD_PHYS_BASE as *mut Gicd;

/// GICv3 redistributor SGI/PPI register block 기저 포인터 (MMU 전 identity 물리, 후 선형 VA)
static mut GICR_BASE: *mut GicrSgi = GICR_PHYS_BASE as *mut GicrSgi;

/// BSP 단일 코어 redistributor 선형 인덱스
const BOOT_CPU: usize = 0;

/// 부팅 proof 용 self-IPI SGI 번호 (INTID 3 software generated interrupt)
const BOOT_PROOF_SGI: u32 = 3;

/// 부팅 proof SGI 의 IntId (컴파일 타임 상수화로 런타임 assert panic 경로 배제)
const BOOT_SGI_INTID: IntId = IntId::sgi(BOOT_PROOF_SGI);

/// GICD/GICR 백엔드 base 를 MMU 활성 후 커널 선형 매핑 가상 주소로 갱신함.
///
/// 이 함수를 호출하지 않으면 MMU 전 identity 물리 주소로 계속 동작함(TTBR0 identity
/// 유지 시에도 유효하나 커널 고주소 매핑 일원화를 위해 갱신). console::update_base 대응.
///
/// # Safety
/// `mmu_enable` 완료 후, 선형 매핑이 GICD/GICR MMIO 페이지를 Device-nGnRE 로 포함하도록
/// 구축된 이후에만 호출해야 함.
pub unsafe fn update_base(gicd_virt: *mut u8, gicr_virt: *mut u8) {
    // SAFETY 부팅 초기 단일 코어 시퀀스에서만 갱신되는 백엔드 base
    unsafe {
        *(&raw mut GICD_BASE) = gicd_virt as *mut Gicd;
        *(&raw mut GICR_BASE) = gicr_virt as *mut GicrSgi;
    }
}

/// 현재 base 로 arm-gic `GicV3` 드라이버 인스턴스를 구성함.
///
/// # Safety
/// `GICD_BASE`/`GICR_BASE` 가 유효한 device MMIO(물리 identity 또는 선형 매핑 VA)를
/// 가리키고 다른 별칭이 없어야 함. 부팅 초기 단일 코어 계약이 이를 보장함.
unsafe fn construct() -> GicV3<'static> {
    // SAFETY GICD_BASE/GICR_BASE 는 non-null 상수(0x0800_0000/0x080A_0000)이거나
    //        non-null 선형 VA 로만 갱신되므로 new_unchecked 가 안전함
    unsafe {
        let gicd_ptr = *(&raw const GICD_BASE);
        let gicr_ptr = *(&raw const GICR_BASE);
        let gicd = UniqueMmioPointer::new(NonNull::new_unchecked(gicd_ptr));
        let gicr = NonNull::new_unchecked(gicr_ptr);
        GicV3::new(gicd, gicr, 1, false)
    }
}

/// GIC CPU 인터페이스 시스템 레지스터 활성 (ICC_SRE_EL1.SRE=1 + ICC_PMR_EL1 + ICC_IGRPEN1_EL1=1).
///
/// 디바이스 MMIO(GICD/GICR)는 arm-gic 에 위임하되 CPU-affine 시스템 레지스터는 raw asm
/// 으로 직접 배선함. SRE=1 을 먼저 세운 뒤 ISB 로 동기화해야 이후 ICC_* 접근이 유효하며,
/// ICC_PMR_EL1 을 0xFF 로 개방하고 ICC_IGRPEN1_EL1 을 1 로 세워 Group1 IRQ 전달을 활성함.
///
/// # Safety
/// 부팅 초기 단일 코어 시퀀스에서 redistributor wake 이후 EL1 에서 1 회만 호출해야 함.
unsafe fn enable_cpu_interface() {
    // SAFETY EL1 에서 ICC_SRE_EL1.SRE set 후 ISB 로 동기화하고 IGRPEN1/PMR 을 설정함
    unsafe {
        core::arch::asm!(
            "mrs {t}, icc_sre_el1",
            "orr {t}, {t}, #1",             // ICC_SRE_EL1.SRE = 1 system register 인터페이스 활성
            "msr icc_sre_el1, {t}",
            "isb",
            "mov {t}, #0xff",
            "msr icc_pmr_el1, {t}",         // ICC_PMR_EL1 priority mask 전면 개방
            "mov {t}, #1",
            "msr icc_igrpen1_el1, {t}",     // ICC_IGRPEN1_EL1 = 1 Group1 IRQ 전달 활성
            "isb",
            t = out(reg) _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// GICv3 를 bring-up 하여 redistributor 를 distributor 보다 먼저 깨우고 GRP1 을 활성함.
///
/// 아래 순서를 강제함
/// (1) GICR_WAKER.ProcessorSleep=0 후 ChildrenAsleep==0 poll 까지 block (arm-gic
///     redistributor MMIO 위임) 로 `GICR wake OK` / `ChildrenAsleep=0` 마커
/// (2) distributor/redistributor default 설정 + GRP1 활성(arm-gic) + ICC_SRE_EL1.SRE=1
///     + ICC_IGRPEN1_EL1=1 (raw 시스템 레지스터 명시) 로 `GRP1 enabled` 마커
/// redistributor 가 sleep 이면 distributor enable 해도 SGI/PPI 가 코어에 미도달하므로
/// wake 를 반드시 선행함.
///
/// # Safety
/// 부팅 초기 단일 코어 시퀀스에서 MMU 활성 및 VBAR_EL1 로드 이후 1 회만 호출해야 함.
pub unsafe fn setup() {
    // SAFETY construct 의 GICD/GICR base 유효성 계약을 승계하며 EL1 에서 1 회 호출
    unsafe {
        let mut gic = construct();

        // (1) redistributor wake FIRST GICR_WAKER MMIO (arm-gic 위임 ChildrenAsleep clear 까지 block)
        let _ = gic.redistributor_mark_core_awake(BOOT_CPU);
        console::write_bytes(b"GICR wake OK\r\n");
        console::write_bytes(b"ChildrenAsleep=0\r\n");

        // (2) distributor/redistributor default + GRP1 GICD/GICR MMIO (arm-gic 위임)
        //     setup 은 wake 이후 순서로 distributor 를 구성함(내부 mark_core_awake 는 재호출
        //     시 AlreadyAwake 로 무해히 무시됨). 이후 CPU 인터페이스 시스템 레지스터를 raw asm
        //     으로 명시 재확인하여 ICC_SRE_EL1.SRE=1 / ICC_IGRPEN1_EL1=1 을 손에 쥐고 봉인함
        gic.setup(BOOT_CPU);
        enable_cpu_interface();
        console::write_bytes(b"GRP1 enabled\r\n");
    }
}

/// 지정 IRQ 라인을 GICD_ISENABLER/GICR_ISENABLER0 로 활성함 (x86 PIC 마스크 해제 대응).
///
/// SGI/PPI 는 redistributor 의 GICR_ISENABLER0, SPI 는 distributor 의 GICD_ISENABLER 로
/// arm-gic `enable_interrupt` 이 자동 분기함.
///
/// # Safety
/// 해당 IRQ 에 유효한 벡터 경로가 준비되고 setup() 이 완료된 이후에 호출해야 함.
pub unsafe fn enable_irq(irq: u8) {
    // SAFETY construct 의 GICD/GICR base 유효성 계약을 승계하며 EL1 에서 호출
    unsafe {
        if let Ok(intid) = IntId::try_from(irq as u32) {
            let mut gic = construct();
            let _ = gic.enable_interrupt(intid, Some(BOOT_CPU), true); // GICD/GICR ISENABLER
        }
    }
}

/// 지정 IRQ 에 EOI 를 통지함 ICC_EOIR1_EL1 (x86 pic_eoi 대응).
///
/// 디바이스 MMIO 가 아닌 CPU-affine 시스템 레지스터이므로 raw asm 으로 직접 배선함.
///
/// # Safety
/// IRQ 핸들러 컨텍스트에서 해당 INTID 를 ACK 한 이후에만 호출해야 함.
pub unsafe fn eoi(irq: u8) {
    // SAFETY ICC_EOIR1_EL1 write 는 EL1 IRQ 핸들러 컨텍스트에서 안전함
    unsafe {
        core::arch::asm!(
            "msr icc_eoir1_el1, {v}",
            v = in(reg) irq as u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// 부팅 proof 용 self-IPI(SGI INTID 3)를 설정하고 자기 자신에게 발생시킴.
///
/// GICR_ISENABLER0 세트(arm-gic enable_interrupt) + Group1 배치 + priority 설정 후
/// DAIF.I 를 해제하고 ICC_SGI1R_EL1(GicCpuInterface::send_sgi)로 self-IPI 를 발생시켜
/// 벡터 IRQ 경로 진입을 확인함. virtual timer PPI 대신 SGI 를 사용하는 이유는 cortex-a72
/// FEAT_RNG/타이머 설정에 무관하게 결정적으로 delivery 가능하기 때문임(부팅 proof 1 회).
///
/// # Safety
/// setup()(GRP1 활성) 및 VBAR_EL1 로드 이후 부팅 초기 단일 코어 시퀀스에서 1 회만 호출.
pub unsafe fn deliver_boot_proof_irq() {
    // SAFETY setup() 로 SRE=1/GRP1/PMR 개방 완료 후 호출되며 EL1 에서 1 회 호출
    unsafe {
        let mut gic = construct();
        // SGI 를 Group1 비보안 배치 + 최고 priority + GICR_ISENABLER0 세트 (arm-gic 위임)
        let _ = gic.set_group(BOOT_SGI_INTID, Some(BOOT_CPU), Group::Group1NS);
        let _ = gic.set_interrupt_priority(BOOT_SGI_INTID, Some(BOOT_CPU), 0x00);
        let _ = gic.enable_interrupt(BOOT_SGI_INTID, Some(BOOT_CPU), true); // GICR ISENABLER0

        // DAIF.I 해제 후 self-IPI 발생 ICC_SGI1R_EL1 (GicCpuInterface::send_sgi 위임)
        cpu::interrupts_enable();
        let _ = GicCpuInterface::send_sgi(
            BOOT_SGI_INTID,
            SgiTarget::List {
                affinity3: 0,
                affinity2: 0,
                affinity1: 0,
                target_list: 0b1,
            },
            SgiTargetGroup::CurrentGroup1,
        );
    }
}

/// IRQ 벡터 진입 시 벡터 asm(`aarch64_irq_current_el`)에서 `bl` 로 진입하는 디스패처.
///
/// ICC_IAR1_EL1(GicCpuInterface::get_and_acknowledge_interrupt)로 INTID 를 ACK 하여
/// `IRQ N delivered` 마커(N 은 실제 INTID)를 emit 하고 ICC_EOIR1_EL1
/// (GicCpuInterface::end_interrupt)로 통지함. spurious(INTID 1023)는 무시함.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_irq_dispatch() {
    if let Some(intid) = GicCpuInterface::get_and_acknowledge_interrupt(InterruptGroup::Group1) {
        // SAFETY console 백엔드는 부팅 초기 유효 초기화되어 IRQ 컨텍스트에서 emit 안전
        unsafe {
            emit_irq_marker(u32::from(intid)); // IRQ N delivered
        }
        GicCpuInterface::end_interrupt(intid, InterruptGroup::Group1); // ICC_EOIR1_EL1
    }
}

/// `IRQ N delivered` 마커를 emit 함 (N 은 실제 INTID 십진 표기 no_std no-alloc 스택 변환).
///
/// # Safety
/// console 백엔드(`PL011_BASE`)가 유효 초기화된 상태에서만 호출해야 함.
unsafe fn emit_irq_marker(intid: u32) {
    // "IRQ " + decimal(intid) + " delivered" (십진수는 스택 버퍼에 역순 채운 뒤 정렬)
    let mut rev = [0u8; 10];
    let mut n = intid;
    let mut r = 0usize;
    if n == 0 {
        rev[0] = b'0';
        r = 1;
    } else {
        while n > 0 {
            rev[r] = b'0' + (n % 10) as u8;
            n /= 10;
            r += 1;
        }
    }
    let mut dec = [0u8; 10];
    let mut d = 0usize;
    while r > 0 {
        r -= 1;
        dec[d] = rev[r];
        d += 1;
    }
    // SAFETY console 백엔드 유효성 계약을 호출자가 승계
    unsafe {
        console::write_bytes(b"IRQ ");
        console::write_bytes(&dec[..d]);
        console::write_bytes(b" delivered\r\n");
    }
}
