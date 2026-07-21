//! 본 모듈은 aarch64 CPU 특권 명령 표면(DAIF/WFI/CNTVCT_EL0/CPACR_EL1/PAN)을 raw asm 으로 배선합니다.
//!
//! # Features
//! x86_64 `cpu.rs` 자유 함수와 1:1 대응하는 aarch64 구현을 제공합니다. 인터럽트
//! 마스킹은 DAIF, user 접근 창은 PAN, FP/SIMD 트랩 해제는 CPACR_EL1.FPEN 으로
//! 매핑하며 cycle counter 는 CNTVCT_EL0 을 읽습니다. PAN 은 FEAT_PAN(ARMv8.1)
//! 부재 CPU(cortex-a72)에서 ID_AA64MMFR1_EL1.PAN 런타임 탐지 후 no-op 로
//! 강등되어(x86 SMAP stac/clac 게이트 대응) 미구현 코어에서의 undefined 예외를
//! 차단합니다.

use crate::arch::cpu::TimerKind;

/// FEAT_PAN(Privileged Access Never) 구현 여부를 런타임 탐지함.
///
/// `ID_AA64MMFR1_EL1.PAN`(bits[23:20]) 이 0 이 아니면 구현으로 판정하며
/// x86 `features().smap` 게이트에 대응함. cortex-a72(ARMv8.0-A)는 미구현이라
/// false 를 반환하므로 `msr pan` 을 실행하지 않음.
fn pan_supported() -> bool {
    let mmfr1: u64;
    // SAFETY ID_AA64MMFR1_EL1 은 EL1 읽기 전용 식별 레지스터로 부작용 없음
    unsafe {
        core::arch::asm!(
            "mrs {v}, id_aa64mmfr1_el1",
            v = out(reg) mmfr1,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((mmfr1 >> 20) & 0xF) != 0
}

/// user 메모리 접근 창 개방(PAN 해제, x86 `stac` 대응).
///
/// # Safety
/// 짝이 되는 `user_access_end` 와 반드시 쌍으로 호출해야 하며 user 메모리 접근
/// 직전에만 열고 즉시 닫아야 함. FEAT_PAN 미구현 코어에서는 no-op 로 강등됨.
pub unsafe fn user_access_begin() {
    if pan_supported() {
        // SAFETY FEAT_PAN 구현 확인 후에만 실행하여 undefined 예외를 차단함
        unsafe {
            core::arch::asm!(
                ".arch_extension pan",
                "msr pan, #0",
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

/// user 메모리 접근 창 폐쇄(PAN 설정, x86 `clac` 대응).
///
/// # Safety
/// `user_access_begin` 직후 user 메모리 작업이 끝난 즉시 호출해야 함.
pub unsafe fn user_access_end() {
    if pan_supported() {
        // SAFETY FEAT_PAN 구현 확인 후에만 실행함
        unsafe {
            core::arch::asm!(
                ".arch_extension pan",
                "msr pan, #1",
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

/// 인터럽트 비활성(IRQ mask, x86 `cli` 대응).
///
/// # Safety
/// EL1 특권 레벨에서만 호출하며 임계 구역 종료 시 `interrupts_enable` 로
/// 복구해야 함.
pub unsafe fn interrupts_disable() {
    // SAFETY DAIF.I set 은 EL1 에서 실행 가능하며 호출자가 복구 계약을 승계
    unsafe {
        core::arch::asm!("msr daifset, #0b0010", options(nomem, nostack, preserves_flags));
    }
}

/// 인터럽트 활성(IRQ unmask, x86 `sti` 대응).
///
/// # Safety
/// 벡터 테이블(VBAR_EL1) 초기화 완료 후에만 호출해야 함.
pub unsafe fn interrupts_enable() {
    // SAFETY DAIF.I clear 는 벡터 테이블 초기화 이후에만 호출됨을 호출자가 보장
    unsafe {
        core::arch::asm!("msr daifclr, #0b0010", options(nomem, nostack, preserves_flags));
    }
}

/// 다음 인터럽트까지 CPU 를 일시 정지시키는 대기 명령(`wfi`, x86 `hlt` 대응).
pub fn wait_for_interrupt() {
    // SAFETY wfi 는 다음 인터럽트까지 CPU 를 정지시키는 안전한 명령
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack, preserves_flags));
    }
}

/// 복구 불가 상태의 CPU 영구 정지 루프(panic fail-stop 전용, x86 `cli;hlt` 대응).
///
/// DAIF 전 필드를 mask 하여 인터럽트를 차단한 뒤 `wfi` 로 정지시키며 spurious
/// wake 에 대비해 무한 루프로 감쌈. 결코 반환하지 않음.
pub fn halt_loop() -> ! {
    loop {
        // SAFETY daifset 전 필드 mask + wfi 는 EL1 에서 임의 시점 안전 실행 가능
        unsafe {
            core::arch::asm!("msr daifset, #0b1111", "wfi", options(nomem, nostack, preserves_flags));
        }
    }
}

/// FP/SIMD 유닛 활성화(CPACR_EL1.FPEN = 0b11).
///
/// EL0/EL1 의 Advanced SIMD & FP 트랩을 해제함. softfloat 타깃이라 belt-and
/// -suspenders 성격이나 elib-k0-nt 의 generic 경로 호환을 위해 배선함.
///
/// # Safety
/// 부팅 초기 단일 코어 시퀀스에서 1 회만 호출해야 함.
pub unsafe fn enable_simd_fpu() {
    // SAFETY CPACR_EL1 RMW 는 EL1 에서 수행하며 isb 로 후속 명령 동기화
    unsafe {
        core::arch::asm!(
            "mrs {t}, cpacr_el1",
            "orr {t}, {t}, #(0b11 << 20)",
            "msr cpacr_el1, {t}",
            "isb",
            t = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// CPU 보안 비트 활성화(SCTLR_EL1.WXN set + SPAN clear).
///
/// WXN(bit19) 은 쓰기 가능 페이지의 실행을 금지(W^X 강제)하고 SPAN(bit23) clear
/// 는 예외 진입 시 PAN 을 자동 set 하게 함(FEAT_PAN 미구현 코어에서 해당 비트는
/// RES0 이라 무해). PAN/UAO PSTATE 즉시 세팅은 기능 부재 코어의 undefined 를
/// 피하기 위해 SCTLR_EL1 RMW 로만 배선함.
///
/// # Safety
/// 부팅 초기 단일 코어 시퀀스에서 1 회만 호출해야 함.
pub unsafe fn enable_security_bits() {
    // SAFETY SCTLR_EL1 RMW 는 EL1 에서 수행하며 미지원 비트는 RES0 로 무시됨
    unsafe {
        core::arch::asm!(
            "mrs {t}, sctlr_el1",
            "orr {t}, {t}, #(1 << 19)",
            "bic {t}, {t}, #(1 << 23)",
            "msr sctlr_el1, {t}",
            "isb",
            t = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// FP/SIMD 설정 마무리(지연 초기화 잔여 확정).
///
/// aarch64 는 CPACR_EL1 단일 배선으로 충분하여 잔여 재적용이 없음. x86 의
/// CR0/CR4 재검증 표면과 계약 대칭을 위해 no-op 로 존속함.
///
/// # Safety
/// `enable_simd_fpu` 호출 이후에만 호출해야 함.
pub unsafe fn finalize_simd_fpu() {}

/// CPU cycle counter 읽기(가상 카운터 CNTVCT_EL0, x86 `rdtsc` 대응).
///
/// CNTVCT_EL0 은 항상 존재하므로 탐지가 불요함.
pub fn cycle_counter() -> u64 {
    let cnt: u64;
    // SAFETY CNTVCT_EL0 은 EL0/EL1 읽기 전용 가상 카운터로 부작용 없음
    unsafe {
        core::arch::asm!("mrs {v}, cntvct_el0", v = out(reg) cnt, options(nomem, nostack, preserves_flags));
    }
    cnt
}

/// 타이머 주파수 Hz 탐지(CNTFRQ_EL0). 0 이면 미설정으로 보고 None 으로 lifting 함.
pub fn timer_frequency() -> Option<(u64, TimerKind)> {
    let hz: u64;
    // SAFETY CNTFRQ_EL0 은 EL0/EL1 읽기 전용 주파수 레지스터로 부작용 없음
    unsafe {
        core::arch::asm!("mrs {v}, cntfrq_el0", v = out(reg) hz, options(nomem, nostack, preserves_flags));
    }
    if hz != 0 {
        Some((hz, TimerKind::InvariantTsc))
    } else {
        None
    }
}
