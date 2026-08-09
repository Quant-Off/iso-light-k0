//! 본 모듈은 aarch64 Ring 3(EL0) 최초 진입 `eret` 시퀀스를 담습니다.
//!
//! # Features
//! TTBR0_EL1 적재 다음 TLB flush, ELR_EL1/SP_EL0/SPSR_EL1 세팅, `eret` 를 단일
//! atomic asm 블록으로 실행하여 EL1(커널)에서 EL0(사용자) 컨텍스트로 권한 강하합니다.
//! x86_64 `process_entry.rs` 의 `mov cr3 + GS 전환 + iretq` 를 role-match 하는 BootEntry
//! HAL trait 의 aarch64 구현 표면이며 x86 iretq 와 동일 `BootEntry::enter_user` 뒤에서
//! 합류합니다.
//!
//! # DIVERGENCE
//!   - `mov cr3` 대응은 `msr ttbr0_el1` + isb + `tlbi vmalle1` + `dsb ish` (TLB flush 명시).
//!   - GS-base 전환 대응 없음 (EL0 스택은 SP_EL0 별도 레지스터).
//!   - iretq frame(SS/RSP/RFLAGS/CS/RIP) 대응은 `msr elr_el1`(RIP) + `msr sp_el0`(RSP)
//!     + `msr spsr_el1`(EL0t 모드) + `eret` 로 대응함 (x86 유저 세그먼트 셀렉터 개념 부재, SPSR_EL1.M[4:0]=0 이 EL0 모드 선택).
//!
//! # Authors
//! Q. T. Felix

/// 사용자 주소 공간(TTBR0)을 활성화하고 EL0 사용자 엔트리로 강하함. 결코 반환하지 않음.
///
/// # Arguments
/// `ttbr0` - 사용자 주소 공간 루트 물리 주소 (x86 cr3 대응, TTBR0_EL1 에 적재)
/// `entry` - 사용자 엔트리 포인트 가상 주소 (x86 push rip 대응, ELR_EL1)
/// `stack` - 사용자 스택 최상단 가상 주소 (x86 push rsp 대응, SP_EL0)
///
/// # Safety
/// - `ttbr0` 는 커널 상위 절반(TTBR1) 매핑을 계승한 유효 사용자 주소 공간 루트여야 함.
/// - 호출 전에 벡터 테이블(VBAR_EL1) + SVC 진입 경로가 준비되어 있어야 함.
/// - 인터럽트 마스크 상태에서 호출 권장 (SPSR_EL1=EL0t 로 DAIF 초기값이 EL0 에 적재됨).
pub unsafe fn enter_user(ttbr0: u64, entry: u64, stack: u64) -> ! {
    // SAFETY: 아래 asm 블록은 단일 atomic 시퀀스로 ttbr0 적재 다음 TLB flush,
    //         elr_el1/sp_el0/spsr_el1 세팅, eret 순으로 실행하며 사이에 어떤 high-level
    //         연산도 끼지 않음 SPSR_EL1=0 은 M[4:0]=0(EL0t) 이며 eret 가 EL0 로 강하함
    unsafe {
        core::arch::asm!(
            // 1. 사용자 주소 공간 루트 적재 (x86 mov cr3 대응)
            "msr ttbr0_el1, {ttbr0}",
            "isb",
            // 2. 전 EL1 매핑 TLB flush (x86 cr3 재로드 시 TLB 자동 flush 대응)
            "tlbi vmalle1",
            "dsb ish",
            // 3. EL0 엔트리 / 스택 (x86 iretq frame push rip/rsp 대응)
            "msr elr_el1, {entry}",
            "msr sp_el0, {stack}",
            // 4. SPSR_EL1 = EL0t (M[4:0]=0, DAIF 초기값) xzr 로 0 직접 적재
            //    (x86 iretq CS RPL=3 + RFLAGS 대응). noreturn 은 출력 오퍼랜드 불가이므로
            //    스크래치 레지스터 대신 zero register 사용
            "msr spsr_el1, xzr",
            // 5. EL0 강하 (x86 iretq 대응)
            "eret",
            ttbr0 = in(reg) ttbr0,
            entry = in(reg) entry,
            stack = in(reg) stack,
            options(noreturn),
        );
    }
}
