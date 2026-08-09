//! arch 디렉토리 루트 cfg-conditional re-export hub
//!
//! # Features
//! 디렉토리 골격 루트입니다. arch-중립 모듈은 `common` 아래에,
//! x86_64 전용 어댑터는 `x86_64` 아래에 배치되며 활성 아키텍처는 `active` 별칭으로
//! 노출됩니다. HAL trait 추출은 본 골격 위에 trait 정의만 추가하면 됩니다.

pub mod common;
pub mod cpu;

// 음성 probe feature 게이트 (production 빌드 미포함)
#[cfg(feature = "mmu-typestate-probe")]
pub mod mmu_typestate_probe;

//
// 6 HAL trait 단일 파일 정의
//
// 모든 메서드는 수신자 없는 associated fn 으로 정적 디스패치만 가능하며
// trait object 화가 구조적으로 차단
// trait 선언부에는 attr 를 달지 않고 impl 측이 #[inline(always)] 를 강제
// 본체는 trait 을 직접 호출하지 않고 기존 free fn 경로를 유지
// trait 은 aarch64 가 동일 표면을 구현하도록 강제하는 컴파일 타임 계약임
//

/// CPU 특권 명령 표면에 대한 arch-중립 계약.
///
/// 구현체는 ZST (x86_64 는 기존 free fn 위임) 이며 aarch64 가
/// 동일 표면을 구현함.
///
/// # 보안 불변식
/// 1. `user_access_begin` / `user_access_end` 는 SMAP(x86 stac/clac) / PAN(aarch64)
///    user 메모리 접근 창을 여닫는 유일한 표면이며 반드시 쌍으로 호출됨.
/// 2. 접근 창 내부에서는 검증된 user 버퍼 복사만 수행함 (zero-trust 경계).
#[allow(dead_code)]
pub trait Cpu {
    /// SMAP(x86 stac) / PAN(aarch64) user 접근 창 개방.
    ///
    /// # Safety
    /// 짝이 되는 `user_access_end` 와 반드시 쌍으로 호출해야 함.
    /// 접근 창은 user 메모리 접근 직전에만 열고 즉시 닫아야 함.
    unsafe fn user_access_begin();

    /// user 접근 창 폐쇄. `user_access_begin` 으로 연 창을 닫음.
    ///
    /// # Safety
    /// `user_access_begin` 직후 user 메모리 작업이 끝난 즉시 호출해야 함.
    unsafe fn user_access_end();

    /// 인터럽트 비활성 (x86 cli / aarch64 daifset).
    ///
    /// # Safety
    /// 커널 특권 레벨에서만 호출하며 임계 구역 종료 시 `interrupts_enable` 로 복구해야 함.
    unsafe fn interrupts_disable();

    /// 인터럽트 활성 (x86 sti / aarch64 daifclr).
    ///
    /// # Safety
    /// IDT/벡터 테이블 초기화 완료 후에만 호출해야 함.
    unsafe fn interrupts_enable();

    /// 다음 인터럽트까지 CPU 대기 (x86 hlt / aarch64 wfi).
    fn wait_for_interrupt();

    /// 복구 불가 상태의 영구 정지 루프 (panic 경로 전용).
    fn halt_loop() -> !;

    /// FP/SIMD 유닛 활성화.
    ///
    /// # Safety
    /// 부팅 초기 단일 코어 시퀀스에서 1 회만 호출해야 함.
    unsafe fn enable_simd_fpu();

    /// CPU 보안 비트 (SMEP/SMAP/UMIP 등) 활성화.
    ///
    /// # Safety
    /// 부팅 초기 단일 코어 시퀀스에서 1 회만 호출해야 함.
    unsafe fn enable_security_bits();

    /// FP/SIMD 설정 마무리 (지연 초기화 잔여분 확정).
    ///
    /// # Safety
    /// `enable_simd_fpu` 호출 이후에만 호출해야 함.
    unsafe fn finalize_simd_fpu();

    /// CPU cycle counter 읽기 (x86 rdtsc / aarch64 cntvct_el0).
    fn cycle_counter() -> u64;

    /// 타이머 주파수 Hz 탐지. 탐지 불가 시 None.
    fn timer_frequency() -> Option<(u64, cpu::TimerKind)>;
}

/// MMU 활성화 3 단계 전이에 대한 arch-중립 계약.
///
/// phantom-type 기반 typestate 강제는 기존 `crate::mmu::Mmu<State>` 구체 타입이
/// 담당하며 본 trait 은 전이 표면의 명명만 고정함.
///
/// # 보안 불변식
/// 1. `pre_mmu_enable` 다음 `mmu_enable` 다음 `post_mmu_enable` 순서 외의 호출 순서는
///    연관 타입 전이로 컴파일 타임에 차단됨.
/// 2. `mmu_enable` 은 커널 매핑이 완료된 주소 공간에 대해서만 호출됨.
#[allow(dead_code)]
pub trait Mmu {
    /// 페이지 테이블 구축 전 상태 (x86 는 `crate::mmu::Mmu<Uninitialized>`)
    type Uninit;
    /// 활성화 가능 상태 (x86 는 `crate::mmu::Mmu<Initialized>`)
    type Init;
    /// 주소 공간 루트 (x86 는 `crate::mmu::AddressSpace`)
    type AddrSpace;

    /// 페이지 테이블 구축 단계. KASLR 오프셋을 반영하여 활성화 가능 상태로 전이함.
    ///
    /// # Arguments
    /// `m` - 미초기화 상태 MMU
    /// `kaslr_offset` - 부트로더가 전달한 KASLR 오프셋
    fn pre_mmu_enable(m: Self::Uninit, kaslr_offset: u64) -> Self::Init;

    /// 주소 공간 루트 로드 (x86 cr3 / aarch64 ttbr0).
    ///
    /// # Safety
    /// `space` 의 루트 테이블이 유효한 물리 주소에 있고 커널 매핑을 포함해야 함.
    unsafe fn mmu_enable(m: &Self::Init, space: &Self::AddrSpace);

    /// 선형 매핑 활성 후처리 (콘솔 베이스 갱신 등).
    ///
    /// # Safety
    /// `mmu_enable` 완료 이후에만 호출해야 함.
    unsafe fn post_mmu_enable();

    /// 물리 주소에서 커널 선형 매핑 가상 주소로 변환.
    fn phys_to_virt(pa: u64) -> u64;
}

/// 인터럽트 디스크립터/벡터 테이블에 대한 arch-중립 계약.
#[allow(dead_code)]
pub trait Idt {
    /// 벡터 테이블 초기화 및 로드.
    ///
    /// # Safety
    /// 부팅 초기 단일 코어 시퀀스에서 1 회만 호출해야 함.
    unsafe fn init();

    /// 지정 IRQ 라인 마스크 해제.
    ///
    /// # Safety
    /// `init` 완료 후 해당 IRQ 핸들러가 등록된 상태에서만 호출해야 함.
    unsafe fn enable_irq(irq: u8);

    /// 지정 IRQ 에 대한 EOI (end of interrupt) 통지.
    ///
    /// # Safety
    /// 해당 IRQ 핸들러 내부에서만 호출해야 함.
    unsafe fn eoi(irq: u8);
}

/// 부팅 콘솔 출력에 대한 arch-중립 계약.
///
/// 색상은 trait 표면에 포함하지 않음 (x86 vga::Color 는 re-export 경로로 존속하고
/// PL011 구현체는 색상을 무시할 수 있음)
#[allow(dead_code)]
pub trait Console {
    /// 문자열 출력.
    ///
    /// # Safety
    /// 콘솔 백엔드(x86 VGA base 등)가 유효하게 초기화된 상태에서만 호출해야 함.
    /// 미초기화 상태 호출은 UB 이므로 safe 표면으로 노출하지 않음.
    unsafe fn write_str(s: &str);

    /// 화면 소거.
    ///
    /// # Safety
    /// `write_str` 와 동일하게 콘솔 백엔드 초기화 상태를 호출자가 보장해야 함.
    unsafe fn clear();
}

/// Ring 3 최초 진입에 대한 arch-중립 계약.
#[allow(dead_code)]
pub trait BootEntry {
    /// 주소 공간 루트를 로드하고 user 엔트리로 강하함 (x86 cr3 + iretq / aarch64 ttbr0 + eret).
    ///
    /// # Arguments
    /// `addr_space_root` - 주소 공간 루트 물리 주소 (x86 cr3 / aarch64 ttbr0)
    /// `entry` - user 엔트리 포인트 가상 주소
    /// `stack` - user 스택 최상단 가상 주소
    ///
    /// # Safety
    /// 주소 공간에 user 매핑과 커널 매핑이 모두 완료된 후에만 호출해야 함.
    /// 반환하지 않으며 이후 커널 재진입은 인터럽트/syscall 경로만 사용함.
    unsafe fn enter_user(addr_space_root: u64, entry: u64, stack: u64) -> !;
}

/// 엔트로피 수집에 대한 arch-중립 계약.
///
/// # 보안 불변식
/// 1. 수집 실패 (quorum 미달 등) 는 반드시 Err 로 표면화되며 폴백 약화 금지.
/// 2. 출력 버퍼 외부로 원시 엔트로피가 누출되지 않음.
#[allow(dead_code)]
pub trait Entropy {
    /// 엔트로피를 수집하여 `buf` 전체를 채움.
    ///
    /// # Arguments
    /// `buf` - 수집 결과 출력 버퍼
    ///
    /// # Errors
    /// quorum 미달 또는 source 불가용 시 `EntropyError` 반환.
    ///
    /// # Safety
    /// BSP single-core 부팅 시퀀스 등 구현체가 요구하는 단일 진입 조건을 지켜야 함.
    unsafe fn collect(buf: &mut [u8]) -> Result<(), common::entropy::EntropyError>;
}

use common::entropy::QuorumEntropy;

/// Entropy trait 첫 구현체. 기존 `QuorumEntropy::collect` associated fn 으로의
/// thin 위임이며 quorum.rs 본문은 무변경임 (lib.rs host 표면 보호).
impl Entropy for QuorumEntropy {
    #[inline(always)]
    unsafe fn collect(buf: &mut [u8]) -> Result<(), common::entropy::EntropyError> {
        // SAFETY 호출자가 quorum.rs collect 의 단일 진입 조건을 그대로 승계
        unsafe { QuorumEntropy::collect(buf) }
    }
}

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as active;

// aarch64 두 번째 구현체 진입 표면
// aarch64-unknown-none-softfloat 타깃으로 컴파일되며 HAL 6 트레이트 + 부팅 합류점
// (entropy quorum 게이트 + DRBG + 신뢰 루트 + IPC + self-check)까지 실동작함
// x86_64 산출물에는 target_arch cfg 로 심볼 미유입
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as active;
