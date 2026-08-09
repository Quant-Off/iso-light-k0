//! 본 모듈은 aarch64 el1_entry asm 스텁에서 bl 로 진입하는 커널 부팅 합류점을 제공합니다.
//!
//! # Features
//! `aarch64_kernel_entry(dtb)` 는 boot_stub `el1_entry` 가 EL=1 early print 직후 `bl`
//! 로 분기하는 Rust 진입 함수입니다. 아래 순서대로
//! 정적 페이지 테이블 구축(build_stage1_map + GICD/GICR/virtio-mmio Device 매핑) 다음 HAL
//! Mmu 3 단계(self_test + MMU=ON), 이어서 GIC base 선형 VA 갱신, Idt::init(GICR wake + GRP1 +
//! boot proof IRQ), psci report_version 으로 7-line boot proof 를 emit 한 뒤,
//! `kernel_init_join` 이 arch-중립 커널 본체(entropy quorum 게이트 + Capability DRBG +
//! 신뢰 루트 + audit cap + IPC + air-gap self-check)를 배선하여 커널이 aarch64 런타임에서
//! 실동작함을 실증합니다.
//!
//! x86_64 `boot_stub` 에서 `_boot_adapter_mb2` 를 거쳐 `_kernel_start` 로 합류하는 계약을 mirror 하되
//! aarch64 는 EL1 MMU-off identity 실행 상태에서 진입하므로 진입 함수가 직접 stage1
//! MMU 를 켭니다. DTB 파싱과 EL0 유저 강하는 커널 higher-half 이관을 선행 요구하므로
//! 후속 작업으로 이연되며, 현재 진입점은 하드코딩 QEMU virt 상수로 합류 시퀀스 종료 후
//! wfi park 합니다.

use crate::arch::aarch64::{Aarch64Idt, Aarch64Mmu, cpu, gic, mmu, psci};
use crate::arch::{Idt, Mmu};

/// 커널 stage1 주소 공간을 정적 소유하는 arch 내부 전역 (동적 할당 0).
///
/// 본체(main.rs KERNEL_ADDR_SPACE) 결합을 피하기 위해 aarch64 내부 static 으로 두며
/// 부팅 초기 단일 코어가 배타 접근함
static mut AARCH64_KERNEL_SPACE: mmu::AddressSpace = mmu::AddressSpace::new();

/// boot_stub el1_entry 가 EL=1 early print 후 bl 로 진입하는 커널 부팅 합류점.
///
/// build_stage1_map, HAL Mmu 3 단계, gic base 선형 VA 갱신, Idt::init,
/// psci report_version 순서로 코딩된 부팅 파이프라인을 배선하여 QEMU virt TCG 부팅에서
/// 7-line boot proof 를 런타임 emit 함
///
/// # Arguments
/// `_dtb` - 진입 x0 DTB 물리 주소 (현재 범위 미사용, 파싱은 후속 작업으로 이연)
///
/// # Safety
/// boot_stub el1_entry 특권 정규화(SP_EL1 VBAR_EL1 CPACR_EL1) 완료 후 부팅 초기 단일
/// 코어에서 1 회만 진입해야 하며 반환하지 않는 `!` 계약을 승계함
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_kernel_entry(_dtb: u64) -> ! {
    // KASLR stage-1 오프셋은 아직 미사용 고정 기저 사용
    let kaslr = 0u64;

    // 1) stage1 페이지 테이블 구축 (커널 W^X + UART/GICD/GICR Device 매핑)
    // SAFETY MMU off identity 상태에서 1 회 호출 정적 AARCH64_KERNEL_SPACE 단독 접근
    let build = unsafe {
        (*(&raw mut AARCH64_KERNEL_SPACE)).build_stage1_map(kaslr, mmu::UART_PHYS)
    };
    if build.is_err() {
        // 정적 풀 소진/W^X 위반 등 매핑 실패는 fail-stop halt (오매핑 진행 차단)
        cpu::halt_loop();
    }

    // 2) HAL Mmu 3 단계 pre, enable(12-step activate), post(self_test + MMU=ON emit)
    let init = <Aarch64Mmu as Mmu>::pre_mmu_enable(mmu::Mmu::new(), kaslr);
    // SAFETY build_stage1_map 완료 후 MMU off 상태 단일 코어에서 1 회 활성
    unsafe {
        <Aarch64Mmu as Mmu>::mmu_enable(&init, &*(&raw const AARCH64_KERNEL_SPACE));
        <Aarch64Mmu as Mmu>::post_mmu_enable();
    }

    // 3) MMU 후 GIC base 를 커널 선형 매핑 VA 로 갱신 (GICD/GICR linear 매핑)
    // SAFETY mmu_enable 완료 후 선형 매핑이 GICD/GICR Device 페이지를 포함함
    unsafe {
        gic::update_base(
            (mmu::linear_base() + mmu::GICD_PHYS) as *mut u8,
            (mmu::linear_base() + mmu::GICR_PHYS) as *mut u8,
        );
    }

    // 4) GIC bring-up (GICR wake FIRST + GRP1) + boot proof IRQ delivery (vectors::init 선행)
    // SAFETY VBAR_EL1 로드 완료 후 부팅 초기 단일 코어에서 1 회 호출
    unsafe {
        <Aarch64Idt as Idt>::init();
    }

    // 5) PSCI 버전 조회 (HVC conduit) 로 PSCI >= 0x10000 마커 emit
    // SAFETY GIC bring-up 직후 EL1 단일 코어 시퀀스에서 호출
    unsafe {
        psci::report_version();
    }

    // 6) 커널 본체 합류 (park 대신 실제 init 시퀀스 실행)
    //    7-line boot proof 이후 arch-중립 서브시스템(entropy quorum gate, Capability
    //    DRBG, 신뢰 루트, audit cap, IPC, air-gap self-check)을 배선하여 커널 본체가
    //    aarch64 런타임에서 실제 동작함을 실증함
    // SAFETY MMU/GIC/PSCI bring-up 완료 후 부팅 초기 단일 코어에서 1 회 진입
    unsafe {
        kernel_init_join();
    }

    // 7) park (후속 작업에서 EL0 enter_user 진입으로 승격, 커널 higher-half 이관 선행 요구)
    loop {
        cpu::wait_for_interrupt();
    }
}

/// aarch64 부팅 합류점의 커널 본체 init 시퀀스.
///
/// # Features
/// 7-line boot proof 이후 실행되며 x86 `_kernel_start` 의 엔트로피 quorum 게이트,
/// Capability DRBG, 신뢰 루트, audit capability, IPC 초기화, air-gap self-check 단계를
/// aarch64 로 role-match 합니다. arch-중립 서브시스템만 배선하며 각 단계 성공을 PL011
/// 콘솔 마커로 emit 하여 런타임 실증합니다. 엔트로피 quorum(hw RNDR + virtio-mmio +
/// jitter 2-of-3)이 미달하면 fail-closed 로 halt 합니다. EL0 유저 강하는 커널
/// higher-half 이관을 선행 요구하므로 본 시퀀스는 self-check 이후 park 로 복귀합니다.
///
/// # Safety
/// 부팅 초기 단일 코어에서 MMU/GIC/PSCI bring-up 완료 후 1 회만 호출해야 합니다.
unsafe fn kernel_init_join() {
    use crate::arch::aarch64::console;
    use crate::arch::common::entropy::{QuorumEntropy, virtio_rng};

    // SAFETY 부팅 초기 단일 코어 아래 각 init 은 정적 BSS singleton 단일 진입 갱신
    unsafe {
        console::write_bytes(b"[k0-aarch64] kernel join start\r\n");

        // (1) virtio-rng probe (quorum source-1 배선, init_prng 의 quorum 수집 전 선행 필수)
        virtio_rng::init_virtio_rng_instance();
        console::write_bytes(b"[k0-aarch64] VIRTIO_RNG probe done\r\n");

        // (2) Capability DRBG 초기화 (entropy quorum 2-of-3 게이트 통과 필수)
        //     hw(RNDR) + virtio-rng + jitter 3 소스를 arch-중립 quorum 이 BLAKE3 로 결합
        match crate::capability::init_prng() {
            Ok(()) => {
                console::write_bytes(b"[k0-aarch64] CAP_DRBG init OK (Hash-DRBG-SHA256)\r\n");
                // ENTROPY_SOURCES_AVAILABLE=N (boot latch, 단일 ASCII digit)
                let n = QuorumEntropy::sources_available_at_boot();
                let mut line = *b"[k0-aarch64] ENTROPY_SOURCES_AVAILABLE=N\r\n";
                let pos = line.len() - 3;
                line[pos] = b'0' + (n & 0x0f);
                console::write_bytes(&line);
                console::write_bytes(b"[k0-aarch64] ENTROPY_QUORUM_2_OF_3_OK\r\n");
            }
            Err(_) => {
                // 엔트로피 quorum 부재는 무조건 부팅 중단 fail-closed (x86 계약 계승)
                console::write_bytes(b"[k0-aarch64] FATAL entropy quorum failure\r\n");
                super::cpu::halt_loop();
            }
        }

        // (3) 신뢰 루트 초기화 (ML-DSA-44 PK 1312B + BOOT_CHALLENGE 32B, CAP_DRBG 의존)
        crate::hsm_attest::init_trust_root();
        console::write_bytes(b"[k0-aarch64] Trust Root init OK (ML-DSA-44)\r\n");

        // (4) AUDIT_READ capability mint (CAP_DRBG 의존)
        crate::air_gap::init_audit_read_cap();
        console::write_bytes(b"[k0-aarch64] AUDIT_READ_CAP init OK\r\n");

        // (5) IPC 서브시스템 초기화 (EP_SYSTEM/EP_CRYPTO/EP_SIGN/EP_LUMEN_WIRE 등록)
        crate::ipc::init();
        console::write_bytes(b"[k0-aarch64] IPC init OK\r\n");

        // (6) air-gap 2 층 self-check (AUDIT_READ_CAP sanity + closed 프로필 심볼 부재)
        crate::air_gap::gap_self_check();
        console::write_bytes(b"[k0-aarch64] gap_self_check OK\r\n");

        console::write_bytes(b"[k0-aarch64] kernel init complete (EL0 spawn deferred)\r\n");
    }
}
