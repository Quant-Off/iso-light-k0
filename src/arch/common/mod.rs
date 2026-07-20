//! arch-중립 모듈 re-export hub
//!
//! # Features
//! 아키텍처에 독립적인 커널 모듈을 모읍니다. 현재는 Phase 8 의 entropy 서브트리와
//! Phase 9 의 k0_secure_zero 를 노출하며 Phase 10 aarch64 합류 시에도 본 모듈은
//! 변경 없이 재사용됩니다. k0_secure_zero 는 zeroize (elib-k0-nt) 의 secure_zero 를
//! 대체하지 않는 커널 raw buffer 보완 표면이며 심볼명 접두어로 명확히 분리됩니다.

pub mod entropy;

/// 컴파일러가 제거(elide) 할 수 없는 raw buffer zeroization.
///
/// inline asm 블록은 Rust Reference 상 black box 로 취급되어 (`pure` 옵션 부재)
/// 최적화기가 내부 명령을 분석·변형·제거할 수 없습니다. `#[inline(never)]` 로
/// 인라인 후 elide 를 차단하고 `#[unsafe(no_mangle)]` 로 LTO 후에도 nm 게이트가
/// 심볼을 실측할 수 있게 보존합니다. `Secret<T>` 등 정형 비밀은 기존 zeroize 를
/// 사용하며 본 함수는 정형화되지 않은 커널 raw buffer 전용 보완입니다.
///
/// # Safety
/// `ptr..ptr+len` 이 유효한 쓰기 가능 영역이어야 함.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe fn k0_secure_zero(ptr: *mut u8, len: usize) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY 호출자가 ptr..ptr+len 쓰기 유효성을 보장 cld 로 DF=0(전진) 을 명시 보장한 뒤
    // rep stosb 가 rcx 회수까지 al 을 기록 DF=1 진입 시 역방향 버퍼 밖 손상 차단
    unsafe {
        core::arch::asm!(
            "cld",
            "rep stosb",
            inout("rdi") ptr => _,
            inout("rcx") len => _,
            in("al") 0u8,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY 호출자가 ptr..ptr+len 쓰기 유효성을 보장 8 바이트 단위 잔여는 바이트 루프
    unsafe {
        let mut p = ptr;
        let mut remaining = len;
        // 8 바이트 정렬 구간을 xzr 로 소거 (Phase 10 ARM-11 실검증)
        while remaining >= 8 {
            core::arch::asm!(
                "str xzr, [{p}], #8",
                p = inout(reg) p,
                options(nostack),
            );
            remaining -= 8;
        }
        // 잔여 바이트 소거
        while remaining > 0 {
            core::arch::asm!(
                "strb wzr, [{p}], #1",
                p = inout(reg) p,
                options(nostack),
            );
            remaining -= 1;
        }
    }
    // 미지원 타깃에서 본체가 비어 조용한 no-op(소거 실패) 이 되는 것을 컴파일 타임에 차단
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("k0_secure_zero 미지원 타깃 무언 no-op 금지 arch 별 소거 경로를 추가하라");
}

// k0_secure_zero 는 Phase 9 시점 호출자가 없어 링커 --gc-sections 가 심볼을 회수함
// (`#[unsafe(no_mangle)]` 만으로는 GC 루트가 되지 않음) nm 게이트 (HAL-05) 가
// uncalled 상태에서도 심볼을 실측할 수 있도록 #[used] fn-pointer 앵커로 보존함
// 본체 boot path 호출자 추가가 아니라 링커 보존 앵커임 (본체 변경 0 원칙 유지)
#[used]
static K0_SECURE_ZERO_ANCHOR: unsafe fn(*mut u8, usize) = k0_secure_zero;
