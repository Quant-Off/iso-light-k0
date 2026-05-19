//! CPU 제어 레지스터 및 SIMD/FPU 컨텍스트 활성화를 수행하는 모듈입니다.
//!
//! elib-k0-nt 보안 크레이트(aes, blake3, chacha20, sha2, sha3, mldsa, mlkem,
//! rng 등) 는 AES-NI / SSE2 / AVX 명령어와 `mfence` 같은 메모리 배리어를
//! 내부에서 사용합니다. CR0.EM=1 또는 CR4.OSFXSR=0 상태에서는 SSE 명령어가
//! #UD(Invalid Opcode) 를 일으켜 커널이 즉시 중단됩니다.
//!
//! 커널은 진입 직후 아래 상태를 반드시 확립해야 합니다.
//!   - CR0.MP = 1 (monitor coprocessor)
//!   - CR0.EM = 0 (native x87 활성)
//!   - CR0.TS = 0 (lazy switch 비활성)
//!   - CR0.NE = 1 (native FP error reporting, #MF 예외 사용)
//!   - CR4.OSFXSR     = 1 (FXSAVE/FXRSTOR 및 SSE 명령어 허용)
//!   - CR4.OSXMMEXCPT = 1 (SSE FP 오류를 #XM으로 라우팅)
//!   - CR4.OSXSAVE    = 1 (가능 시 XSAVE 패밀리 활성)
//!   - XCR0[0] = 1 (x87 상태 저장 영역)
//!   - XCR0[1] = 1 (SSE 상태 저장 영역)
//!   - XCR0[2] = 1 (AVX/YMM 상태 저장 영역, CPU 지원 시에만)
//!
//! 보안 고려사항:
//!   - XSAVE 영역은 사용자/커널 컨텍스트 전환 시 반드시 소거/복원 경로에서
//!     `zeroize` 처리되어야 함 (추후 스케줄러 구현 시 XSAVEOPT + wipe).
//!   - 여기서는 부팅 시 단일 초기화만 수행하며, MSR/제어 레지스터 쓰기는
//!     인터럽트 비활성(CLI) 상태의 단일 코어에서만 호출할 것.

//
// CPUID 간이 래퍼
//

/// CPUID leaf `eax`, sub-leaf `ecx`를 실행한 결과(EAX, EBX, ECX, EDX) 반환.
#[cfg(target_arch = "x86_64")]
#[inline]
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (mut eax, mut ebx, mut ecx, mut edx);
    // SAFETY: CPUID는 임의 시점에 안전하게 실행 가능한 읽기 전용 명령어
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            ebx = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") sub  => ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

//
// CPU 기능 탐지 결과
//

/// CPU가 지원하는 SIMD 확장 + 보안 기능 상태 요약.
#[derive(Clone, Copy, Debug)]
pub struct CpuFeatures {
    pub sse: bool,
    pub sse2: bool,
    pub xsave: bool,
    pub avx: bool,
    pub avx2: bool,
    pub aes_ni: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub sha_ni: bool,
    /// CR4.SMEP (Supervisor Mode Execution Prevention)
    pub smep: bool,
    /// CR4.SMAP (Supervisor Mode Access Prevention)
    pub smap: bool,
    /// CR4.UMIP (User-Mode Instruction Prevention)
    pub umip: bool,
}

impl CpuFeatures {
    #[cfg(target_arch = "x86_64")]
    pub fn detect() -> Self {
        // CPUID.01H: EDX에 SSE/SSE2, ECX에 AES/XSAVE/AVX/RDRAND
        let (_, _, ecx1, edx1) = cpuid(1, 0);
        let sse = (edx1 >> 25) & 1 != 0;
        let sse2 = (edx1 >> 26) & 1 != 0;
        let aes_ni = (ecx1 >> 25) & 1 != 0;
        let xsave = (ecx1 >> 26) & 1 != 0;
        let avx = (ecx1 >> 28) & 1 != 0;
        let rdrand = (ecx1 >> 30) & 1 != 0;

        // CPUID.07H.0: EBX[5]=AVX2, [7]=SMEP, [18]=RDSEED, [20]=SMAP, [29]=SHA-NI
        //              ECX[2]=UMIP
        let (_, ebx7, ecx7, _) = cpuid(7, 0);
        let avx2 = (ebx7 >> 5) & 1 != 0;
        let smep = (ebx7 >> 7) & 1 != 0;
        let rdseed = (ebx7 >> 18) & 1 != 0;
        let smap = (ebx7 >> 20) & 1 != 0;
        let sha_ni = (ebx7 >> 29) & 1 != 0;
        let umip = (ecx7 >> 2) & 1 != 0;

        Self {
            sse,
            sse2,
            xsave,
            avx,
            avx2,
            aes_ni,
            rdrand,
            rdseed,
            sha_ni,
            smep,
            smap,
            umip,
        }
    }
}

//
// 감지된 기능의 전역 캐시
//
// 부팅 초기 단일 코어에서 한 번 확정되므로 `static mut` 접근은 안전함
// SMP 전환 시에는 per-CPU 영역으로 이동해야 함
static mut CPU_FEATURES: CpuFeatures = CpuFeatures {
    sse: false,
    sse2: false,
    xsave: false,
    avx: false,
    avx2: false,
    aes_ni: false,
    rdrand: false,
    rdseed: false,
    sha_ni: false,
    smep: false,
    smap: false,
    umip: false,
};

/// 감지된 CPU 기능 플래그 반환 (`enable_simd_fpu()` 이후 유효).
#[inline]
pub fn features() -> CpuFeatures {
    // SAFETY: 부팅 초기 이후 불변
    unsafe { *(&raw const CPU_FEATURES) }
}

//
// 제어 레지스터 접근 헬퍼
//

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: CR0 읽기는 Ring 0에서 항상 안전
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn write_cr0(v: u64) {
    // SAFETY: 호출자가 적절한 CR0 조합을 보장해야 함 (WP/PG 비트 주의)
    unsafe {
        core::arch::asm!("mov cr0, {}", in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: CR4 읽기는 Ring 0에서 항상 안전
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn write_cr4(v: u64) {
    // SAFETY: 호출자가 적절한 CR4 조합을 보장 (PAE/PGE 등 중요 비트 유지 필요)
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) v, options(nomem, nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn xsetbv(index: u32, value: u64) {
    // SAFETY: OSXSAVE=1 이후에만 호출할 것 — 아니면 #UD 발생
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") index,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
}

/// Model-Specific Register 읽기.
///
/// # Safety
/// - Ring 0 에서만 호출 가능. Ring 3 에서 RDMSR 은 #GP 발생.
/// - `idx` 가 미정의 MSR 이면 #GP 발생.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn rdmsr(idx: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: 호출자가 Ring 0 + 유효한 MSR 인덱스를 보장
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") idx,
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Model-Specific Register 쓰기.
///
/// # Safety
/// - Ring 0 에서만 호출 가능.
/// - 잘못된 비트 조합은 즉시 시스템 동작을 망가뜨릴 수 있음.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn wrmsr(idx: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: 호출자가 Ring 0 + MSR 의미를 검증함
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") idx,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
}

//
// CR0 / CR4 비트 상수
//

const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR0_NE: u64 = 1 << 5;
/// Write Protect: Ring 0에서도 read-only 페이지에 쓰기 차단(.text/.rodata 보호)
const CR0_WP: u64 = 1 << 16;

const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
/// User-Mode Instruction Prevention (CPUID.07H.0:ECX[2])
const CR4_UMIP: u64 = 1 << 11;
const CR4_OSXSAVE: u64 = 1 << 18;
/// Supervisor Mode Execution Prevention
const CR4_SMEP: u64 = 1 << 20;
/// Supervisor Mode Access Prevention
const CR4_SMAP: u64 = 1 << 21;

const XCR0_X87: u64 = 1 << 0;
const XCR0_SSE: u64 = 1 << 1;
const XCR0_AVX: u64 = 1 << 2;

/// IA32_EFER MSR 인덱스
pub const IA32_EFER: u32 = 0xC000_0080;
/// EFER.SCE — System Call Extensions (syscall/sysret 활성)
pub const EFER_SCE: u64 = 1 << 0;

//
// 공개 API
//

/// x87 / SSE / (가능 시) AVX 컨텍스트를 CPU에 활성화함.
///
/// 호출 이후 kernel 코드 내에서 SSE/AES-NI/AVX 기반 암호 연산을 `#UD` 없이
/// 실행할 수 있음. elib-k0-nt 크레이트(aes, blake3, sha2, chacha20 등)가
/// 의존하는 `mfence` 및 XMM 레지스터 경로의 전제 조건임.
///
/// # Safety
/// - 인터럽트 비활성화(CLI) 상태의 단일 코어에서 호출해야 함.
/// - CR0/CR4는 페이징/PAE 등 결정적 비트를 보존하도록 read-modify-write로만 갱신함.
/// - XCR0 설정 시 OSXSAVE=1이 먼저 적용되어 있어야 함(내부에서 순서 보장).
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_simd_fpu() {
    // 0. CPUID로 지원 기능 수집
    let feats = CpuFeatures::detect();
    // SAFETY: 단일 코어 부팅 초기
    unsafe {
        *(&raw mut CPU_FEATURES) = feats;
    }

    // 1. CR0: EM=0, TS=0, MP=1, NE=1
    //   EM=1이면 모든 SSE/x87 -> #UD. 반드시 0
    //   TS=1이면 첫 FPU/SSE 접근 시 #NM. lazy save 안 쓰므로 0
    //   MP=1 + TS=1 조합만 WAIT에서 #NM 발생. 여기선 MP=1, TS=0이므로 무해함
    //   NE=1로 x87 예외를 #MF로 라우팅 (PIC를 통한 IRQ13 경로 미사용)
    let mut cr0 = unsafe { read_cr0() };
    cr0 &= !(CR0_EM | CR0_TS);
    cr0 |= CR0_MP | CR0_NE;
    unsafe {
        write_cr0(cr0);
    }

    // 2. CR4: OSFXSR, OSXMMEXCPT, (옵션) OSXSAVE
    //   OSFXSR=1이 없으면 모든 SSE 명령어가 #UD 를 일으킴
    //   OSXMMEXCPT=1이면 SSE FP 오류를 #XM으로 라우팅 (없으면 #UD)
    let mut cr4 = unsafe { read_cr4() };
    cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
    if feats.xsave {
        cr4 |= CR4_OSXSAVE;
    }
    unsafe {
        write_cr4(cr4);
    }

    // 3. x87 FPU 상태 초기화
    //   FNINIT: 제어/상태/태그 워드를 리셋. 구현부가 부동소수 연산을 하지
    //   않더라도 예외 마스크를 결정적 상태로 만들어 추후 #MF 오작동 방지함
    // SAFETY: CR0.EM=0이므로 FNINIT 실행 가능
    unsafe {
        core::arch::asm!("fninit", options(nostack, preserves_flags));
    }

    // 4. XCR0: x87 + SSE + (가능 시) AVX 활성
    //   XSETBV는 CR4.OSXSAVE=1 이후에만 합법. 그렇지 않으면 #UD
    if feats.xsave {
        let mut xcr0: u64 = XCR0_X87 | XCR0_SSE;
        if feats.avx {
            xcr0 |= XCR0_AVX;
        }
        // SAFETY: OSXSAVE=1 이미 설정됨
        unsafe {
            xsetbv(0, xcr0);
        }
    }
}

/// 사용자/커널 격리에 필요한 보안 비트를 일괄 활성화함.
///
/// 활성화 항목:
///   - CR0.WP   = 1  (Ring 0 도 read-only 페이지에 쓰기 차단)
///   - CR4.SMEP = 1  (CPUID 지원 시: 커널이 사용자 페이지 코드 실행 차단)
///   - CR4.SMAP = 1  (CPUID 지원 시: 커널이 사용자 페이지 데이터 접근 차단)
///   - CR4.UMIP = 1  (CPUID 지원 시: Ring 3 에서 SGDT/SIDT/STR/SLDT/SMSW 차단)
///   - IA32_EFER.SCE = 1  (syscall/sysret 명령어 활성)
///
/// EFER.NXE 와 EFER.LME 는 부팅 트램폴린(`boot_stub.rs`)에서 이미 설정되어
/// 있으므로 RMW(read-modify-write)로 SCE 만 추가함.
///
/// # Security Note
/// SMAP 활성화 후에는 커널이 사용자 메모리에 직접 접근할 때 일시적으로
/// `stac` 으로 AC 플래그를 세우고, 작업 후 `clac` 으로 다시 클리어해야 함.
/// 본 커널은 사용자 메모리 접근을 syscall 디스패처에서만 수행하며 그 경로에서
/// 명시적으로 stac/clac 를 사용함.
///
/// # Safety
/// - `enable_simd_fpu()` (CpuFeatures 캐싱) 이후 호출.
/// - 인터럽트 비활성화(CLI) 상태의 단일 코어에서 호출.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_security_bits() {
    let feats = features();

    // 1. CR0.WP = 1
    // SAFETY: WP 만 OR 로 추가. 다른 비트(PG/PE/MP/NE)는 보존.
    let mut cr0 = unsafe { read_cr0() };
    cr0 |= CR0_WP;
    unsafe {
        write_cr0(cr0);
    }

    // 2. CR4: SMEP/SMAP/UMIP (지원 시)
    let mut cr4 = unsafe { read_cr4() };
    if feats.smep {
        cr4 |= CR4_SMEP;
    }
    if feats.smap {
        cr4 |= CR4_SMAP;
    }
    if feats.umip {
        cr4 |= CR4_UMIP;
    }
    unsafe {
        write_cr4(cr4);
    }

    // 3. IA32_EFER.SCE = 1 (syscall/sysret 활성)
    // SAFETY: EFER 읽기-수정-쓰기. NXE/LME 등 기존 비트 보존.
    unsafe {
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | EFER_SCE);
    }
}

/// IDT/PIC 초기화 이후 CPU 컨텍스트 최종 확정.
///
/// `enable_simd_fpu()`에서 설정한 비트가 중간 초기화(특히 `init_gdt` 중
/// 세그먼트 레지스터 재로드)로 변경되지 않음을 재검증하고, 필요 시 재적용함.
///
/// # Safety
/// 단일 코어 + CLI 상태.
#[cfg(target_arch = "x86_64")]
pub unsafe fn finalize_simd_fpu() {
    let feats = features();

    let mut cr0 = unsafe { read_cr0() };
    cr0 &= !(CR0_EM | CR0_TS);
    cr0 |= CR0_MP | CR0_NE;
    unsafe {
        write_cr0(cr0);
    }

    let mut cr4 = unsafe { read_cr4() };
    cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
    if feats.xsave {
        cr4 |= CR4_OSXSAVE;
    }
    unsafe {
        write_cr4(cr4);
    }
}

/// SMAP 우회용 EFLAGS.AC=1 설정. `clac()`와 짝으로 사용.
///
/// # Safety
/// - 호출 후 반드시 `clac()`을 짝으로 호출하여 AC=0 으로 복구.
/// - SMAP 미활성 환경에서도 무해(NOP 동등). SMAP 활성 시 사용자 메모리 접근 직전에만 호출.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn stac() {
    if features().smap {
        // SAFETY: SMAP 활성 환경에서만 STAC 실행 (#UD 회피)
        unsafe {
            core::arch::asm!("stac", options(nostack, nomem, preserves_flags));
        }
    }
}

/// SMAP 우회 종료. `stac()`로 열린 사용자 메모리 접근 윈도우를 닫음.
///
/// # Safety
/// `stac()` 직후 사용자 메모리 작업이 끝난 즉시 호출.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn clac() {
    if features().smap {
        // SAFETY: SMAP 활성 환경에서만 CLAC 실행
        unsafe {
            core::arch::asm!("clac", options(nostack, nomem, preserves_flags));
        }
    }
}

//
// aarch64 스텁
//
// aarch64 타겟에서는 CPACR_EL1 구성을 통해 FP/SIMD(Advanced SIMD & NEON) 트랩을
// 해제해야 함. 현재 활성 타겟이 x86_64-unknown-none이므로 스텁만 제공함

#[cfg(target_arch = "aarch64")]
pub unsafe fn enable_simd_fpu() {
    // CPACR_EL1.FPEN = 0b11 (EL0/EL1 FP/SIMD 트랩 비활성)
    // SAFETY: 커널 특권 레벨(EL1)에서 호출
    unsafe {
        core::arch::asm!(
            "mrs x0, cpacr_el1",
            "orr x0, x0, #(0b11 << 20)",
            "msr cpacr_el1, x0",
            "isb",
            out("x0") _,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn finalize_simd_fpu() {}
