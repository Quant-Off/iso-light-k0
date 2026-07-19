//! Müller CPU Time Jitter NPTRNG minimum-core procedure
//!
//! # Features
//! noise source via arch::cpu::cycle_counter HAL hook + 2 KiB memory-fold loop + von Neumann debias
//! LTO 회피 `#[inline(never)]` + `core::hint::black_box` 모든 fold step ENTR-08 명문 + Pitfall 4 + LWN 642166
//! TCG 환경 self-disable 16384 sample boot self-test fail 시 영구 disable (재허용 미적용)
//! CMOS RTC port 0x70 0x71 UIP edge polling 기반 TSC calibration fallback (Pitfall 12)

use super::health::{HealthVerdict, StreamHealth};

const POOL_SIZE: usize = 2048;
const SAMPLES_PER_BYTE: usize = 64;
// ROADMAP SC #2 min-entropy >= 0.5 회귀 게이트 표본 수
const BOOT_SELF_TEST_SAMPLES: usize = 16384;
// RTC UIP edge 당 polling 상한 QEMU port IO 지연 기준 수 초 budget RTC 부재 시 Err 폴백
const CALIBRATE_LOOP_ITERS: usize = 8_000_000;

#[used]
static mut JITTER_POOL: [u8; POOL_SIZE] = [0u8; POOL_SIZE];

// TCG self-disable flag 영구 (재허용 미적용 Pitfall 4)
#[used]
static mut JITTER_DISABLED: bool = false;

// Wave 4 main.rs 가 boot 시점 dump 하는 raw delta 표본 버퍼 host-side 분석용
#[used]
static mut BOOT_SELF_TEST_BUF: [u8; BOOT_SELF_TEST_SAMPLES] = [0u8; BOOT_SELF_TEST_SAMPLES];

// Wave 3 quorum 합류 전 LTO 제거 차단 anchor 함수 포인터 참조로 심볼 보존 (ENTR-08)
#[used]
static JITTER_FOLD_KEEP: unsafe fn() -> u64 = jitter_fold_step;
#[used]
static JITTER_COLLECT_KEEP: unsafe fn() -> Option<u8> = jitter_collect_byte;

/// black_box 장벽을 별도 심볼로 유지하는 함수
///
/// LTO 후 binary 에서 black_box marker 심볼과 호출 site 가 관측 가능해야
/// `scripts/check-jitter-lto.sh` 의 DCE 차단 검증이 성립하므로 inline 금지로 고정함
#[inline(never)]
fn jitter_black_box(v: u64) -> u64 {
    core::hint::black_box(v)
}

// ENTR-08 instruction count >= 1024 보장 opt-level z 는 자동 unroll 을 하지 않으므로
// 매크로 전개로 fold step 본문을 정적 전개함 (256 step x 8 회 반복 = POOL_SIZE)
macro_rules! fold_one {
    ($pool:ident, $acc:ident, $idx:expr) => {{
        let idx = $idx;
        let v = $pool[idx].wrapping_mul(0x9E37_79B1u32.wrapping_mul(idx as u32 + 1) as u8);
        $pool[idx] = jitter_black_box(v as u64) as u8;
        $acc = $acc.wrapping_add(v as u64);
    }};
}

macro_rules! fold_16 {
    ($pool:ident, $acc:ident, $base:expr) => {{
        fold_one!($pool, $acc, $base);
        fold_one!($pool, $acc, $base + 1);
        fold_one!($pool, $acc, $base + 2);
        fold_one!($pool, $acc, $base + 3);
        fold_one!($pool, $acc, $base + 4);
        fold_one!($pool, $acc, $base + 5);
        fold_one!($pool, $acc, $base + 6);
        fold_one!($pool, $acc, $base + 7);
        fold_one!($pool, $acc, $base + 8);
        fold_one!($pool, $acc, $base + 9);
        fold_one!($pool, $acc, $base + 10);
        fold_one!($pool, $acc, $base + 11);
        fold_one!($pool, $acc, $base + 12);
        fold_one!($pool, $acc, $base + 13);
        fold_one!($pool, $acc, $base + 14);
        fold_one!($pool, $acc, $base + 15);
    }};
}

/// von Neumann debias 로 1 옥텟 entropy 를 수집하는 함수 (ENTR-08 명문)
///
/// # Errors
/// SAMPLES_PER_BYTE budget 안에 8 bit 확보 실패 또는 JITTER_DISABLED 시 None
///
/// # Safety
/// 단일 코어 부팅 초기 + JITTER_POOL 의 단일 진입 가정 FMASK 재진입 차단
#[inline(never)]
pub unsafe fn jitter_collect_byte() -> Option<u8> {
    // SAFETY BSP single-core JITTER_DISABLED 단일 진입 읽기
    if unsafe { (&raw const JITTER_DISABLED).read() } {
        return None;
    }
    let mut accumulator: u8 = 0;
    let mut bit_count: u8 = 0;
    for _ in 0..SAMPLES_PER_BYTE {
        let t0 = crate::arch::cpu::cycle_counter();
        // SAFETY BSP single-core JITTER_POOL 단일 진입
        let bit_a = unsafe { jitter_fold_step() } as u8 & 1;
        let t1 = crate::arch::cpu::cycle_counter();
        // SAFETY BSP single-core JITTER_POOL 단일 진입
        let bit_b = unsafe { jitter_fold_step() } as u8 & 1;
        let t2 = crate::arch::cpu::cycle_counter();
        let delta_a = (t1.wrapping_sub(t0)) as u8 & 1;
        let delta_b = (t2.wrapping_sub(t1)) as u8 & 1;
        let debiased = match (delta_a, delta_b) {
            (0, 1) => Some(0u8),
            (1, 0) => Some(1u8),
            _ => None,
        };
        if let Some(bit) = debiased {
            accumulator = (accumulator << 1) | bit;
            bit_count += 1;
            if bit_count == 8 {
                return Some(accumulator);
            }
        }
        core::hint::black_box(bit_a);
        core::hint::black_box(bit_b);
    }
    None
}

/// 2 KiB pool 을 순회하며 memory fold 를 수행하는 함수
///
/// # Safety
/// 단일 코어 BSP + JITTER_POOL 단일 진입 (FMASK 재진입 차단)
#[inline(never)]
unsafe fn jitter_fold_step() -> u64 {
    let mut acc: u64 = 0;
    // SAFETY single-core BSP + JITTER_POOL 단일 진입 (FMASK 재진입 차단)
    let pool = unsafe { &mut *(&raw mut JITTER_POOL) };
    let mut base = 0usize;
    while base < POOL_SIZE {
        fold_16!(pool, acc, base);
        fold_16!(pool, acc, base + 16);
        fold_16!(pool, acc, base + 32);
        fold_16!(pool, acc, base + 48);
        fold_16!(pool, acc, base + 64);
        fold_16!(pool, acc, base + 80);
        fold_16!(pool, acc, base + 96);
        fold_16!(pool, acc, base + 112);
        fold_16!(pool, acc, base + 128);
        fold_16!(pool, acc, base + 144);
        fold_16!(pool, acc, base + 160);
        fold_16!(pool, acc, base + 176);
        fold_16!(pool, acc, base + 192);
        fold_16!(pool, acc, base + 208);
        fold_16!(pool, acc, base + 224);
        fold_16!(pool, acc, base + 240);
        base += 256;
    }
    core::hint::black_box(acc)
}

/// 16384 raw delta 표본을 수집해 boot self-test 를 수행하는 함수
///
/// RCT APT 패스 카운트가 50% 미만이면 JITTER_DISABLED 를 영구 set 하고
/// false 를 반환함 표본은 BOOT_SELF_TEST_BUF 에 dump 되어 Wave 4 의
/// main.rs 가 host-side min-entropy 추정에 사용함
///
/// # Safety
/// 단일 코어 부팅 초기 1 회 호출 + BOOT_SELF_TEST_BUF JITTER_POOL 단일 진입 가정
// Wave 4 main.rs boot 합류 전까지 호출자 부재 한시 허용
#[allow(dead_code)]
pub unsafe fn jitter_boot_self_test() -> bool {
    // SAFETY BSP single-core BOOT_SELF_TEST_BUF 단일 진입
    let buf = unsafe { &mut *(&raw mut BOOT_SELF_TEST_BUF) };
    let mut health = StreamHealth::new();
    let mut fail_count: usize = 0;
    let mut i = 0usize;
    while i < BOOT_SELF_TEST_SAMPLES {
        let t0 = crate::arch::cpu::cycle_counter();
        // SAFETY BSP single-core JITTER_POOL 단일 진입
        let _ = unsafe { jitter_fold_step() };
        let t1 = crate::arch::cpu::cycle_counter();
        let sample = t1.wrapping_sub(t0) as u8;
        buf[i] = sample;
        if health.check(sample) == HealthVerdict::Fail {
            fail_count += 1;
        }
        i += 1;
    }
    let pass_count = BOOT_SELF_TEST_SAMPLES - fail_count;
    if pass_count * 2 < BOOT_SELF_TEST_SAMPLES {
        // SAFETY BSP single-core JITTER_DISABLED 단일 진입 갱신 영구 disable
        unsafe {
            *(&raw mut JITTER_DISABLED) = true;
        }
        return false;
    }
    true
}

/// boot self-test 원시 delta 표본 buffer 의 읽기 전용 slice 를 반환하는 함수
///
/// Wave 4 main.rs 가 boot serial 로 hex dump 해 host-side min-entropy 추정에 사용함
/// pre-conditioning raw 표본이므로 key material 이 아님
///
/// # Safety
/// jitter_boot_self_test 완료 후 BSP single-core 단일 진입 read 가정
#[allow(dead_code)]
pub(crate) unsafe fn boot_self_test_samples() -> &'static [u8] {
    // SAFETY BSP single-core BOOT_SELF_TEST_BUF 단일 진입 read
    unsafe { &*(&raw const BOOT_SELF_TEST_BUF) }
}

/// CMOS RTC 1 Hz UIP edge 2 회 간 RDTSC 차이로 TSC 주파수를 산출하는 함수
///
/// IDT 의존성 0 으로 BSP single-core 부팅 초기에 가용하며 RTC 부재 등
/// edge 미검출 시 Err 를 반환해 호출자 timer_frequency 가 None 으로 lifting 함
///
/// # Errors
/// RTC UIP edge 미검출 (CALIBRATE_LOOP_ITERS 초과) 또는 tick 차이 0 시 Err
pub fn calibrate_tsc_via_rtc() -> Result<u64, ()> {
    #[cfg(target_arch = "x86_64")]
    {
        let t0 = match wait_uip_falling_edge() {
            Some(t) => t,
            None => return Err(()),
        };
        let t1 = match wait_uip_falling_edge() {
            Some(t) => t,
            None => return Err(()),
        };
        let ticks = t1.wrapping_sub(t0);
        if ticks == 0 {
            return Err(());
        }
        Ok(ticks)
    }
    #[cfg(not(target_arch = "x86_64"))]
    Err(())
}

/// RTC status register A 의 UIP bit 1 -> 0 edge 를 검출하는 함수
///
/// edge 검출 시점의 RDTSC tick 을 반환하며 상한 초과 시 None
#[cfg(target_arch = "x86_64")]
fn wait_uip_falling_edge() -> Option<u64> {
    let mut seen_high = false;
    let mut iters = 0usize;
    while iters < CALIBRATE_LOOP_ITERS {
        // SAFETY Ring 0 CMOS port 0x70 0x71 읽기 전용 폴링 BSP single-core 단일 진입
        let uip = unsafe { cmos_read_status_a() } & 0x80;
        if uip != 0 {
            seen_high = true;
        } else if seen_high {
            return Some(crate::arch::cpu::cycle_counter());
        }
        iters += 1;
    }
    None
}

/// CMOS RTC status register A 를 읽는 함수
///
/// # Safety
/// Ring 0 에서만 호출 가능 port 0x70 select 와 0x71 read 사이 다른 CMOS 접근이
/// 없어야 하므로 BSP single-core 부팅 초기 단일 진입을 가정함
#[cfg(target_arch = "x86_64")]
unsafe fn cmos_read_status_a() -> u8 {
    let val: u8;
    // SAFETY 호출자가 Ring 0 + 단일 진입을 보장
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x70u16,
            in("al") 0x0Au8,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") 0x71u16,
            options(nostack, preserves_flags),
        );
    }
    val
}
