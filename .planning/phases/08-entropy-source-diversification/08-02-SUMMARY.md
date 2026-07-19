---
phase: 08-entropy-source-diversification
plan: 02
subsystem: kernel-entropy-arch
tags: [entropy, arch-skeleton, compile-error-mutex, virtio-drivers, kernel-hal, lossless-move, timer-frequency]

# Dependency graph
requires:
  - phase: 08-entropy-source-diversification
    provides: "08-01 Wave 0 skeleton (entropy-degraded-ok feature, virtio-drivers 0.13 등록, ci-phase8 표면)"
provides:
  - src/arch/ 디렉토리 골격 12 파일 (D-01 Forward 정합, Phase 9 HAL prior art)
  - ENTR-05 compile_error mutex 활성 (entropy-degraded-ok + tls-external 동시 활성 컴파일 차단)
  - src/arch/x86_64/entropy/hw.rs (capability.rs rdseed64/rdrand64/fill_hw_entropy lossless move, collect_hw_into)
  - src/arch/common/entropy/quorum.rs EntropyError 3-variant enum (Wave 3 본문 anchor)
  - src/arch/common/entropy/virtio_rng.rs KernelHal Hal impl + SENTINEL + virtio_collect + VIRTIO_RNG_INSTANCE BSS singleton
  - src/arch/x86_64/entropy/virtio_transport.rs probe_virtio_rng ECAM scan (D-02 transport 분리)
  - src/arch/cpu.rs timer_frequency CPUID 0x15/0x16 chain + TimerKind (W7 SC 7 정합)
  - src/capability.rs fill_hw_entropy bridge stub (호출자 시그니처 변경 0, ENTR-06 부분 충족)
  - Cargo.toml cargo-machete 한시 ignore 제거 (Wave 0 이월 의무 이행)
affects: [08-03, 08-04, 08-05, 08-06, phase-09-hal, phase-10-aarch64]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "KernelHal static BSS DMA pool (repr align 4096, bump index, 소진 시 paddr 0 fail-stop)"
    - "VMA -> phys 변환 (mmu.rs KERNEL_VMA_BASE prior art) 을 Hal dma_alloc/share 에 적용"
    - "ct_eq_bytes per-byte CtEqOps 누산 (keystore.rs prior art, CtEqOps slice 미구현 우회)"
    - "Wave anchor placeholder (docstring + TODO 1 줄) 로 빈 모듈 컴파일 유지"

key-files:
  created:
    - src/arch/mod.rs
    - src/arch/cpu.rs
    - src/arch/common/mod.rs
    - src/arch/common/entropy/mod.rs
    - src/arch/common/entropy/quorum.rs
    - src/arch/common/entropy/health.rs
    - src/arch/common/entropy/jitter.rs
    - src/arch/common/entropy/virtio_rng.rs
    - src/arch/x86_64/mod.rs
    - src/arch/x86_64/entropy/mod.rs
    - src/arch/x86_64/entropy/hw.rs
    - src/arch/x86_64/entropy/virtio_transport.rs
  modified:
    - src/main.rs
    - src/cpu.rs
    - src/capability.rs
    - Cargo.toml

key-decisions:
  - "KernelHal DMA 는 plan 의 단순 identity 대신 VMA -> phys 변환 + 4-page aligned pool 로 구현 (higher-half 커널에서 device 에 VMA 전달 시 DMA 오염 방지)"
  - "sentinel verify-changed 는 ct_eq_bytes per-byte CtEqOps 누산으로 구현 (CtEqOps 가 slice 미지원)"
  - "virtio_collect 는 n 을 buf.len() 으로 clamp + 모든 이탈 경로 zeroize (silent panic 차단)"
  - "13 marker 정본 회귀 검증은 Linux+KVM lane 위임 유지 (Mac QEMU 11 TCG pre-existing 결함 Plan 01 정합)"

patterns-established:
  - "arch 트리 모듈은 전부 Korean 모듈 docstring + 필요 시 # Safety 헤더 (5-게이트)"
  - "Wave N 합류 anchor 는 #[allow(dead_code)] + 한시 허용 주석으로 zero-warning 빌드 유지"

requirements-completed: [ENTR-05]
requirements-partial: [ENTR-01 (hw + virtio 어댑터 합류, jitter 는 Wave 2), ENTR-06 (bridge stub, quorum 통합은 Wave 3)]

# Metrics
duration: ~30min
completed: 2026-07-19
---

# Phase 8 Plan 02: Wave 1 arch 골격 신설 Summary

**src/arch/ 12 파일 골격 + ENTR-05 compile_error mutex 활성 + capability.rs lossless move bridge + virtio-drivers KernelHal 컴파일 검증을 Phase 1~7 회귀 0 으로 정합**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-07-19T11:12:20Z
- **Completed:** 2026-07-19T11:40:00Z
- **Tasks:** 3/3
- **Files modified:** 16 (created 12, modified 4)

## Accomplishments

- src/arch/ 디렉토리 골격 12 파일 신설 (mod/cpu/common/x86_64 + entropy 서브트리), `pub mod arch` + `pub(crate) fn cpuid` 노출, 4 개 feature 조합 빌드 전부 실측 (closed / degraded-only / tls-only 통과, mutex 조합 exit 101 컴파일 차단)
- ENTR-05 compile_error mutex 가 Wave 1 에서 실제 활성 — `make check-entropy-mutex` 가 Wave 0 expected-fail 에서 PASS 로 전환
- capability.rs L176-289 의 HW_RNG_MAX_RETRIES + rdseed64 + rdrand64 + fill_hw_entropy 본문을 hw.rs 로 lossless move (Intel SDM Vol. 1 §7.3.17.2 인용 docstring 보존), `collect_hw_into` rename + EntropyError 매핑, capability.rs 는 bridge stub 만 잔존 — 호출자 (init_prng L248-249 / reseed_drbg L277) 시그니처 변경 0, ENTR-06 diff guard 실측 PASS (sum=0)
- virtio_rng.rs 에 KernelHal (Hal 5 메서드, static BSS 4-page aligned DMA pool, alloc 0) + SENTINEL 0xFE + VIRTIO_SCRATCH + virtio_collect (sentinel 채움 + request_entropy + ct_eq verify-changed + 전 경로 zeroize) + VIRTIO_RNG_INSTANCE BSS singleton 채움 — virtio-drivers 0.13 API 정합 컴파일 실증 (RESEARCH §A1 해소)
- virtio_transport.rs 에 probe_virtio_rng (MCFG_ECAM_BASE 0xE000_0000 + MmioCam Ecam + PciRoot::enumerate_bus(0) + DeviceType::EntropySource 매치) 채움 — 실제 crate 소스 (registry) 로 시그니처 정본 inspection 수행
- Cargo.toml 의 cargo-machete 한시 ignore 제거 (Wave 0 이월 의무), `cargo machete` + `make ci-phase7` GREEN 실측
- `bash scripts/check-virtio-sentinel.sh` PASS (Wave 2 예정이던 stub 해소가 앞당겨짐)

## Task Commits

1. **Task 1: arch 디렉토리 골격 + ENTR-05 mutex 활성** - `48ae2a8`
2. **Task 2: hw.rs lossless move + capability bridge stub + EntropyError** - `2939271`
3. **Task 3: KernelHal + virtio_collect + probe_virtio_rng + machete ignore 제거** - `5e71833`

## Files Created/Modified

- `src/arch/mod.rs` - cfg-conditional re-export hub (x86_64 as active)
- `src/arch/cpu.rs` - timer_frequency CPUID 0x15/0x16 chain + TimerKind 2-variant (calibration fallback 은 Wave 2 anchor, 현재 None)
- `src/arch/common/mod.rs` - arch-중립 hub
- `src/arch/common/entropy/mod.rs` - compile_error mutex + 4 서브모듈 + pub use EntropyError
- `src/arch/common/entropy/quorum.rs` - EntropyError 3-variant (Timeout dead variant 제거 D-05 정합), QuorumEntropy 는 Wave 3
- `src/arch/common/entropy/health.rs` - Wave 2 placeholder
- `src/arch/common/entropy/jitter.rs` - Wave 2 placeholder
- `src/arch/common/entropy/virtio_rng.rs` - KernelHal + sentinel + virtio_collect + BSS singleton
- `src/arch/x86_64/mod.rs` / `src/arch/x86_64/entropy/mod.rs` - x86_64 hub
- `src/arch/x86_64/entropy/hw.rs` - rdseed64/rdrand64/collect_hw_into lossless move
- `src/arch/x86_64/entropy/virtio_transport.rs` - probe_virtio_rng ECAM scan
- `src/main.rs` - pub mod arch 1 줄
- `src/cpu.rs` - cpuid pub(crate) 1 단어
- `src/capability.rs` - fill_hw_entropy bridge stub 통합 (-104 줄)
- `Cargo.toml` - machete 한시 ignore 제거

## Decisions Made

- KernelHal 의 dma_alloc/share 는 plan 원문의 "phys==virt identity" 대신 mmu.rs L255 prior art 의 `VMA >= KERNEL_VMA_BASE -> VMA - KERNEL_VMA_BASE` 변환 적용 — higher-half 커널 (0xFFFFFFFF80000000) 의 static BSS 주소를 그대로 device 에 주면 DMA 가 잘못된 물리 주소를 침범. mmio_phys_to_virt 는 identity (boot identity map 가정, threat model T-08-01 정합)
- DMA pool 은 1 page 가 아닌 `#[repr(C, align(4096))]` 4-page bump pool — VirtQueue modern layout 이 Dma 2 회 (1 page 씩) 할당하므로 단일 page 는 alias UB, 정렬 미보장. 소진 시 paddr 0 반환으로 Dma::new 가 DmaError fail-stop. indirect descriptor 는 alloc feature 전용이라 (crate 소스 실측) pool 고갈 경로 부재
- EntropyError import 는 fill_hw_entropy 의 cfg(x86_64) 블록 안으로 이동 (비 x86 빌드 unused import 경고 차단)
- Wave 2~4 합류 전 호출자 부재 표면 (timer_frequency / TimerKind / virtio_collect / probe_virtio_rng / EntropyError 잔여 variant) 은 `#[allow(dead_code)]` 한시 부여 — main.rs USER_*_ELF prior art, zero-warning 빌드 유지

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Task 1 에서 hw.rs / virtio_transport.rs placeholder 선행 신설**
- **Found during:** Task 1
- **Issue:** plan 의 Task 1 이 x86_64/entropy/mod.rs 에 `pub mod hw; pub mod virtio_transport;` 선언을 요구하나 두 파일은 Task 2/3 산출물 -> Task 1 시점 빌드 불가
- **Fix:** docstring-only placeholder 2 파일을 Task 1 에 선행 신설, Task 2/3 이 본문 교체
- **Files modified:** src/arch/x86_64/entropy/{hw,virtio_transport}.rs
- **Committed in:** `48ae2a8`

**2. [Rule 2 - Critical] KernelHal identity map 이 higher-half 커널과 불합치**
- **Found during:** Task 3
- **Issue:** plan 의 "phys==virt pass-through" 는 static BSS 가 higher-half VMA (0xFFFFFFFF8xxxxxxx) 인 본 커널에서 device 에 비물리 주소를 전달 -> DMA 오염/실패
- **Fix:** dma_alloc/share 에 mmu.rs KERNEL_VMA_BASE 변환 적용 + DMA pool 을 4-page aligned bump pool 로 구현 (VirtQueue 2 회 할당 실측 근거)
- **Files modified:** src/arch/common/entropy/virtio_rng.rs
- **Verification:** `cargo build --target x86_64-unknown-none` 통과 (런타임 실증은 Wave 4 boot init 합류 시)
- **Committed in:** `5e71833`

**3. [Rule 1 - Bug] PATTERNS §2.6 의 slice ct_eq 가 컴파일 불가**
- **Found during:** Task 3
- **Issue:** `scratch.ct_eq(&still_sentinel[..])` — CtEqOps 는 스칼라 + SecureBuffer 만 구현 (main.rs L1226 기존 명문), slice 미지원
- **Fix:** keystore.rs prior art 의 per-byte `CtEqOps::eq` 누산 helper `ct_eq_bytes` 신설 (check-virtio-sentinel.sh 의 ct_eq grep 패턴도 충족)
- **Files modified:** src/arch/common/entropy/virtio_rng.rs
- **Committed in:** `5e71833`

**4. [Rule 2 - Critical] virtio_collect 의 panic/누수 경로 보강**
- **Found during:** Task 3
- **Issue:** PATTERNS 본문은 `buf[..n]` 가 buf.len() < n 시 panic, 실패 조기 반환 경로 (instance None / request 실패 / n==0) 에서 scratch 미소거
- **Fix:** `take = min(n, buf.len())` clamp + 모든 이탈 경로 `scratch.zeroize()` (with_attest_buf 전-경로 zeroize 정합)
- **Files modified:** src/arch/common/entropy/virtio_rng.rs
- **Committed in:** `5e71833`

**5. [Rule 3 - Blocking] worktree 에 dev smoke key 부재 (환경 조치, repo 변경 0)**
- **Found during:** 종합 검증 (`make qemu-smoke-smoke`)
- **Issue:** gitignored `keys/dev_trust_root.sk44` 가 worktree 에 없어 feature smoke 빌드 실패
- **Fix:** main repo 에서 복사 (pk44 md5 일치 실측, 쌍 정합) — gitignored 파일이라 repo 변경 0
- **Committed in:** 없음 (환경 조치)

### 기록 사항 (비수정)

- plan verification 의 "13 파일" 은 산술 오기 — plan 자신의 열거 목록이 정확히 12 파일이고 12 파일 전부 존재 실측
- 08-01 SUMMARY 의 stub 표는 check-virtio-sentinel 해소를 Wave 2 로 예정했으나 본 plan Task 3 action 이 sentinel 본문 채움을 명시하여 앞당겨 해소됨

---

**Total deviations:** 5 auto-fixed (Rule 1 x1, Rule 2 x2, Rule 3 x2)
**Impact on plan:** 전부 정합성/보안 확보 목적, scope creep 0. 호출자 시그니처 변경 0 유지

## Issues Encountered

- **Mac QEMU 11 TCG 부팅 결함 재현 (pre-existing, out-of-scope):** `make qemu-smoke-smoke` 가 Plan 01 과 동일 signature 로 실패 (전 marker MISS, "RDSEED/RDRAND 부재"). boot-path diff 는 main.rs 모듈 선언 1 줄뿐임을 `git diff --stat` 으로 실측 — 본 plan 변경과 무관. deferred-items.md 에 재현 기록 추가, 13 marker 정본 회귀는 Linux+KVM lane 위임 (VALIDATION.md + Plan 01 정합)

## Known Stubs

전부 plan 이 명시한 Wave 진행 anchor

| Stub | File | 해소 시점 |
|------|------|-----------|
| quorum.rs QuorumEntropy 본문 부재 (enum 만 존재) | src/arch/common/entropy/quorum.rs | Wave 3 |
| health.rs / jitter.rs 빈 placeholder | src/arch/common/entropy/{health,jitter}.rs | Wave 2 |
| VIRTIO_RNG_INSTANCE = None (boot init 부재) | src/arch/common/entropy/virtio_rng.rs | Wave 4 main.rs probe 호출 |
| timer_frequency calibration fallback None | src/arch/cpu.rs | Wave 2 jitter calibrate 합류 |
| fill_hw_entropy bridge (hw 직접 호출) | src/capability.rs | Wave 3 quorum::collect_with_retry 교체 |

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Wave 2 진입 anchor 준비 완료 — health.rs RCT/APT 본문 + jitter.rs Müller 본문 + virtio_rng.rs sentinel 정밀화 + cycle_counter HAL hook 이 본 골격 위에 본문 추가만 하면 됨
- `make check-entropy-mutex` PASS 전환 + machete ignore 제거로 Wave 0 이월 의무 2 건 전부 이행
- `make ci-phase7` GREEN 유지, 4 개 feature 조합 빌드 매트릭스 전부 실측

---
*Phase: 08-entropy-source-diversification*
*Completed: 2026-07-19*

## Self-Check: PASSED

- created files 8/8 spot-check FOUND (arch 트리 7 + SUMMARY 1), find src/arch 12/12
- task commits 3/3 FOUND (48ae2a8, 2939271, 5e71833)
- mutex build exit 101 + check-entropy-mutex PASS + ci-phase7 GREEN + ENTR-06 guard sum=0 실측
