---
phase: 08-entropy-source-diversification
plan: 05
subsystem: entropy
tags: [qemu-marker, jitter, min-entropy, lto-gate, boot-serial, ci-gate]
wave: 4
requires: [08-01, 08-02, 08-03, 08-04]
provides:
  - "qemu-test.sh 13 entropy marker entropy_dependent=false flip (ENTR-07 production+degraded 강제 PASS)"
  - "qemu-test.sh 신규 4 marker check 합류 (timer / ENTROPY_QUORUM / ENTROPY_SOURCES + ENTROPY_DEGRADED 게이트)"
  - "main.rs BOOT_SELF_TEST_BUF 16384 옥텟 boot serial hex dump (host-side min-entropy 분석 입력)"
  - "check-jitter-lto.sh build-rel 산출물 PASS 실측 (ENTR-08 LTO 회피 검증)"
affects:
  - scripts/qemu-test.sh
  - src/main.rs
  - src/arch/common/entropy/jitter.rs
tech-stack:
  added: []
  patterns:
    - "check_marker klass false = ENTR-07 flip 전 lane 강제 PASS (stall 예외 해제)"
    - "JITTER_BOOT_DUMP_BEGIN N=16384 / END anchor 64 line x 256 byte hex host-side 추출"
    - "check_gated_marker REQUIRE_* default 1 + K0_REQUIRE_DEGRADED 게이트"
key-files:
  created: []
  modified:
    - scripts/qemu-test.sh
    - src/main.rs
    - src/arch/common/entropy/jitter.rs
key-decisions:
  - "reworked 3-mode script (full/tcg-entropy/tcg-no-entropy) 위에 flip 적응 3-mode 로직 + 4 recognition 보존"
  - "ENTROPY_DEGRADED_OK_ACTIVE 는 degraded 빌드 전용이므로 check_marker false 가 아닌 K0_REQUIRE_DEGRADED 게이트 (honest gating count 15)"
  - "jitter.rs boot_self_test_samples 접근자 추가 (private BOOT_SELF_TEST_BUF 노출 Rule 3)"
requirements-completed: [ENTR-03, ENTR-07, ENTR-08]
patterns-established:
  - "Pattern 1: entropy_dependent=false flip 은 reworked klass 시스템에서 stall 예외 해제로 매핑 (full 무변화 tcg-entropy 강제)"
  - "Pattern 2: 16384 sample host-side 분석은 boot serial dump anchor 로 CI lane 위임"
duration: 70min
completed: 2026-07-20
---

# Phase 8 Plan 05: Wave 4 검증 가시 효과 Summary

**qemu-test.sh 13 entropy marker 를 reworked 3-mode script 위에서 entropy_dependent=false 로 flip + 신규 4 marker check 합류하고 main.rs 에 BOOT_SELF_TEST_BUF 16384 옥텟 boot serial hex dump 를 배선 check-jitter-lto.sh 가 실제 build-rel 산출물에 PASS (instructions=1819 black_box=273) QEMU 13-marker boot 회귀와 16384 min-entropy 게이트는 Linux+KVM lane 이연**

## Performance

- **Duration:** ~70 min
- **Completed:** 2026-07-20
- **Tasks:** 2 auto 완료 + 1 checkpoint 사용자 approved (CI delegation)
- **Files modified:** 3 (+ deferred-items.md 이연 기록)

## Accomplishments

- scripts/qemu-test.sh 의 marker 검증 영역을 reworked 3-mode script 구조에 맞춰 적응 flip. 기존 12 check_marker (struct 1 + entropy 5 + stall 6) 의 klass 를 `false` 로 전환해 ENTR-07 의 production+degraded 양 lane 강제 PASS 를 표현. stall 예외 해제로 tcg-entropy 에서도 HSM/BUS/CHAN/WIRE marker 가 강제됨. 3-mode 자동 결정 로직 + K0_TEST_MODE override + 함수 body 의 stall 분기 + Wave 0 의 4 recognition 변수 전부 보존
- 신규 4 marker check 합류 timer / ENTROPY_QUORUM / ENTROPY_SOURCES 는 check_marker `false` 강제 ENTROPY_DEGRADED_OK_ACTIVE 는 degraded 빌드 전용이므로 check_gated_marker + K0_REQUIRE_DEGRADED 게이트로 honest 처리. check_gated_marker 3 종 (ATTEST_PHASE5 / ATTEST_PHASE5_1 / GAP_PHASE6) 의 REQUIRE_* default 를 0 에서 1 로 flip
- src/main.rs 의 ENTROPY_QUORUM marker 다음 위치에 jitter_boot_self_test PASS 시 BOOT_SELF_TEST_BUF 16384 옥텟 전체를 JITTER_BOOT_DUMP_BEGIN N=16384 ~ END 사이 64 line x 256 byte hex 로 emit. format_jitter_dump_line helper 신설 (alloc 0 Korean docstring). host-side ea_iid / Most Common Value 추정 입력 anchor
- jitter.rs 에 boot_self_test_samples 접근자 추가 (private static mut BOOT_SELF_TEST_BUF 를 read-only slice 로 노출 pre-conditioning raw 표본 key material 아님)
- check-jitter-lto.sh 를 실제 build-rel 산출물에 실행해 `[CI] PASS instructions=1819 black_box=273` 실측 (ENTR-08 LTO 회피 binary-level gate 충족)
- 4 cfg 빌드 (closed / entropy-degraded-ok / tls-external / smoke) 전수 GREEN + host test 18/18 PASS 회귀 0

## Task Commits

1. **Task 1: qemu-test.sh 13 marker entropy_dependent false flip + 신규 4 marker check** - `b371f83`
2. **Task 2: main.rs BOOT_SELF_TEST_BUF 16384 옥텟 boot dump + jitter.rs 접근자** - `03d2146`
3. **Task 3: make qemu-kvm / qemu-tcg 13 marker + 16384 min-entropy checkpoint** - 사용자 approved (CI delegation Linux+KVM lane 이연)

**이연 기록 commit:** `c15807f` (deferred-items.md Wave 4 이연)

## Files Created/Modified

- `scripts/qemu-test.sh` - 12 check_marker klass false flip + 신규 3 check_marker (timer/ENTROPY_QUORUM/ENTROPY_SOURCES) + ENTROPY_DEGRADED check_gated_marker + check_gated_marker REQUIRE_* default 0 에서 1 + tcg-no-entropy modal DEPRECATED 주석 + 합류 anchor 주석 (3-mode 로직 보존)
- `src/main.rs` - format_jitter_dump_line helper 신설 + init_prng Ok 분기 ENTROPY_QUORUM marker 다음 BOOT_SELF_TEST_BUF 16384 옥텟 hex dump (JITTER_BOOT_DUMP_BEGIN/END + 64 line)
- `src/arch/common/entropy/jitter.rs` - boot_self_test_samples 접근자 추가 (Rule 3 private buffer 노출)

## Decisions Made

- **reworked 3-mode script 적응** - 본 plan 은 3-mode rework 이전 작성. carryover 지시대로 flip 을 현 klass 시스템에 매핑. reworked 함수 body 에서 klass 는 struct/entropy/stall 중 `stall` 만 tcg-entropy 예외 처리하므로 struct/entropy 는 `false` 와 동작 동일 (cosmetic). stall 을 `false` 로 바꾸면 tcg-entropy 에서도 강제 = ENTR-07 flip 의 정확한 의미. full lane (qemu-kvm /dev/kvm, qemu-tcg K0_TEST_MODE=full) 동작 무변화
- **honest gating count 15 (17 아님)** - plan verify 는 17 을 언급하나 4번째 recognition marker ENTROPY_DEGRADED_OK_ACTIVE 는 degraded 빌드에서만 emit 되므로 production lane 에서 강제하면 false-fail. 이를 K0_REQUIRE_DEGRADED 게이트로 처리해 정직하게 15 개만 unconditional required. Task 1 <verify> 의 >=15 는 충족 (정직성 우선 fabricated marker 배제)
- **jitter.rs 접근자 Rule 3** - Task 2 <files> 는 main.rs 한정이나 BOOT_SELF_TEST_BUF 가 module-private 라 dump 컴파일 불가. boot_self_test_samples pub(crate) 접근자 추가가 필요 최소 fix

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - 블로킹 접근] jitter.rs boot_self_test_samples 접근자 추가**
- **Found during:** Task 2
- **Issue:** plan Task 2 code 는 `crate::arch::common::entropy::jitter::BOOT_SELF_TEST_BUF` 직접 참조를 가정하나 해당 static 은 module-private 라 main.rs 에서 접근 불가 (컴파일 실패)
- **Fix:** jitter.rs 에 `pub(crate) unsafe fn boot_self_test_samples() -> &'static [u8]` 접근자 추가. raw pointer unsafe 를 jitter.rs 안에 encapsulate 하고 read-only slice 노출
- **Files modified:** src/arch/common/entropy/jitter.rs (Task 2 <files> = main.rs 한정 밖)
- **Verification:** 4 cfg 빌드 GREEN + host test 18/18 PASS
- **Committed in:** `03d2146` (Task 2 commit 일부)

### 적응 사항 (carryover-mandated 비수정)

- **qemu-test.sh 3-mode rework 적응** - baseline 이 script 를 full/tcg-entropy/tcg-no-entropy 3-mode 로 재작성한 이후 본 plan 실행. plan 의 "entropy_dependent true->false" flip 을 현 klass 시스템에 매핑 stall 예외 해제로 표현. 3-mode 자동 결정 + K0_TEST_MODE override + 4 recognition 변수 전부 clobber 0
- **marker count 15 vs plan 17** - ENTROPY_DEGRADED_OK_ACTIVE honest gating 으로 unconditional required 는 15. Task 1 <verify> (>=15) 충족 plan-level verification (>=17) 은 over-count 로 판단 (정직성 우선)
- **K0_REQUIRE_DEGRADED Makefile export 미배선** - Task 1 <files> = qemu-test.sh 한정이라 Makefile::qemu-tcg 의 K0_REQUIRE_DEGRADED=1 export 는 미배선. Wave 5 ci-phase8 sealing 시 배선 권고 (deferred-items 기록)

---

**Total deviations:** 1 auto-fixed (Rule 3 접근자 1) + 적응 3 (carryover-mandated)
**Impact on plan:** 접근자 1건 외 plan 정합. reworked script clobber 0 3-mode 로직 + 4 recognition 보존. 호출자 시그니처 변경 0

## Issues Encountered

- **QEMU 13-marker boot 회귀 본 macOS 호스트 실행 불가** - /dev/kvm 부재 (full lane) + QEMU 11 TCG pre-existing RDRAND/RDSEED · post-TLS stall 결함 (Wave 0~3 기록). Task 1/2 의 script/code edit 는 완료 정본 boot 검증은 Linux+KVM lane 이연 (deferred-items 기록 checkpoint 사용자 approved CI delegation)
- **16384 min-entropy 게이트 real boot serial 필요** - BOOT_SELF_TEST_BUF dump 추출은 real QEMU boot serial 이 있어야 가능. 본 호스트 미생성으로 ea_iid 입력 부재 Linux+KVM lane 이연

## Verification Results (실측)

| 항목 | 결과 |
|------|------|
| `bash -n scripts/qemu-test.sh` | PASS |
| check_marker "false" count | 15 (Task 1 <verify> >=15 PASS) |
| check_gated_marker REQUIRE_*:-1 count | 3 PASS |
| DEPRECATED Phase 8 주석 + check_marker ENTROPY_QUORUM | PASS |
| 3-mode 로직 + 4 recognition 변수 보존 | PASS (함수 body stall 분기 잔존) |
| `cargo build --target x86_64-unknown-none` (closed) | PASS |
| `cargo build --features entropy-degraded-ok` | PASS |
| `cargo build --features tls-external` | PASS |
| `cargo build --features smoke` (임시 dev sk provisioning 커밋 0) | PASS |
| host test 4종 (`--include-ignored`) | **18/18 PASS** |
| `make build-rel` + `bash scripts/check-jitter-lto.sh` | **PASS** (instructions=1819 black_box=273) |
| `make qemu-kvm` 13 marker boot | **Linux+KVM lane 이연** (deferred-items) |
| `make qemu-tcg` 13 marker boot | **Linux+KVM lane 이연** (deferred-items) |
| 16384 sample min-entropy >= 0.5 | **Linux+KVM lane 이연** (real boot serial 필요) |
| `make ci-phase8` 6-leg composite | **Linux+KVM lane 이연** (qemu-kvm/qemu-tcg 포함) |

## Known Stubs

없음. Task 1/2 산출물은 전부 실 배선 (marker flip 실동작 + dump emit 실동작). QEMU boot 검증만 환경 결함으로 CI lane 위임 (stub 아닌 이연)

## Threat Flags

없음. 본 wave 의 surface (marker flip + boot dump + 접근자) 는 전부 plan threat_model (T-08-02/03/04/07) 의 mitigate 대상. BOOT_SELF_TEST_BUF dump 는 pre-conditioning raw 표본 한정 key material 미노출. marker 는 honest gating (init_prng Ok 분기 + jitter_ok 조건에서만 emit)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Wave 5 (Plan 06) 진입 anchor 완비 ci-phase8 6-leg composite 실행 + PHASE-SUMMARY 작성 + state.complete-phase 동기화
- Linux+KVM CI lane 위임 항목 (deferred-items 기록) `make qemu-kvm` / `make qemu-tcg` 13 marker PASS + 16384 min-entropy >= 0.5 + `make ci-phase8`
- Wave 5 배선 권고 Makefile::qemu-tcg 의 `K0_REQUIRE_DEGRADED=1` export (degraded lane 에서 ENTROPY_DEGRADED marker 강제)
- ENTR-08 (LTO 회피) 는 본 wave 에서 build-rel 산출물 PASS 로 완결 ENTR-03/ENTR-07 은 script/code edit 완결 boot 검증만 CI lane 잔존

---
*Phase: 08-entropy-source-diversification*
*Completed: 2026-07-20*

## Self-Check: PASSED
</content>
</invoke>
