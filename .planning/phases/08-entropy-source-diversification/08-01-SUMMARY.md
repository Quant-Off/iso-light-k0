---
phase: 08-entropy-source-diversification
plan: 01
subsystem: infra
tags: [entropy, virtio-drivers, cargo-features, makefile-ci, qemu-markers, compile-fail]

# Dependency graph
requires:
  - phase: 07-integration-gap-audit
    provides: check-machete standing gate + ci-phase7 prior art
provides:
  - Cargo.toml feature entropy-degraded-ok + virtio-drivers 0.13 (default-features=false) 등록
  - scripts/check-jitter-lto.sh skeleton (ENTR-08 objdump CI, Wave 0 expected fail-fast)
  - scripts/check-virtio-sentinel.sh skeleton (ENTR-04 3 grep 패턴, Wave 0 expected fail-fast)
  - tests/compile-fail/entropy-mutex.rs (ENTR-05 1차 안전망)
  - scripts/qemu-test.sh 신규 entropy marker 4 종 recognition (회귀 0)
  - Makefile ci-phase8 6-leg composite + 6 skeleton targets + .PHONY 확장
affects: [08-02, 08-03, 08-04, 08-05, 08-06, phase-12-ci-matrix]

# Tech tracking
tech-stack:
  added: [virtio-drivers 0.13 (crates.io, rcore-os, default-features=false)]
  patterns:
    - Wave 0 skeleton fail-fast CI 표면 선행 신설 (본문 채움은 Wave 1~4)
    - EXPECTED_PRESENT source-grep 게이트 (check-no-alloc-bus.sh mirror)

key-files:
  created:
    - scripts/check-jitter-lto.sh
    - scripts/check-virtio-sentinel.sh
    - tests/compile-fail/entropy-mutex.rs
  modified:
    - Cargo.toml
    - Makefile
    - scripts/qemu-test.sh

key-decisions:
  - "virtio-drivers 를 cargo-machete metadata ignore 에 한시 등록 (Wave 1 본문 합류 시 제거 의무)"
  - "check-entropy-mutex leg 는 plan 원문 반전 오류를 수정하여 compile_error 토큰 존재 시 PASS 로 구현"
  - "13 marker 전체 회귀의 정본 검증은 Linux+KVM lane 으로 위임 (Mac QEMU 11 TCG 비결정 결함)"

patterns-established:
  - "Wave 0 skeleton: CI leg 는 target 부재 시 진단 메시지 + exit 1 fail-fast, false-pass 차단"
  - "marker recognition 선행 + check_marker 합류 후행 (Wave 4 anchor 주석)"

requirements-completed: [ENTR-01, ENTR-04, ENTR-05, ENTR-07, ENTR-08]

# Metrics
duration: 45min
completed: 2026-07-19
---

# Phase 8 Plan 01: Wave 0 Infra Skeleton Summary

**entropy-degraded-ok feature 와 virtio-drivers 0.13 등록 + ci-phase8 6-leg 호출 표면 + qemu-test 신규 marker 4 종 recognition 을 Phase 1~7 회귀 0 으로 정합**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-07-19T10:38:44Z
- **Completed:** 2026-07-19T11:24:00Z
- **Tasks:** 4/4
- **Files modified:** 6 (created 3, modified 3)

## Accomplishments

- Cargo.toml 에 `entropy-degraded-ok = []` feature 와 `virtio-drivers = { version = "0.13", default-features = false }` 등록, closed 프로필과 feature 활성 프로필 양쪽 `cargo build --target x86_64-unknown-none` 통과 (alloc-zero 정합, release LTO 빌드도 통과)
- check-jitter-lto.sh / check-virtio-sentinel.sh skeleton 신설 (chmod +x), Wave 0 fail-fast exit 1 실측 (바이너리 부재 / 심볼 부재 / target 파일 부재 3 경로 전부 진단 메시지 + exit 1)
- tests/compile-fail/entropy-mutex.rs 신설 (Korean docstring, 단일 cfg + const panic)
- qemu-test.sh 에 HAS_TIMER_LINE / HAS_ENTROPY_QUORUM_OK / HAS_ENTROPY_DEGRADED_ACTIVE / HAS_ENTROPY_SOURCES_AVAILABLE 4 변수 + grep 4 줄 recognition-only 추가, diff 삭제 라인 0 (기존 marker 회귀 0)
- Makefile 에 ci-phase8 6-leg composite + check-jitter-lto / check-virtio-sentinel / check-entropy-mutex / entropy-host-test / qemu-tcg / qemu-kvm 신설, `make -n ci-phase8` 6-leg 시퀀스 노출, `make ci-phase7` 회귀 통과 실측

## Task Commits

1. **Task 1: Cargo.toml feature + virtio-drivers 0.13** - `11b7efb`
2. **Task 2: check-jitter-lto + check-virtio-sentinel + entropy-mutex.rs** - `13cd00d`
3. **Task 3: qemu-test.sh marker recognition** - `2d9b864`
4. **Task 4: Makefile ci-phase8 composite + skeleton legs** - `c689ad2`

## Files Created/Modified

- `Cargo.toml` - entropy-degraded-ok feature, virtio-drivers 0.13 dep, cargo-machete 한시 ignore
- `scripts/check-jitter-lto.sh` - ENTR-08 objdump LTO 보호 게이트 skeleton (objdump -> gobjdump fallback)
- `scripts/check-virtio-sentinel.sh` - ENTR-04 sentinel + ct_eq + zeroize 3 패턴 grep skeleton
- `tests/compile-fail/entropy-mutex.rs` - ENTR-05 mutex 1차 안전망
- `scripts/qemu-test.sh` - 신규 marker 4 종 recognition + Wave 4 합류 anchor 주석 (additive only)
- `Makefile` - ci-phase8 6-leg + 6 skeleton targets + .PHONY 7 항목 확장

## Decisions Made

- machete ignore 는 `[package.metadata.cargo-machete]` (Cargo.toml) 에 배치, `.machete.toml` 은 cargo-machete 0.9.2 가 읽지 않음을 실측했고 정책 파일 (.machete.toml) 은 변경 0
- CLAUDE.md 기호 규칙 우선 적용 plan 원문의 Unicode 화살표와 em dash 는 ASCII "->" / 일반 서술로 치환

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] worktree path-dep 미해결**
- **Found during:** Task 1 사전 baseline build
- **Issue:** worktree 의 `../elib-k0-nt/*` path dep 이 `.claude/worktrees/elib-k0-nt` 로 해석되어 부재
- **Fix:** `.claude/worktrees/elib-k0-nt -> /Library/Quant/code-projects/elib-k0-nt` symlink 생성 (환경 조치, repo 변경 0)
- **Verification:** `cargo build --target x86_64-unknown-none` 통과
- **Committed in:** 없음 (repo 외 환경 조치)

**2. [Rule 3 - Blocking] virtio-drivers 미사용 상태가 ci-phase7 check-machete 회귀를 파괴**
- **Found during:** Task 1
- **Issue:** Wave 0 사전 등록 dep 은 코드 참조 0 -> `cargo machete` exit 1 -> plan 이 의무화한 `make ci-phase7` 회귀 통과와 충돌
- **Fix:** Cargo.toml `[package.metadata.cargo-machete] ignored = ["virtio-drivers"]` 한시 추가 + Wave 1 제거 의무 주석. `.machete.toml` (proc-macro 한정 정책) 은 미변경
- **Files modified:** Cargo.toml
- **Verification:** `cargo machete` exit 0, `make ci-phase7` 전체 통과
- **Committed in:** `11b7efb`
- **후속 의무:** Plan 02 (Wave 1) 의 virtio KernelHal 본문 합류 시 본 ignore 항목 제거

**3. [Rule 1 - Bug] check-jitter-lto.sh 심볼 부재 진단 메시지 소실**
- **Found during:** Task 2 검증
- **Issue:** `set -euo pipefail` 하에서 SYMBOL 추출 command substitution 의 grep 무매칭이 조기 종료를 유발, exit 1 은 맞으나 진단 메시지 미출력 (PATTERNS §2.12 스니펫에도 동일 잠재 결함)
- **Fix:** 추출 파이프라인 말미 `|| true` 가드 추가
- **Files modified:** scripts/check-jitter-lto.sh
- **Verification:** 바이너리 부재 / 심볼 부재 (debug 바이너리) 2 경로 모두 메시지 + exit 1 실측
- **Committed in:** `13cd00d`

**4. [Rule 1 - Bug] check-entropy-mutex plan 원문 recipe 논리 반전**
- **Found during:** Task 4
- **Issue:** plan 원문 `@! cargo build ... | grep -q "compile_error" || FAIL` 은 compile_error 존재 시 FAIL, 부재 시 PASS 로 동작 -> plan 자신이 명시한 Wave progression (Wave 0 expected exit 1, Wave 1 PASS 전환) 과 정반대
- **Fix:** 선행 `!` 제거, compile_error 토큰 존재 시 PASS 로 구현 + PASS echo 라인 추가
- **Files modified:** Makefile
- **Verification:** Wave 0 실행 시 "[CI] FAIL ENTR-05 compile_error trigger 누락" + make Error 1 (expected fail-fast) 실측
- **Committed in:** `c689ad2`

---

**Total deviations:** 4 auto-fixed (Rule 1 x2, Rule 3 x2)
**Impact on plan:** 전부 정합성 확보 목적, scope creep 0. machete ignore 는 Wave 1 제거 의무로 추적

## Issues Encountered

- **Mac QEMU 11 TCG 부팅 비결정 결함 (pre-existing, out-of-scope):** `make qemu-smoke` (tcg-entropy) 가 "MMU Typestate Init Done" 직후 무증상 정지 또는 #UD wild-jump 패닉으로 실패. base commit 5205f1d 의 Cargo.toml 로 원복 재빌드한 kernel 로도 동일 재현 -> 본 plan 변경과 무관함을 실증. qemu-test.sh 변경분은 additive only (삭제 라인 0) 로 구조적으로도 회귀 불가. deferred-items.md 에 기록, 13 marker 정본 회귀 검증은 Linux+KVM lane 위임

## Known Stubs

전부 plan 이 명시한 Wave 0 의도적 skeleton (fail-fast 로 false-pass 차단)

| Stub | File | 해소 시점 |
|------|------|-----------|
| jitter_fold_step 심볼 부재 fail-fast | scripts/check-jitter-lto.sh | Wave 2 (Plan 03 Task 2) 1차 PASS |
| virtio_rng.rs 부재 fail-fast | scripts/check-virtio-sentinel.sh | Wave 2 virtio_rng.rs 신설 |
| compile_error 부재 expected exit 1 | Makefile check-entropy-mutex | Wave 1 mod.rs compile_error 신설 |
| host test 4 종 부재 fail-fast | Makefile entropy-host-test | Plan 03 Task 4 본문 채움 |
| 신규 marker 4 종 recognition only | scripts/qemu-test.sh | Wave 4 check_marker 합류 |

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Wave 1 진입 anchor 준비 완료 compile_error mod.rs 신설 + virtio KernelHal + capability.rs hw lossless move + arch::cpu::timer_frequency 표면
- Wave 1 의무 2 건 (1) src/arch/common/entropy/mod.rs 의 compile_error! 신설 -> check-entropy-mutex PASS 전환 (2) virtio-drivers 본문 합류 시 Cargo.toml machete ignore 제거
- `make ci-phase8` 호출 가능 (Wave 0 은 expected fail-fast), `make ci-phase7` GREEN 유지

---
*Phase: 08-entropy-source-diversification*
*Completed: 2026-07-19*

## Self-Check: PASSED

- created files 4/4 FOUND (scripts 2, tests 1, SUMMARY 1)
- task commits 4/4 FOUND (11b7efb, 13cd00d, 2d9b864, c689ad2)
- Cargo feature grep PASS, .PHONY ci-phase8 PASS
