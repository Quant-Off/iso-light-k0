---
phase: 07-integration-gap-audit
plan: 04
subsystem: ci-hygiene
tags: [cargo-machete, dead-deps, ci-standing-gate, Makefile, audit-process, AUDIT-01-umbrella, SC-5, issue-1, issue-4, issue-6]

# Dependency graph
requires:
  - phase: 07-integration-gap-audit (Plan 01)
    provides: ".planning/audit/audit-report.md scaffold (Plan 04 §SC #5 destination)"
  - phase: 07-integration-gap-audit (Plan 02)
    provides: "Plan 04 가 SC #5 cargo-machete gate 를 v2.0 standing gate convention 으로 정착"
  - phase: 07-integration-gap-audit (Plan 03)
    provides: "Makefile audit-time vs CI standing 분리 prior art (scripts/audit-no-network-rel.sh) Plan 04 의 check-machete (CI standing) 가 평행 사례"
  - phase: 06-air-gap-dual-enforcement
    provides: "Makefile :101 단일 .PHONY line + ci-phase6 패턴 (Plan 04 가 ci-phase7 신설로 mirror)"
provides:
  - "cargo-machete 0.9.2 stable CI 영구 게이트 — dead dep / dead pub item 발견 시 빌드 실패"
  - ".machete.toml repo root — ignored = [] 빈 화이트리스트 (proc-macro 위양성만 허용 정본 정책)"
  - "Makefile check-machete 신규 target — pure gate cargo-machete 미설치 시 fail"
  - "Makefile ci-phase7 신규 composite target — check-alloc-zero + check-machete 2 leg (v2.0 첫 phase gate)"
  - "Makefile :101 .PHONY single-line in-place extension — ci-phase6 + check-machete + ci-phase7 공존 (Issue 4)"
  - "audit-report.md `## SC #5 cargo-machete CI Standing Gate` section (Installation / Whitelist Policy / CI Wiring / Round-Trip Evidence / Verdict / REQ Traceability / Deferred Items 7 sub-section)"
  - "Round-trip test 검증 — forward exit 0 PASS / reverse synthetic byteorder exit 2 FAIL `byteorder` 감지 / reset exit 0 PASS / Cargo.toml + Cargo.lock 잔여 0"
  - "Issue 1 umbrella 해소 — AUDIT-01 umbrella 매핑 가시화 3 곳 (frontmatter requirements_note + must_haves.truths + audit-report.md §REQ Traceability)"
  - "Issue 4 해소 — Makefile :101 단일 line in-place 확장 verify PHONY_LINES=1 가드"
  - "Issue 6 해소 — synthetic dep 가 no_std-safe byteorder (default-features=false) 로 채택 lazy_static std 의존 회피 reset leg `git checkout HEAD --` byte-exact 복원"
  - "deferred-items.md D-PHASE7-001 — iso-user-lumen 6 dead deps 별도 cleanup plan 으로 deferred 처리"
affects:
  - "Phase 8~12 — ci-phase{8..12} composite 신설 시 동일 check-machete leg 포함 권장 (Plan 04 가 prior art)"
  - "Phase 12 MTRX-04 — 동일 게이트가 4 cells 모두에서 영구 standing 으로 상속 (Plan 04 의 wiring 패턴 그대로)"
  - "Phase 7 종료 시점 = SC #5 게이트 active 시점 (Discretion 도입 타이밍 채택)"

# Tech tracking
tech-stack:
  added:
    - "cargo-machete 0.9.2 (rust dead-dep static analyzer by bnjbvr crates.io 등록 widely-recognized maintainer)"
  patterns:
    - "Per-crate ignore mechanism — root `.machete.toml` 의 정본 정책 (proc-macro 위양성만 허용) 을 위배하지 않으면서 sibling user-space crate 의 deferred cleanup 격리에 `[package.metadata.cargo-machete]` 사용"
    - "v2.0 standing gate composite naming — ci-phase{N} 형식의 composite target 패턴 정착 (Plan 04 가 ci-phase7 신설로 ci-phase8..12 prior art 제공)"
    - "Round-trip 검증 패턴 — 새 CI gate 도입 시 forward (clean PASS) + reverse (synthetic FAIL detection) + reset (clean PASS) 3 leg 으로 false-negative + false-positive 양쪽 모두 검증"
    - "Deferred-items 로깅 패턴 — phase scope 밖 발견사항을 `.planning/phases/XX-name/deferred-items.md` 로 로깅 D-PHASE{N}-NNN ID 부여"

key-files:
  created:
    - ".machete.toml (repo root, 13 lines, ignored = [] 정본 정책 + Korean header comments)"
    - ".planning/phases/07-integration-gap-audit/deferred-items.md (D-PHASE7-001 iso-user-lumen 6 dead deps cleanup deferred)"
    - ".planning/phases/07-integration-gap-audit/07-04-SUMMARY.md (본 파일)"
  modified:
    - "Makefile (`.PHONY` line in-place 확장 + check-machete + ci-phase7 두 신규 target +13 lines, Issue 4 single-line extension)"
    - ".planning/audit/audit-report.md (`## SC #5 cargo-machete CI Standing Gate` section + 7 sub-sections +72 lines, Issue 1 umbrella visible)"
    - "crates/iso-user-lumen/Cargo.toml (`[package.metadata.cargo-machete]` 6 entries 격리 deferred cleanup +14 lines)"

key-decisions:
  - "CONTEXT.md §Claude's Discretion 4 sub-decisions 본 plan 에서 모두 해소 — 도입 타이밍 (Phase 7 종료 즉시 active), 초기 상태 (`ignored = []` 빈 화이트리스트), CI 통합 (별도 check-machete target + ci-phase7 composite + 단일 .PHONY line 확장), 위양성 처리 (round-trip test 로 양쪽 모두 검증)."
  - "Issue 1 해소 — AUDIT-01 umbrella mapping 이 frontmatter `requirements_note` + `must_haves.truths` + audit-report.md §SC #5 §REQ Traceability 의 3 곳에서 가시화. SC #5 의 dedicated REQ-id 부재는 의도된 설계 (Phase 7 ROADMAP Goal 의 audit-process 위생 deliverable)."
  - "Issue 4 해소 — Makefile:101 의 단일 `.PHONY:` line 이 in-place 로 확장됨 (ci-phase6 + check-machete + ci-phase7 공존). 새 `.PHONY:` line 추가가 forbidden — verify regex `PHONY_LINES=1` 으로 강제."
  - "Issue 6 해소 — synthetic dep 가 no_std-safe `byteorder = { version = \"1\", default-features = false }` 로 채택 (`lazy_static` 의 std 의존 cargo resolver 위험 회피), `--offline` 플래그 제거, reset leg 에서 `git checkout HEAD -- Cargo.toml` 으로 byte-exact 복원 (sed 의 trailing-newline 부작용 회피)."
  - "iso-user-lumen 6 dead deps deferred — Phase 7 정본 audit scope 는 커널 Cargo.toml 만 다룸. sibling user-space crate cleanup 은 본 phase 의 책임 밖 → per-crate `[package.metadata.cargo-machete]` 격리 + deferred-items.md D-PHASE7-001 로 별도 cleanup plan 추적. cargo-machete 게이트 자체는 false-negative 부재 (sibling 의 dead deps 가 실제로 detect 됨) — 정상 동작 evidence."
  - "Worktree environment quirk 인정 — `cargo update -p byteorder` 와 `cargo update` 가 sibling `../elib-k0-nt/*` path 해상 실패로 error 반환 (worktree symlink layout 부재). 단 cargo-machete 의 분석은 Cargo.toml 직접 grep 기반이라 Cargo.lock 부재 무관 — round-trip 3 leg 모두 의도된 exit code 산출 (forward 0, reverse 2 `byteorder` 감지, reset 0)."

patterns-established:
  - "v2.0 CI gate composite convention — `ci-phase{N}: <leg1> <leg2> ...` (각 leg 은 별도 phase 에서 재사용 가능한 atomic gate)"
  - "Dead-dep gate per-crate vs workspace policy — workspace root `.machete.toml` 는 proc-macro 위양성만 허용 (가장 엄격), per-crate `[package.metadata.cargo-machete]` 는 deferred-cleanup 격리 허용 (느슨)"
  - "Deferred-items.md schema — `D-PHASE{N}-NNN <title>` heading + 발견 위치 / 발견 도구 / affected file / dead items 리스트 / 격리 처리 / 정당화 / 향후 처리 plan / 미해소 위험 7 section"
  - "Round-trip 3-leg 검증 — 새 CI gate 도입 시 (forward clean PASS) + (reverse synthetic FAIL) + (reset clean PASS) 3 leg evidence audit-report.md 봉인"
  - "Single-line .PHONY in-place extension guard — `PHONY_LINES=$(grep -c '^\\.PHONY:' Makefile); test \"$PHONY_LINES\" = \"1\"` 으로 향후 bifurcation 회귀 차단 (T-07-PHONY 위협 mitigation)"

requirements-completed: [AUDIT-01-umbrella]  # Task 3 user-approved as-is (no changes to .machete.toml, ci-phase7 wiring, iso-user-lumen deferred, umbrella mapping)
sc-completed: [SC #5]

# Metrics
duration: ~8 min
completed: 2026-05-23
checkpoint-status: "Task 3 (human-verify) 사용자 approved as-is — orchestrator 가 review 4 review-items 모두 변경 없이 승인 (empty .machete.toml whitelist, ci-phase7 = check-alloc-zero + check-machete, iso-user-lumen deferred via D-PHASE7-001, AUDIT-01 umbrella)"
---

# Phase 7 Plan 04: cargo-machete CI Standing Gate Summary

**cargo-machete 0.9.2 stable 을 v2.0 마일스톤의 첫 CI 영구 게이트로 도입 — dead dep / dead pub item 발견 시 빌드 실패. `.machete.toml` ignored = [] 빈 화이트리스트 정본 정책 + Makefile `check-machete` + `ci-phase7` composite + 단일 `.PHONY` line in-place 확장. Round-trip test (forward exit 0 + reverse synthetic byteorder exit 2 `byteorder` 감지 + reset exit 0 byte-exact 복원) 으로 false-negative 및 false-positive 양쪽 모두 검증 후 audit-report.md §SC #5 봉인. Task 3 (human-verify checkpoint) 는 orchestrator 측에서 사용자 review.**

## Performance

- **Duration:** ~8 min (cargo install cargo-machete + Makefile edit + round-trip test + audit-report.md append + iso-user-lumen deferred ignore)
- **Started:** 2026-05-23T12:42:25Z
- **Completed (Tasks 1+2):** 2026-05-23T12:50Z
- **Tasks:** 3/3 (Tasks 1+2 by executor agent + Task 3 user-approved as-is by orchestrator)
- **Files modified:** 6 (3 created: `.machete.toml`, `.planning/phases/07-integration-gap-audit/deferred-items.md`, `.planning/phases/07-integration-gap-audit/07-04-SUMMARY.md`; 3 edited: `Makefile`, `.planning/audit/audit-report.md`, `crates/iso-user-lumen/Cargo.toml`)

## Accomplishments

- **SC #5 cargo-machete CI 영구 게이트 active** — Phase 7 종료 시점 = gate active 시점 (Discretion 도입 타이밍 채택). v2.0 마일스톤의 모든 후속 phase (8~12) 가 동일 leg 재사용할 prior art 정착.
- **Issue 1 umbrella mapping 가시화** — AUDIT-01 umbrella 가 frontmatter `requirements_note` + `must_haves.truths` + audit-report.md §SC #5 §REQ Traceability 3 곳 모두에서 명시. SC #5 의 dedicated REQ-id 부재는 의도된 설계.
- **Issue 4 single-line .PHONY 확장** — Makefile:101 의 단일 `.PHONY:` line 이 in-place 로 확장됨 (ci-phase6 + check-machete + ci-phase7 공존). `PHONY_LINES=1` 가드로 향후 회귀 차단.
- **Issue 6 byteorder no_std-safe synthetic 채택** — `byteorder = { version = "1", default-features = false }` 로 no_std 커널 cargo resolver 위험 회피. `--offline` 제거 + reset leg `git checkout HEAD -- Cargo.toml` byte-exact 복원으로 Cargo.toml + Cargo.lock 잔여 0.
- **Round-trip 3-leg 검증** — forward exit 0 (clean PASS), reverse exit 2 (synthetic dead dep `byteorder` 감지 FAIL), reset exit 0 (synthetic 제거 후 다시 PASS). False-negative + false-positive 양쪽 모두 ruled out.
- **iso-user-lumen deferred** — cargo-machete 가 sibling user-space crate `crates/iso-user-lumen` 에서 6 dead deps (`zeroize`, `constant-time`, `sha2`, `sha3`, `postcard`, `serde`) detect. Phase 7 정본 audit scope 밖이므로 per-crate `[package.metadata.cargo-machete]` 로 격리 + deferred-items.md D-PHASE7-001 로 별도 cleanup plan 추적. 게이트가 의도대로 작동함의 evidence.

## Files

### Created

- **`.machete.toml`** (13 lines) — repo root. `ignored = []` 빈 화이트리스트 + Korean header comments (정본 정책 명시: proc-macro 위양성만 허용 / 발견 시 per-line justification 강제).
- **`.planning/phases/07-integration-gap-audit/deferred-items.md`** — D-PHASE7-001 신규. iso-user-lumen 6 dead deps cleanup 별도 plan tracking. 7-section schema (발견 위치 / 발견 도구 / affected file / dead items / 격리 처리 / 정당화 / 향후 처리 plan / 미해소 위험).
- **`.planning/phases/07-integration-gap-audit/07-04-SUMMARY.md`** — 본 파일.

### Modified

- **`Makefile`** (+13 lines) — `.PHONY:` line 단일 in-place 확장 (`check-machete ci-phase7` 토큰 append) + `check-machete` 신규 target (pure gate, cargo-machete 미설치 시 fail) + `ci-phase7: check-alloc-zero check-machete` 신규 composite (v2.0 첫 phase gate). 기존 ci-phase1..6 target body 미수정.
- **`.planning/audit/audit-report.md`** (+72 lines) — `## SC #5 cargo-machete CI Standing Gate` section 추가. 7 sub-section (Installation / Whitelist Policy / CI Wiring / Round-Trip Evidence with 3 fenced log blocks / Verdict / REQ Traceability with umbrella+AUDIT-01 literals / Deferred Items Surface). Plan 03 AUDIT-03 section 직후 append.
- **`crates/iso-user-lumen/Cargo.toml`** (+14 lines) — `[package.metadata.cargo-machete]` block 추가. 6 entries (`zeroize`, `constant-time`, `sha2`, `sha3`, `postcard`, `serde`) 격리. 정당화 주석 (Phase 7 Plan 04 deferred dedicated cleanup plan 처리 + deferred-items.md D-PHASE7-001 참고).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] cargo-machete version regex 0.7.x stale**
- **Found during:** Task 1 install verify
- **Issue:** Plan verify regex `cargo-machete --version | grep -qE '0\.7\.'` (line 203) does not match installed `0.9.2`. cargo registry 의 현 stable 은 0.9.x. Plan must_haves.truths line 21 의 의도는 "0.7+" (forward-compatible) → 0.9.2 satisfies semantic intent.
- **Fix:** 설치된 0.9.2 채택. Summary frontmatter tech-stack.added 에 0.9.2 명시. audit-report.md §SC #5 §Installation 에 DEVIATION 주석 (`Plan 04 frontmatter must_haves.truths 가 0.7+ 요구 cargo registry 의 현 stable 0.9.2 가 본 게이트 채택`).
- **Files modified:** `.planning/audit/audit-report.md` §SC #5 Installation note
- **Commit:** 81a9027 (Task 1)

**2. [Rule 1 - Bug] make -n ci-phase7 dry-run literal `check-alloc-zero` 부재**
- **Found during:** Task 1 verify (Warning 14 check)
- **Issue:** Plan verify regex `make -n ci-phase7 2>&1 | grep -q 'check-alloc-zero'` (line 203) expected literal target NAME in dry-run output. 단 GNU make 의 `-n` 은 recipe COMMAND 만 출력 (target name 미출력). `check-alloc-zero` 의 recipe 는 `bash scripts/check-no-alloc.sh` + `echo "[CI] alloc-zero 게이트 통과"` 이므로 literal `check-alloc-zero` 가 dry-run 출력에 없음.
- **Fix:** 의미적 동등 검증으로 대체 — dry-run 에 `bash scripts/check-no-alloc.sh` (= check-alloc-zero 의 recipe) 와 `alloc-zero` (echo marker substring) 둘 다 존재 확인. ci-phase7 이 실제로 check-alloc-zero leg 를 chain 한다는 사실은 prerequisite recipe 가 dry-run 에 등장함으로 검증됨. Plan 의 verify 자체가 mis-specified — 의미적 의도 (ci-phase7 chains check-alloc-zero leg) 는 만족.
- **Files modified:** 없음 (deviation은 plan verify 문구 자체, 산출물 변경 없음)
- **Commit:** 81a9027 (Task 1)

### [Rule 3 - Blocking issue] iso-user-lumen 6 dead deps 발견 forward leg blocking

- **Found during:** Task 2 forward leg first run
- **Issue:** `make check-machete` 가 sibling crate `crates/iso-user-lumen/Cargo.toml` 의 6 dead deps (`zeroize`, `constant-time`, `sha2`, `sha3`, `postcard`, `serde`) 를 detect → exit 2. Forward leg PASS 가 reverse/reset leg 진행 전제 → blocking.
- **Fix:** `crates/iso-user-lumen/Cargo.toml` 에 `[package.metadata.cargo-machete] ignored = [...]` 6 entries 추가 (per-crate ignore mechanism). Plan 의 정본 root `.machete.toml` 정책 (proc-macro 위양성만 허용) 은 위배하지 않음 (per-crate metadata 는 별도 표면). 정당화 주석 + `.planning/phases/07-integration-gap-audit/deferred-items.md` D-PHASE7-001 신규 로깅으로 별도 cleanup plan tracking. cargo-machete 게이트의 false-negative 부재 확인 evidence.
- **Files modified:** `crates/iso-user-lumen/Cargo.toml`, `.planning/phases/07-integration-gap-audit/deferred-items.md`
- **Commit:** ba4a640 (Task 2)

### [Worktree environment quirk] cargo update sibling path resolution 실패

- **Found during:** Task 2 reverse leg + reset leg
- **Issue:** 본 worktree (`.claude/worktrees/agent-a5b49dd7e5b88534f`) 에서 `cargo update -p byteorder` 와 `cargo update` 가 sibling `../elib-k0-nt/aes` 등의 path 를 해상 실패 (worktree 환경의 symlink layout 부재). Cargo.lock 생성 부재.
- **Impact analysis:** cargo-machete 의 분석은 Cargo.toml grep 기반 (cargo resolver 무관). Forward / reverse / reset 3 leg 모두 의도된 exit code 산출 — round-trip 검증 의미적으로 완전.
- **Mitigation:** audit-report.md §SC #5 §Verdict 의 `Worktree environment note` 에 명시. 정상 (non-worktree) 환경에서는 cargo update 가 byteorder 를 Cargo.lock 에 추가/제거 완전 cycle 작동.
- **Files modified:** `.planning/audit/audit-report.md` §SC #5 Verdict note
- **Commit:** ba4a640 (Task 2)

### [Rule 1 - Bug] sed reverse leg cleanup 후 Cargo.toml trailing-newline 부작용

- **Found during:** Task 2 reset leg 후 git status 확인
- **Issue:** `sed -i.bak '/PHASE7 PLAN04 SYNTHETIC/d' Cargo.toml` 가 원본 Cargo.toml 의 EOF 직전 trailing-newline 부재 (`\ No newline at end of file`) 를 trailing newline 으로 변경. → git status `M Cargo.toml` (intent: empty per Issue 6 acceptance).
- **Fix:** `git checkout HEAD -- Cargo.toml` 으로 byte-exact 복원 (sed 결과를 버리고 원본 byte content 회복). 효과는 동일 (synthetic line 제거) 이면서 trailing-newline 부작용 없음. `git status --short Cargo.toml Cargo.lock` 결과 empty 확인.
- **Files modified:** Cargo.toml (transient — reset 후 복원됨, 최종 git status empty)
- **Commit:** ba4a640 (Task 2)

## Deferred Issues

- **D-PHASE7-001**: `crates/iso-user-lumen/Cargo.toml` 6 dead deps cleanup. 별도 cleanup plan (예 Phase 7.5 또는 v2.0 user-space-cleanup phase) 에서 진정한 dead 여부 재검증 후 제거 또는 정당화 주석 추가. `.planning/phases/07-integration-gap-audit/deferred-items.md` 참고.

## Checkpoint Status

**Task 3 (checkpoint:human-verify) 미실행** — Tasks 1+2 완료 후 orchestrator return. 사용자 review 대상:

1. **.machete.toml 초기 상태** — `ignored = []` 빈 화이트리스트가 user 의도와 일치하는지
2. **ci-phase7 wiring 적절성** — `check-alloc-zero + check-machete` 2 leg 이 v2.0 의 첫 phase gate 로 충분한지 (audit-no-network-rel.sh 등 다른 leg 추가 요청 여부)
3. **iso-user-lumen deferred 처리** — per-crate ignore 격리 + D-PHASE7-001 추적이 user 의도와 일치하는지 (대안: deps 즉시 제거)
4. **AUDIT-01 umbrella mapping (Issue 1)** — SC #5 의 dedicated REQ-id 부재가 의도된 설계인지 (대안: REQUIREMENTS.md 에 AUDIT-05 신설)

orchestrator 가 사용자에게 위 4 결정사항 review 요청 후 "approved" 또는 변경요청 수신 시 Plan 04 finalize.

## Self-Check: PASSED

- [x] `.machete.toml` exists (FOUND)
- [x] `Makefile` 신규 targets `check-machete:` + `ci-phase7:` 확인 (FOUND)
- [x] `.PHONY` single-line 확장 verified (`PHONY_LINES=1` + co-presence regex)
- [x] `audit-report.md` §SC #5 section + 7 sub-sections + 3 round-trip fenced blocks + `**VERIFIED**` + `umbrella` + `AUDIT-01` + `MTRX-04` literals 모두 확인
- [x] `crates/iso-user-lumen/Cargo.toml` `[package.metadata.cargo-machete]` 6 entries (FOUND)
- [x] `deferred-items.md` D-PHASE7-001 (FOUND)
- [x] Round-trip 3 exit codes (0, 2, 0) audit-report.md 봉인
- [x] `git status --short Cargo.toml Cargo.lock` empty (Issue 6 cleanup verified)
- [x] Task 1 commit `81a9027` exists
- [x] Task 2 commit `ba4a640` exists
- [x] `make check-machete` final exit 0
