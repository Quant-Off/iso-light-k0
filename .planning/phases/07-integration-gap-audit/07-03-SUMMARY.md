---
phase: 07-integration-gap-audit
plan: 03
subsystem: audit
tags: [air-gap, dual-gate, closed-profile, nm, objdump, demangle, reproof, AUDIT-03, issue-5]

# Dependency graph
requires:
  - phase: 06-air-gap-dual-enforcement
    provides: "scripts/check-no-network.sh (5-pattern CI standing gate prior art) + D-07 2-layer self-check + NETWORK_ATTACH_CAP / NETWORK_CAP_STATE FSM BSS singletons"
  - phase: 01-capability-backed-hsm-registry
    provides: "scripts/check-no-alloc.sh (objdump → gobjdump → nm --demangle fallback chain pattern)"
  - phase: 07-integration-gap-audit (Plan 01)
    provides: ".planning/audit/audit-report.md + E-17 closed-profile footnote (Plan 03 destination handoff)"
provides:
  - "scripts/audit-no-network-rel.sh — Phase 7 AUDIT-03 audit-time 1회 재증명 wrapper (Phase 6 CI standing gate 와 file-system level 분리)"
  - ".planning/audit/airgap-reproof.log — closed-profile 산출 바이너리 VERDICT PASS evidence (commit SHA + KERNEL_BIN_SHA256 봉인)"
  - "audit-report.md `## AUDIT-03 Air-Gap Dual-Gate Re-Proof` section (Scope/Method/Pattern Universe (7)/Result/Relation/Cross-reference 6 sub-section)"
  - "Issue 5 해소 — fallback chain 모든 분기 -C/--demangle 강제 (objdump / gobjdump / nm 3 분기, 실제 ≥4 grep 히트)"
  - "7-pattern universe — Phase 6 5 패턴 (NETWORK_ATTACH_CAP, NETWORK_CAP_STATE, init_network_cap, take_network_cap, air_gap..network) + Plan 03 2 패턴 (handle_attach.*Network, gen_token_u64.*air_gap)"
affects:
  - "Phase 8 ENTR 및 후속 phases — AUDIT-03 PASS 가 v2.0 진입 전제 (audit-report.md 봉인)"
  - "Phase 6 D-07 Layer 1 — 본 plan 이 demangle-on-all-branches 강화 사례로 reference 됨 (audit-report.md Relation section)"
  - "Plan 01 E-17 closed profile footnote — Plan 03 §AUDIT-03 section 이 destination"

# Tech tracking
tech-stack:
  added: []  # audit phase no new code dependencies
  patterns:
    - "audit-time vs CI standing 분리 — 동일 dual-gate 검증을 두 표면 (CI fast-fail 5 패턴 vs audit-time evidence-log 7 패턴 + commit pinning) 으로 책임 분리"
    - "Demangle-on-all-branches enforcement — fallback chain 의 모든 dump-tool 분기에서 -C/--demangle 강제 (mangled-symbol false-positive PASS 차단)"
    - "Evidence-log frontmatter schema — PHASE / GENERATED_AT / COMMIT / BUILD_CMD / BUILD_EXIT / DUMP_TOOL / KERNEL_BIN / KERNEL_BIN_SIZE / KERNEL_BIN_SHA256 / PATTERNS_SEARCHED / PATTERNS_MATCHED / per-pattern detail / VERDICT"

key-files:
  created:
    - "scripts/audit-no-network-rel.sh (audit-time 재증명 wrapper, chmod 0755, set -euo pipefail)"
    - ".planning/audit/airgap-reproof.log (evidence — VERDICT PASS, COMMIT ee29a00, SHA256 85c6931, DUMP_TOOL `objdump -C --syms`)"
  modified:
    - ".planning/audit/audit-report.md (`## AUDIT-03 Air-Gap Dual-Gate Re-Proof` section 추가, +33 lines)"

key-decisions:
  - "Discretion 해소 — CONTEXT.md §Air-gap 재증명의 audit-time vs CI standing 분리 결정 채택. scripts/audit-no-network-rel.sh (audit-time) 가 scripts/check-no-network.sh (CI standing) 와 file-system level 로 분리. 두 표면의 책임 혼동 방지."
  - "Issue 5 (checker iteration 1) 해소 — Phase 6 prior art 는 nm 분기만 --demangle, objdump/gobjdump 분기는 mangled 출력. 본 plan 은 -C 를 objdump/gobjdump 분기에도 추가 → fallback chain 모든 분기에서 demangle 강제. 패턴 `air_gap..network` 가 demangled `air_gap::network::*` form 만 매치하므로 mangled 심볼 false-positive PASS 차단 (AUDIT-03 중앙 보안 게이트 soundness)."
  - "7-pattern universe — Phase 6 5 패턴 mirror + 2 패턴 추가. 추가 패턴 (handle_attach.*Network = D-01 dispatch 본문, gen_token_u64.*air_gap = CAP_DRBG ↔ air_gap 호출 경계) 은 NETWORK_ATTACH 발급 경로 defense-in-depth — init_network_cap 패턴 누락 시에도 gen_token_u64 caller boundary 가 보안 게이트."
  - "Per-pattern grep 카운트 + matched-symbol 상세 (FAIL 시) — log 에 `[1]..[7]` 각 패턴별 hits 수 + FAIL 분기에서는 매치된 심볼 라인을 별도 blocking diagnostic section 으로 emit. PASS path 에서는 diagnostic section 미생성."
  - "DUMP_OUTPUT 1회 캐시 — 7 패턴 검사를 위해 `$DUMP_CMD \"$KERNEL_BIN\"` 을 1회만 실행 후 변수 캐시. 반복 호출 비용 절감 + 동일 단일 출력 스냅샷에 대한 정합성 보장."

patterns-established:
  - "Audit-time wrapper script convention — `scripts/audit-*.sh` 명명으로 CI gate (`scripts/check-*.sh`) 와 명시 분리. 본 plan 이 첫 적용 사례."
  - "Evidence-log pinning schema — COMMIT (git rev-parse HEAD) + KERNEL_BIN_SHA256 (sha256sum/shasum -a 256) 양쪽 봉인. 재현자는 동일 commit 에서 byte-identical 바이너리 재빌드 후 verdict 재확인 가능."
  - "Demangle-on-all-branches convention — 어떤 패턴이라도 demangled-only form 을 포함하면 fallback chain 의 모든 분기에서 -C/--demangle 강제. 본 plan 이 사례 1; Phase 6 D-07 Layer 1 (check-no-network.sh) 는 legacy 보존."
  - "Acceptance criterion as guard — `grep -E '(objdump|nm).*(-C|--demangle)' scripts/audit-no-network-rel.sh | wc -l ≥ 3` 가 향후 회귀 방지 가드 (스크립트가 다시 demangle 없는 분기로 회귀하면 verify 실패)."

requirements-completed: [AUDIT-03]

# Metrics
duration: ~4 min
completed: 2026-05-23
---

# Phase 7 Plan 03: Air-Gap Dual-Gate Re-Proof Summary

**Phase 6 air-gap dual-gate (build-time `tls-external` cfg + runtime NETWORK_ATTACH capability) 가 v2.0 진입 시점 closed-profile 산출 바이너리 (`target/x86_64-unknown-none/release/iso-light-k0`, 208,864 bytes, SHA-256 `85c6931c…`) 에서도 zero-bypass 임을 7-pattern demangled-symbol search 로 audit 시점 1회 재증명 (VERDICT PASS, commit ee29a00).**

## Performance

- **Duration:** ~4 min (build + run + evidence emit + audit-report.md edit)
- **Started:** 2026-05-23T12:34Z
- **Completed:** 2026-05-23T12:38Z
- **Tasks:** 2
- **Files modified:** 3 (2 created: `scripts/audit-no-network-rel.sh`, `.planning/audit/airgap-reproof.log`; 1 edited: `.planning/audit/audit-report.md`)

## Accomplishments

- **AUDIT-03 PASS** — closed-profile 산출 바이너리에서 7 패턴 모두 0 hits 확인. Phase 6 dual-gate 가 v2.0 진입 시점에서도 zero-bypass.
- **Issue 5 해소** — fallback chain 모든 분기 (objdump / gobjdump / nm) 에서 `-C` / `--demangle` 강제. 패턴 `air_gap..network` 의 mangled-symbol false-positive PASS 위험 차단. Acceptance grep 카운트 4 hits (≥3 요건).
- **Audit-time vs CI standing 분리** — `scripts/audit-no-network-rel.sh` (audit-time 1회) 가 `scripts/check-no-network.sh` (Phase 6 CI 영구 게이트) 와 file-system level 로 분리. Phase 6 prior art 는 unchanged.
- **Evidence pinning** — `.planning/audit/airgap-reproof.log` 에 COMMIT (`ee29a00e8b8605229f98ef76f12b14b42119d4c8`) + KERNEL_BIN_SHA256 (`85c6931cfad20a203073551bec635fff1446270d8aa6d04e934b83647af2738c`) + DUMP_TOOL (`objdump -C --syms`) 봉인. 재현자가 동일 commit 에서 byte-identical 재빌드 후 verdict 재확인 가능.
- **Plan 01 E-17 footnote destination** — audit-report.md `## AUDIT-03 Air-Gap Dual-Gate Re-Proof` section 이 Plan 01 Task 2 의 `BusVariant::Network closed profile entry` "symbol absent — see Plan 03 air-gap re-proof" footnote 의 destination.

## Task Commits

Each task was committed atomically:

1. **Task 1: Create audit-no-network-rel.sh + execute closed-profile re-proof** — `55b89bc` (docs)
2. **Task 2: Add §AUDIT-03 section to audit-report.md** — `facd00b` (docs)

## Files Created/Modified

- `scripts/audit-no-network-rel.sh` — 신규 audit-time wrapper. set -euo pipefail, 7 EXPECTED_ABSENT 패턴, fallback chain 모든 분기 demangle 강제, evidence-log emit, exit 0 (PASS) / exit 1 (FAIL).
- `.planning/audit/airgap-reproof.log` — 신규 evidence. PHASE/GENERATED_AT/COMMIT/BUILD_CMD/BUILD_EXIT/DUMP_TOOL/KERNEL_BIN/KERNEL_BIN_SIZE/KERNEL_BIN_SHA256/PATTERNS_SEARCHED/PATTERNS_MATCHED/per-pattern detail/VERDICT 12 frontmatter keys + 7 numbered per-pattern lines.
- `.planning/audit/audit-report.md` — `## AUDIT-03 Air-Gap Dual-Gate Re-Proof` section 추가 (+33 lines). 6 sub-section: Scope / Method / Pattern Universe (7) / Result / Relation to Phase 6 CI standing gate / Audit cross-reference.

## Decisions Made

- **Audit-time vs CI standing 책임 분리** — Plan 03 신규 wrapper 가 `scripts/audit-*.sh` 명명 convention 적용. CI gate 는 unchanged.
- **Demangle-on-all-branches** — Issue 5 resolution. objdump/gobjdump 분기에 `-C` 추가, nm 은 기존 `--demangle` 유지. acceptance grep 가드로 회귀 방지.
- **DUMP_OUTPUT 1회 캐시** — 7 패턴 검사를 위해 `$DUMP_CMD "$KERNEL_BIN"` 을 1회만 실행 후 변수에 저장. 반복 호출 비용 절감 + 단일 출력 스냅샷 정합성.
- **FAIL diagnostic 분리** — PASS path 에서는 evidence-log 가 12 frontmatter + 7 per-pattern + VERDICT 만 emit. FAIL 분기에서만 매치된 심볼 라인을 별도 blocking diagnostic section 으로 추가 (PASS log noise 0).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] elib-k0-nt sibling 디렉토리 worktree 상에서 누락**
- **Found during:** Task 1 (script 첫 실행 시 cargo build 실패)
- **Issue:** Cargo.toml 이 `../elib-k0-nt/*` 상대경로로 13개 elib crate 를 참조. Worktree 위치 `.claude/worktrees/agent-a2fd83634bf212977/` 의 `..` 은 `.claude/worktrees/` 인데, 실제 elib-k0-nt 는 `/Library/Quant/code-projects/elib-k0-nt/` (iso-light-k0 의 sibling) 에 위치. 따라서 worktree 에서는 `../elib-k0-nt` 가 해소되지 않아 `failed to load source for dependency aes` 빌드 실패.
- **Fix:** `/Library/Quant/code-projects/iso-light-k0/.claude/worktrees/elib-k0-nt` symlink 를 실제 sibling 디렉토리로 생성 (`ln -s /Library/Quant/code-projects/elib-k0-nt ...`). 환경 fix only, source 미수정. Worktree 외부 (parent worktrees 디렉토리) 의 환경 fix 이므로 git index 영향 없음.
- **Files modified:** 없음 (워크트리 외부 symlink, git tracked 아님)
- **Verification:** `cargo build --release --target x86_64-unknown-none` 재실행 4.54s 성공, audit script PASS.
- **Committed in:** N/A (환경 fix, 코드 변경 아님)

---

**Total deviations:** 1 auto-fixed (1 blocking - worktree environment)
**Impact on plan:** Plan 외 활동 0. Source code / scripts / audit artifacts 모두 plan 명세대로 산출. Worktree-only 환경 이슈로 main repo / CI 환경에서는 발생 자체가 불가능 (sibling elib-k0-nt 가 직접 존재).

## Issues Encountered

- **Worktree relative-path dependency 해석** — Cargo `../elib-k0-nt` 가 worktree 위치에서 해소되지 않음. Symlink 로 즉시 해소. 본 이슈는 Phase 7 plan 03 의 책임 아니라 worktree 인프라 이슈이므로 별도 deferred-items 등록 불요 (main repo / CI 에서 영향 0).

## Acceptance Criteria Verification

- [x] `test -x scripts/audit-no-network-rel.sh` — PASS
- [x] `grep -E '(objdump|nm).*(-C|--demangle)' scripts/audit-no-network-rel.sh | wc -l` = 4 (≥ 3 — Issue 5 가드)
- [x] `bash scripts/audit-no-network-rel.sh` exits 0 — PASS
- [x] `.planning/audit/airgap-reproof.log` 12 frontmatter keys 모두 존재 (PHASE/GENERATED_AT/COMMIT/BUILD_CMD/BUILD_EXIT/DUMP_TOOL/KERNEL_BIN/KERNEL_BIN_SIZE/KERNEL_BIN_SHA256/PATTERNS_SEARCHED/PATTERNS_MATCHED/VERDICT)
- [x] `DUMP_TOOL: objdump -C --syms` (demangle flag 포함)
- [x] `VERDICT: PASS`
- [x] `PATTERNS_SEARCHED: 7`, `PATTERNS_MATCHED: 0`
- [x] `COMMIT: ee29a00e8b8605229f98ef76f12b14b42119d4c8` (40-char hex)
- [x] 7 per-pattern lines `[1]..[7]` 모두 `0 hits`
- [x] audit-report.md `## AUDIT-03 Air-Gap Dual-Gate Re-Proof` section + 6 sub-section + 7-pattern enumeration + cross-reference 텍스트 모두 포함
- [x] `git status --short scripts/check-no-network.sh` empty (Phase 6 CI gate unchanged)
- [x] G1 escalation 미발생 (VERDICT PASS — `## G1` section 변경 없음)

## User Setup Required

None — audit-time script 는 main repo / CI 환경에서 직접 실행 가능 (sibling `../elib-k0-nt` 가 정상 존재하는 환경 기준). 본 plan 의 worktree 환경 fix 는 부수적, 산출물 자체에는 영향 없음.

## Next Phase Readiness

- AUDIT-03 PASS 봉인 — Phase 8 ENTR 진입 전제 충족.
- Plan 01 E-17 closed-profile footnote 의 destination 완성 — Plan 02 dispatch-reachability G3 single-entry verdict 와 정합 유지 (BusVariant::Network closed 프로필 심볼 부재로 dispatch entry 도달 자체 불가).
- Phase 7 Plan 04 (Phase 8~12 re-adjustment authority) 는 본 plan 의 산출물에 비의존 — bucket counts (G1=0, G2=11, G3=1, G4=5) 는 Plan 01/02 결정사항 유지.

## Self-Check: PASSED

- FOUND: scripts/audit-no-network-rel.sh
- FOUND: .planning/audit/airgap-reproof.log
- FOUND: .planning/audit/audit-report.md
- FOUND: .planning/phases/07-integration-gap-audit/07-03-SUMMARY.md
- FOUND commit 55b89bc (Task 1)
- FOUND commit facd00b (Task 2)

---
*Phase: 07-integration-gap-audit*
*Plan: 03*
*Completed: 2026-05-23*
