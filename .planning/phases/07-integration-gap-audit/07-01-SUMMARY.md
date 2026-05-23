---
phase: 07-integration-gap-audit
plan: 01
subsystem: audit
tags: [triage, dead-code, placeholder, dispatch-reachability, air-gap, four-bucket]

# Dependency graph
requires:
  - phase: 01-capability-backed-hsm-registry
    provides: "Pitfall 13 PATTERNS — flat grep dump → triaged report 회피 절차 (D-01..D-04 적용 입력)"
  - phase: 02-external-bus-driver-abstraction
    provides: "BusVariant + 5-stub variant + 와일드카드 흡수 패턴 (D-04 narrow 정의 입력 사례)"
  - phase: 06-air-gap-dual-enforcement
    provides: "D-07 2-layer self-check (gap_self_check Layer 2-a/2-c panic) — E-15/E-16 G2 justification"
provides:
  - ".planning/audit/audit-report.md 4-bucket triaged report (G1=0, G2=11, G3=1, G4=5; total 17 triaged entries from 16 raw + 1 synthetic)"
  - "Raw Evidence Appendix canonical Markdown-row schema (17 rows, ^\\| E-[0-9]+ regex 충족, triage_status 컬럼 포함)"
  - "G1 키보드 우선순위 (D-03) 명시적 enforcement — 'G1: 적용 항목 없음' empty-state line + 16 rows 사전 검토 narrative"
  - "BusKind::Network closed-vs-tls-external dual-treatment (단일 row + 프로필 컬럼 + closed footnote Plan 03 인계)"
  - "main.rs L50/51/53 cluster note (Warning 10 resolution)"
affects:
  - "Plan 02 (dispatch-reachability.md) — 본 G2/G4 verdict 가 dispatch table 매핑 입력; Plan 02 가 G2/G4 → G3 upgrade 권한 보유"
  - "Plan 03 (air-gap dual-gate zero-bypass proof) — E-17 closed profile footnote 가 nm/objdump 검증 결과 amendment 인계"
  - "Plan 04 (Phase 8~12 re-adjustment authority) — 본 보고서의 bucket count + generated_at_commit 가 quantitative input"
  - "Phase 8~12 — AUDIT-04 재조정 권한 발동 시 본 보고서의 ## Phase 8~12 Re-adjustment Authority section 참조"

# Tech tracking
tech-stack:
  added: []  # audit phase — no new code dependencies
  patterns: ["4-bucket triage canonical schema", "raw-evidence appendix + bucket cross-reference (E-NN id link)", "G1 키보드 우선순위 keyboard-priority gate", "Warning 10 main.rs L50 cluster note convention"]

key-files:
  created:
    - ".planning/audit/ (디렉토리 — sibling of phases/research/debug/quick)"
    - ".planning/audit/audit-report.md (Tasks 1+2 산출, Task 4 가 ## Phase 8~12 Re-adjustment Authority section 채움)"
  modified: []  # production src/ untouched per plan scope

key-decisions:
  - "G1 sites = 0 — v1.0 종료 직후 본체에 알려진 보안/정합성 결함 부재. 명시적 empty-state line 'G1: 적용 항목 없음' 보존 (D-03 keyboard-priority enforcement)"
  - "E-08 hsm_registry NETWORK_ATTACH right bit → G2 (still dead but Phase 6 reserved comment + v2.x reservation intent). 대안 mechanism (NETWORK_CAP_STATE FSM) 채택 사실은 evidence 컬럼에 명시"
  - "E-09 tls parse_handshake_header → G4 (conservative borderline). Task 3 human review 가 G2 upgrade 여부 결정 — write/parse pair 완전성 design intent 가 충분하면 upgrade"
  - "BusKind::Network dual-treatment — Claude's Discretion CONTEXT.md L55-56 결정. 단일 row + 프로필 컬럼 (tls-external) + closed profile footnote (Plan 03 air-gap re-proof 대상) 형식 채택"
  - "verify_automated 의 RAW_COUNT 스코프 over-restrictive — Rule 1 deviation 으로 기록 (acceptance criteria intent 는 per-section awk 으로 충족)"

patterns-established:
  - "Canonical Markdown-row schema (Warning 9): | E-NN | file | lines | pattern | bucket | rule | evidence | (옵션 +profile +triage_status). 동일 schema 가 Raw Evidence Appendix + G1..G4 sections 양쪽에 적용 (cross-reference 가능)"
  - "G1 키보드 우선순위 enforcement narrative pattern: bucket triage 전 G1 자격 site-by-site 평가 + verdict 명시 + empty-state line 또는 SECURITY-REVIEW marker 강제"
  - "Borderline G4 + Task 3 reviewer pending — D-02 evidence 가 borderline 인 항목은 conservative G4 + 'Task 3 review pending' 명시. Reviewer 가 upgrade 권한"

requirements-completed: [AUDIT-01, AUDIT-04]  # Task 3 user-approved as-is, Task 4 inline by orchestrator after checkpoint

# Metrics
duration: ~11min
completed: 2026-05-23
---

# Phase 7 Plan 01: Integration Gap Audit — 4-Bucket Triage Report Summary

**16 raw evidence sites + 1 synthetic G3 entry 를 D-01..D-04 결정 규칙 1:1 적용으로 G1=0/G2=11/G3=1/G4=5 4-bucket 으로 분류한 triaged report 생성 + Phase 8~12 Re-adjustment Authority section 작성 (AUDIT-04 정본 6-step procedure + Quantitative Input + Trigger Conditions + Out-of-scope clarifications + Authority Status tracker). Pitfall 13 'flat grep dump → triaged report' 회피 정신을 canonical row schema (Warning 9 unified) + G1 키보드 우선순위 explicit narrative + BusKind::Network dual-profile treatment 으로 강제.**

> **Task 3 checkpoint 결과: 사용자 approved as-is** (E-09 G4 유지, E-08 G2 유지, BusKind::Network single-row+footnote 형식 유지). Task 4 (Phase 8~12 Re-adjustment Authority section) 는 orchestrator 가 Task 3 승인 직후 inline 실행 (commit 48a6b73).

## Performance

- **Duration:** ~11 min (Tasks 1+2 by executor agent) + inline Task 4 (~3 min by orchestrator after Task 3 approval)
- **Started:** 2026-05-23T11:59:58Z
- **Tasks 1+2 completed:** 2026-05-23T12:11:XXZ (executor)
- **Task 3 checkpoint resolved:** 2026-05-23 (user approved as-is — no verdict changes)
- **Task 4 completed inline:** 2026-05-23 (orchestrator commit 48a6b73)
- **Tasks executed:** 4 of 4 (all tasks complete)
- **Files modified:** 1 (`.planning/audit/audit-report.md`)

## Accomplishments

- **`.planning/audit/` 디렉토리 신규** — sibling of `.planning/{phases,research,debug,quick}`. audit-report.md 가 핵심 산출물.
- **Raw Evidence Appendix 17 rows** (9 dead_code + 5 wildcard + 2 air_gap panic + 1 synthetic G3 named-arm) — `^\| E-[0-9]+` canonical regex 100% 충족, triage_status 컬럼 사후 표기.
- **G1 키보드 우선순위 enforcement (D-03)** — 16 raw sites 사전 평가 narrative + 'G1: 적용 항목 없음 (v1.0 종료 직후 알려진 결함 부재 = v1.0 완료성 확인)' empty-state line.
- **G2 11 entries** (D-01 + D-02→D-01 + D-01+D-04 와일드카드 흡수) — E-04 keystore TRUST_ROOT_PSK_SLOT, E-06/07 main USER_*_ELF (Phase E hook), E-08 hsm_registry NETWORK_ATTACH (Phase 6 reserved), E-10..E-14 bus.rs 5 wildcards (REQUIREMENTS OoS 인용), E-15/E-16 air_gap panic (Phase 6 D-07 fail-stop intent).
- **G3 1 entry** (E-17 BusKind::Network tls-external profile, D-04 narrow) + closed profile footnote (Plan 03 air-gap re-proof 인계).
- **G4 5 entries** (D-02 conservative) — E-01/02/03 idt PIC EOI/IRQ (no IRQ REQ; polling 커널), E-05 vga Color enum (cosmetic 16-색 palette), E-09 tls parse_handshake_header (borderline — Task 3 reviewer 가 G2 upgrade 여부 결정).
- **Cluster notes** — main.rs L50 (docstring 닫는 줄) + L51/53 (#[allow] attribute) 동일 G2 cluster (Warning 10 resolution). bus.rs:351 BusError::NotImplemented 변종 정의 = typed-error stub, evidence row 별도 미생성 (5 wildcard 사용처만 추적).
- **BusKind::Network meta-note** — enum/named arm 양쪽에 unconditionally 등재 (cfg gate 없음), CONTEXT.md D-01 의 "closed 프로필 심볼 부재" 표현과 부분 불일치. 분기는 hsm_registry.rs handle_attach + air_gap.rs gap_self_check 양쪽에 위치 — Plan 03 가 nm/objdump 로 closed 산출 바이너리 차원 재증명.

## Task Commits

각 task 는 atomic 으로 커밋:

1. **Task 1: audit-report.md scaffold + raw evidence enumeration** — `f1ea82e` (docs)
2. **Task 2: D-01..D-04 적용 + G1/G2/G3/G4 4-bucket triage 완료** — `a70ec89` (docs)
3. **Task 3: Human review checkpoint** — *user-approved as-is (no verdict changes); no separate commit*
4. **Task 4: Phase 8~12 Re-adjustment Authority section** — `48a6b73` (docs) — by orchestrator inline after Task 3 approval

**Plan metadata commit:** (본 SUMMARY.md 의 commit hash — final commit 후 기록)

## Files Created/Modified

- **Created:** `.planning/audit/audit-report.md` — 4-bucket triaged report scaffold + populated G1/G2/G3/G4 sections + Raw Evidence Appendix (17 rows with triage_status). `## Phase 8~12 Re-adjustment Authority` section 은 header 만 (Task 4 에서 채움).
- **Created:** `.planning/audit/` 디렉토리.
- **Created (by this commit):** `.planning/phases/07-integration-gap-audit/07-01-SUMMARY.md` (본 파일).
- **NOT modified:** `src/**/*.rs` — Plan 01 의 scope 외 (audit-only phase per ROADMAP §Phase 7).

## Decisions Made

위 frontmatter `key-decisions` 의 5 결정을 narrative 로 기록:

1. **G1 = 0 verdict** — 16 raw sites 전수 검토 결과 보안/정합성 결함 부재. v1.0 완료성의 일차 지표. 빈 G1 section 누락은 audit 불완전성으로 오독될 수 있으므로 명시적 empty-state line 보존 (CONTEXT.md §specifics 2번째 항목 준수).

2. **E-08 NETWORK_ATTACH right bit → G2** — `pub const NETWORK_ATTACH: Self = Self(1 << 5)` 의 line comment "Phase 6 reserved" 가 documented future-purpose mapping 자격 (D-01) 으로 인정. Phase 6 실제 구현이 alternative mechanism (NETWORK_CAP_STATE FSM + NETWORK_ATTACH_CAP BSS singleton) 을 채택해 right-bit 슬롯 자체는 redundant 가 됐으나, v2.x 가 right-bit 기반 fallback / cross-check 용도로 활용할 가능성을 evidence 컬럼에 명시. (Conservative alternative: G4 with note "replaced by NETWORK_CAP_STATE" — 본 plan 은 lenient G2 채택.)

3. **E-09 parse_handshake_header → G4 (borderline)** — write_handshake_header 의 reader pair 가 design intent 라고 추정 가능하지만, 명시적 REQ / OoS 매핑 부재. Conservative G4 + Task 3 reviewer 가 G2 upgrade 여부 최종 결정 (acceptance criteria 의 "최소 한 sites borderline + reviewer 결정" 만족).

4. **BusKind::Network dual-treatment 형식** — CONTEXT.md L55-56 Claude's Discretion 3 형식 후보 (단일 row + 프로필 컬럼 / 분리 entry / 각주) 중 **단일 row + 프로필 컬럼 + 별도 footnote** 형식 채택. 이유: (a) E-17 single row 가 visual scan 시 BusKind::Network 의 G3 verdict 를 한 줄에 응집 (b) 프로필 컬럼이 tls-external 한정 사실 명시 (c) 별도 footnote 가 closed 프로필 Plan 03 인계 사실 분리. 분리 entry 는 visual fragmentation, 각주만은 G3 단정 시 가시성 부족 — 단일 row + footnote 가 두 약점 모두 회피.

5. **verify_automated RAW_COUNT 결함 발견 + Rule 1 deviation 기록** — verify script 의 `RAW_COUNT=$(grep -cE '^\| E-[0-9]+' $AR)` 는 appendix + bucket sections 양쪽의 E-NN 행을 모두 카운트하므로, canonical schema (Warning 9 unified row format) 가 정확히 적용된 상태에서 TRIAGED_COUNT >= RAW_COUNT 가 수학적으로 불가능. acceptance criteria 의 awk 기반 per-section count (TRIAGED_COUNT >= APPENDIX_COUNT - DROPPED_COUNT) 가 실제 intent 충족 — 본 plan 은 acceptance intent 를 우선 적용.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] verify_automated RAW_COUNT 스코프 over-restrictive**
- **Found during:** Task 2 acceptance verification
- **Issue:** PLAN.md Task 2 의 `<verify><automated>` 안의 `RAW_COUNT=$(grep -cE '^\| E-[0-9]+' $AR)` 는 파일 전체의 E-NN 행을 카운트하므로 appendix (17 rows) + buckets (17 rows) = 34 rows. `TRIAGED_COUNT` (bucket scope, 17 rows) 와 비교 시 `TRIAGED_COUNT >= RAW_COUNT` (17 >= 34) 가 항상 실패. canonical schema (Warning 9 명시: "BOTH Raw Evidence Appendix AND G1..G4 sections" 동일 `^\| E-[0-9]+` 사용) 와 verify script 가 수학적으로 모순.
- **Fix:** acceptance criteria 의 진정한 intent ("Every raw evidence row has a corresponding triaged entry under exactly one of G1..G4 OR dropped") 을 충족하는 awk per-section count 로 검증 (TRIAGED_COUNT=17 >= APPENDIX_COUNT-DROPPED=17). audit-report.md 자체는 acceptance 의 9 individual criteria 모두 PASS. PLAN.md verify script 의 RAW_COUNT 정의 수정은 본 plan 의 scope 외 (PLAN.md 는 본 plan 의 입력 artifact, 수정 시 retroactive plan 변경 위험).
- **Files modified:** none (audit-report.md 는 canonical schema 그대로 유지; verify script 의 결함 우회만 수행)
- **Verification:** acceptance criteria 9 개 모두 PASS (G1 marker / D-rule 인용 / BusVariant::Usb G2 / BusKind::Network G3 tls-external / air_gap.rs:178/191 G2 D-07 / canonical schema / E-08 still-dead G2)
- **Committed in:** part of Task 2 commit `a70ec89` (audit-report.md 자체에 영향 없음)

**2. [Rule 1 - Documentation correction] CONTEXT.md D-01 의 "BusKind::Network closed profile 심볼 부재" 표현 vs 실제 코드 불일치**
- **Found during:** Task 2 raw evidence + dispatch context analysis
- **Issue:** CONTEXT.md L29 "BusVariant::Network 는 Phase 6 `tls-external` cfg-gate 로 closed 빌드에서 심볼 부재" — 실제 `src/bus.rs:341` (`BusKind::Network = 6`) 및 L845 (`BusKind::Network => Self::Network`) 는 `#[cfg(feature = "tls-external")]` 게이트 없이 unconditionally 등재. closed 빌드에도 enum variant + named arm 심볼은 존재. 분기는 (a) `src/hsm_registry.rs:557-587` handle_attach Network arm (b) `src/air_gap.rs:172-185` gap_self_check Layer 2-a/2-b 에 위치.
- **Fix:** audit-report.md Raw Evidence Appendix 의 Meta-notes 섹션에 명시 — "BusKind::Network 변종 자체는 unconditionally 등재. closed-vs-tls-external 분기는 handle_attach + gap_self_check 양쪽에 위치". E-17 G3 entry 는 tls-external profile 만 verdict 적용. closed 프로필은 footnote 로 Plan 03 air-gap re-proof 인계.
- **Files modified:** `.planning/audit/audit-report.md` (Raw Evidence Appendix Meta-notes + G3 closed profile footnote)
- **Verification:** grep `tls-external` src/bus.rs 결과 0 (BusKind::Network 위치에 cfg 없음 확인); E-17 verdict 가 tls-external 한정 명시
- **Committed in:** part of Task 2 commit `a70ec89`

---

**Total deviations:** 2 auto-fixed (1 verify script bug workaround, 1 plan documentation correction)
**Impact on plan:** verify_automated 결함은 plan 의 acceptance intent 와 무관 (intent-correct verification 통과). CONTEXT.md 표현 정정은 Plan 03 의 air-gap 재증명 입력 정확성을 위해 필수 (closed-vs-tls-external 분기 mechanism 정확 식별).

## Issues Encountered

- **`.planning/` 가 `.gitignore` 에 등재됨** — `git add -f` 로 force-stage 필요. 본 worktree 의 `.planning/` 디렉토리는 main 리포의 `.planning/` 와 별개로 worktree 초기화 직후 부재 (worktree base commit `39d4c72` 에 `.planning/` 부재). Task 1 시작 시 `.planning/audit/` + `.planning/phases/07-integration-gap-audit/` 디렉토리 신규 생성. 모든 commit 은 `git add -f` 로 진행.
- **Worktree base reset (`39d4c72fa49...` 시점)** — `<worktree_branch_check>` 의 base 식별이 `7fec82fbca4...` (Multi-HSM v1.0 milestone merge) 였으나 force-reset 으로 `39d4c72` 로 정렬. enumeration grep 은 본 reset 후 작업 디렉토리 기준 (`src/*.rs` 30 files, 14583 lines) 으로 실행.
- **BusVariant vs BusKind 명명 불일치** — 코드는 `BusKind` (enum) + `BusInstance` (dispatch enum), CONTEXT.md / PLAN.md 는 "BusVariant" 로 표기. 본 보고서는 *코드의 실제 식별자* 를 사용 (BusKind / BusInstance) — 향후 reader 가 grep 으로 확인 가능. plan 의 "BusVariant" 표현은 BusKind 의 별칭으로 해석.

## User Setup Required

None — Phase 7 은 audit-only phase, 외부 서비스 / 환경변수 / dashboard 설정 없음.

## Next Phase Readiness

**Ready for Task 3 checkpoint review:**
- `.planning/audit/audit-report.md` 의 G2 vs G4 borderline 항목들 (특히 E-09 tls parse_handshake_header) 의 verdict 확인
- G1 section 의 empty-state line 적정성 확인 (silent downgrade 부재)
- BusKind::Network dual-treatment 형식 (단일 row + 프로필 컬럼 + footnote) 의 적정성 확인
- D-02 entries 의 G2 evidence 충분성 확인 (특히 E-08 NETWORK_ATTACH 의 "Phase 6 reserved" 코멘트가 G2 자격 충분한지)

**Deferred to Task 4 (post-checkpoint continuation):**
- `## Phase 8~12 Re-adjustment Authority` section 채움 (Trigger Conditions / Quantitative Input / Procedure / Out-of-scope clarifications + Authority Status tracker)
- Quantitative Input 의 bucket count 4-tuple (G1=0, G2=11, G3=1, G4=5) + generated_at_commit `39d4c72` + raw=17/dropped=0 인용
- 6-step procedure 정본 (AUDIT-04 verbatim trigger condition "ROADMAP.md 수정 + decision log 추가" 인용)

**For Plan 02 (dispatch-reachability.md):**
- 본 Task 2 의 G2/G4 verdict 는 visible-proximity preliminary — Plan 02 가 syscall.rs / WireCmd / IPC / IDT 4 dispatch 축 전수 매핑 후 G2/G4 → G3 upgrade 권한 보유 (특히 E-01..E-03 idt PIC handlers 와 E-09 parse_handshake_header 가 후보)

**For Plan 03 (air-gap dual-gate zero-bypass proof):**
- E-17 closed profile footnote 가 Plan 03 의 nm/objdump 재증명 결과 amendment 인계점 — `BusKind::Network` 구현체 심볼 + `NETWORK_ATTACH` capability 발급 경로의 closed 산출 바이너리 부재 검증 결과를 audit-report.md 에 사후 기록

**For Plan 04 (Phase 8~12 Re-adjustment Authority — Task 4):**
- 본 보고서의 bucket count + generated_at_commit + raw evidence count 가 Quantitative Input 의 정량 근거

## Self-Check

```bash
[ -f .planning/audit/audit-report.md ] && echo "FOUND" || echo "MISSING"
# FOUND
git log --oneline | grep -q f1ea82e && echo "FOUND f1ea82e" || echo "MISSING f1ea82e"
# FOUND f1ea82e
git log --oneline | grep -q a70ec89 && echo "FOUND a70ec89" || echo "MISSING a70ec89"
# FOUND a70ec89
grep -c '^## G[1-4]' .planning/audit/audit-report.md
# 4
grep -cE '^\| E-[0-9]+' .planning/audit/audit-report.md
# 34 (17 appendix + 17 bucket — canonical schema Warning 9)
awk '/^## G[1-4]/{flag=1;next} /^## /{flag=0} flag && /^\| E-[0-9]+/{c++} END{print c+0}' .planning/audit/audit-report.md
# 17 triaged
awk '/^## Raw Evidence Appendix/{flag=1;next} /^## /{flag=0} flag && /^\| E-[0-9]+/{c++} END{print c+0}' .planning/audit/audit-report.md
# 17 appendix
```

## Self-Check: PASSED

audit-report.md 존재 확인, 3 task commits 확인 (f1ea82e + a70ec89 + 48a6b73), 4-bucket header 4개 확인, canonical row 17 triaged + 17 appendix 확인, G1 empty-state line 확인, Phase 8~12 Re-adjustment Authority section 의 7 acceptance criteria 모두 PASS (4 headers + AUDIT-04 citation + 4 bucket counts + Authority Status tracker + 6 procedure steps + 사용자 합의 in Step 2 + verbatim AUDIT-04 trigger text + frontmatter SHA match).

---

*Phase: 07-integration-gap-audit*
*Plan: 01*
*Completed: 2026-05-23 (Tasks 1+2 by executor agent + Task 3 user-approved + Task 4 by orchestrator inline)*
