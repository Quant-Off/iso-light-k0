---
phase: 07-integration-gap-audit
plan: 02
subsystem: audit
tags: [dispatch-reachability, syscall, wirecmd, ipc, idt, orphan-handler, audit, no_std]

# Dependency graph
requires:
  - phase: 07-integration-gap-audit (Plan 01)
    provides: ".planning/audit/audit-report.md (17 raw evidence rows E-01..E-17 + preliminary G1/G2/G3/G4 verdicts)"
provides:
  - "docs/dispatch-reachability.md (4 dispatch 축 합집합 unbounded trace 17 사이트 매핑)"
  - "orphan_handler_count = 2, orphan_dispatch_entry_count = 0 quantitative gate"
  - "audit-report.md Triage Revision Log (no revisions - Plan 01 verdicts upheld)"
affects: [07-03-plan, 07-04-plan, 08-entr, 09-hal, 10-arm, 12-mtrx]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "4-axis dispatch reachability mapping (syscall ∪ WireCmd ∪ IPC ∪ IDT) for kernel placeholder triage"
    - "Unbounded reverse-call trace with visited-set cycle detection (Issue 2 Option A)"
    - "Cross-file E-NN identifier convention for raw-evidence ↔ dispatch-mapping linkage"

key-files:
  created:
    - "docs/dispatch-reachability.md"
  modified:
    - ".planning/audit/audit-report.md (Triage Revision Log section appended)"

key-decisions:
  - "G3 dispatch surface scope = 4-axis union (not intersection) — rationale: D-04 narrow definition requires only one named entry, union avoids syscall-only false negatives"
  - "Tracing depth = unbounded (Issue 2 Option A) — 13K LOC × bounded in-src callers makes exhaustive traversal feasible; no `unreached-within-N-hops` bucket"
  - "Tool choice = manual rg + Markdown — 1회 audit cost-benefit defers cargo-call-stack to v2.1"
  - "audit-report.md back-edit not required — Plan 01 G3 verdict (E-17 BusKind::Network tls-external) confirmed by authoritative Plan 02 dispatch knowledge"

patterns-established:
  - "Dispatch axis enumeration template: per-axis sub-section with grep extraction + match arm → resolves-to table"
  - "Orphan classification trichotomy: orphan-handler (caller absent) / orphan-entry (symbol absent — Rust compiler prevents) / data-only (const/enum N/A)"
  - "Cross-file SHA pin (audit_source: ...@<sha>) for audit↔mapping drift detection"

requirements-completed: [AUDIT-02]

# Metrics
duration: ~30min
completed: 2026-05-23
---

# Phase 7 Plan 02: 4-Axis Dispatch Reachability Mapping Summary

**17 placeholder 사이트 (E-01..E-17) 의 syscall ∪ WireCmd ∪ IPC ∪ IDT 4 dispatch 축 unbounded trace 매핑 — orphan_handler_count=2 / orphan_dispatch_entry_count=0 PASS gate 충족, G3 verdict back-edit 불필요 (Plan 01 verdicts upheld)**

## Performance

- **Duration:** ~30분
- **Started:** 2026-05-23T12:00Z (approx)
- **Completed:** 2026-05-23T12:28Z
- **Tasks:** 2/2 (모두 autonomous)
- **Files modified:** 2 (docs/dispatch-reachability.md 신규, .planning/audit/audit-report.md 추가 섹션)

## Accomplishments

- **`docs/dispatch-reachability.md` 신규 생성** — 4 dispatch 축 (Ring 3 syscall / WireCmd / IPC / IDT) 의 명시 enumeration + 17 사이트 (E-01..E-17) 전수 매핑 + orphan 분석 + 방법론 노트를 포함하는 self-contained AUDIT-02 산출물.
- **SC #2 PASS gate 충족** — `orphan_dispatch_entry_count = 0` (모든 dispatch arm 이 정의된 심볼로 resolve; Rust 컴파일러 보강); `orphan_handler_count = 2` (E-03 `enable_irq`, E-09 `parse_handshake_header` — 양 사이트 모두 audit-report.md 의 G4 truly-dead verdict 와 정합).
- **G3 verdict cross-check 완료** — 단일 G3 entry (E-17 BusKind::Network tls-external profile) 가 dispatch-reachability.md 매핑 (axis=syscall, dispatch entry=named arm, orphan?=no) 과 일치 → audit-report.md back-edit 불필요.
- **audit-report.md `## Triage Revision Log` 신규 섹션 추가** — literal "No revisions: Plan 01 verdicts upheld" 명시 (Issue 3 resolution per plan acceptance criteria).
- **Discretion 해소 기록** — Methodology 섹션에 4-axis union 선택, manual rg 도구 선택, unbounded tracing 선택 의 결정 근거를 명시.

## Task Commits

각 task 가 원자적으로 commit 됨:

1. **Task 1: 4 dispatch 축 enumeration + 사이트별 매핑 (unbounded tracing)** — `e0cbb0d` (docs)
2. **Task 2: zero-orphan gate enforcement + audit-report.md back-edit** — `dde8882` (docs)

**Plan metadata:** (SUMMARY.md commit will follow this section)

## Files Created/Modified

- `docs/dispatch-reachability.md` (신규) — 4 dispatch 축 명시 enumeration + 17 사이트 매핑 + orphan 분석 (`orphan_handler_count=2`, `orphan_dispatch_entry_count=0`) + SC #2 PASS gate + Methodology (union / manual rg / unbounded).
- `.planning/audit/audit-report.md` (수정 +8 lines) — `## Triage Revision Log` 섹션 추가, literal "No revisions: Plan 01 verdicts upheld" 포함, bucket counts 동일 유지 명시.

## Decisions Made

본 plan 의 4 Claude's Discretion 해소 결정 (모두 `07-02-PLAN.md` <objective> 에 사전 기록된 결정의 실행 확인):

1. **G3 표면 범위 = 4 dispatch 축 합집합** (intersection 아님). 근거: D-04 narrow 정의가 "어느 한 dispatch table 의 named entry" 면 충족이므로 union 이 자연스러움; intersection 은 syscall-only stub (E-17 같은 사례) 의 false negative 위험.

2. **Tracing 깊이 = unbounded** (Issue 2 Option A). 근거: 13K LOC × 평균 in-src caller ~5 → 완전 추적 비용 bounded; 깊이 캡은 깊은 호출 경로의 진정 reachable G3 후보를 `unreached-within-N-hops` 로 false-negative 강등 위험. 실제 매핑 결과 최대 추적 깊이 = 2 (모든 placeholder 가 dispatch axis 의 직접 또는 1-hop 안쪽).

3. **도구 선택 = manual rg + Markdown table**. 근거: 13K LOC 단발 audit, 4 축 모두 grep-friendly. `cargo-call-stack` / rust-analyzer 도입 비용 > 본 audit 의 가시성 산출 가치. v2.1 자동화 이월 (CONTEXT.md §deferred).

4. **G3 verdict back-edit 불필요**. 근거: 단일 G3 entry (E-17) 가 dispatch-reachability 매핑과 정합; 다른 어느 사이트도 D-04 narrow 정의 (named dispatch entry + stub body) 추가 충족하지 않음 (E-10..E-14 wildcard 흡수 명시 배제, E-15/E-16 boot init 의도 fail-stop, E-01/E-02 IDT 벡터 reachable 이나 본문 정상, E-03/E-09 orphan-handler).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Task 1 verify gate counter scope correction**

- **Found during:** Task 1 (post-creation verification)
- **Issue:** Plan 02 Task 1 `<automated>` verify counts `EVIDENCE_ROWS=$(grep -cE '^\| E-[0-9]+' .planning/audit/audit-report.md)` which returns **34** (E-NN rows duplicated across G2/G3/G4 sections + Raw Evidence Appendix in audit-report.md). The acceptance criteria prose ("`## Site → Dispatch Mapping` table row count ≥ `## Raw Evidence Appendix` row count in audit-report.md") specifies appendix-scoped counting (17 rows). The bash gate's regex doesn't match the prose intent.
- **Fix:** Re-verified using appendix-scoped awk extraction matching the acceptance prose: `EVIDENCE_ROWS=$(awk '/^## Raw Evidence Appendix/{flag=1;next} /^## /{flag=0} flag && /^\| E-[0-9]+/{c++} END{print c}' .planning/audit/audit-report.md)` → returns 17. Site mapping has 17 unique E-NN rows → ≥ 17 → PASS per acceptance prose. The plan's bash verify counter is itself a Plan 02 spec bug (counts duplicates), not a content gap — content satisfies the acceptance criterion.
- **Files modified:** None (verify-only scoping; no doc changes needed since each E-NN appears once in `docs/dispatch-reachability.md` Site → Dispatch Mapping table, matching the 17 unique appendix rows).
- **Verification:** Appendix-scoped count 17 == Site rows 17. All other plan `<verification>` gates pass cleanly (4 axis headers, orphan_dispatch_entry_count=0, SC #2 PASS line, no `unreached-within-N-hops`, `unbounded` in Methodology, Triage Revision Log header + literal "No revisions" line).
- **Committed in:** Documented in this SUMMARY only (no code/doc fix required).

**2. [Rule 1 - Bug] Plan 01 Task 2 G4 cluster verdict refinement for E-01/E-02 (informational, no back-edit)**

- **Found during:** Task 1 dispatch trace
- **Issue:** Plan 01 `## G4` section L132/133 classifies E-01 (`pic_eoi_master`) and E-02 (`pic_eoi_slave`) as G4 with rationale "함수 본문 정상 작동 가능 ... 이나 호출자 0" — however, `irq0_handler` (idt.rs:549) and `irq_default_handler` (idt.rs:557) explicitly call `pic_eoi_master()`, and `irq_slave_default_handler` (idt.rs:565) calls `pic_eoi_slave()`. All three irq*_handler functions are registered in the IDT vector by `init_idt()` (L681/685/691). So E-01/E-02 ARE reachable via the IDT axis — they are NOT orphan handlers. Plan 01 L132 hedge "**Plan 02 dispatch-reachability 가 IRQ handler vector 축에서 추가 evidence 발견 시 upgrade 가능**" anticipated this.
- **Why this is not a G3 upgrade:** D-04 narrow G3 definition requires "named dispatch entry + stub body" — E-01/E-02 bodies are real PIC OUT command sequences (not `unimplemented!() / todo!() / panic!("not implemented") / Err(NotImplemented)`), so D-04 narrow is not satisfied. The G4 verdict remains accurate as "no semantic role currently activated" (PIC mask 0xFF blocks all IRQ delivery; `enable_irq` is itself orphan), but the *justification text* "호출자 0" is empirically wrong (callers exist via the IRQ vector path).
- **Fix:** Documented in `docs/dispatch-reachability.md` Site → Dispatch Mapping (E-01 row: `axis=IDT, dispatch entry=IDT[0x20] irq0_handler AND IDT[0x21..0x27] irq_default_handler, orphan?=no`). audit-report.md verdict (G4) **kept as-is** — D-04 narrow guards against G3 upgrade, and G4 (truly-dead) is also imprecise but the more accurate alternative G2 "documented future-purpose hook" would require explicit REQ/OoS mapping which is absent. The Triage Revision Log notes the path-reachability fact without changing the bucket count, since changing E-01/E-02 to G2 would require D-01 evidence not currently present (no REQ explicitly preserves these helpers — Plan 04 reviewer can re-evaluate during human review with the new evidence). Bucket counts G1=0/G2=11/G3=1/G4=5 unchanged.
- **Files modified:** `docs/dispatch-reachability.md` (E-01/E-02 rows record IDT reachability), `.planning/audit/audit-report.md` (Triage Revision Log mentions E-01/E-02 IDT path in the narrative without changing verdicts).
- **Committed in:** `e0cbb0d` (E-01/E-02 IDT reachability in mapping), `dde8882` (Triage Revision Log narrative).

---

**Total deviations:** 2 informational documentation-only refinements (1 plan-verify-gate scope correction noted in SUMMARY only, 1 cross-file evidence enrichment without bucket-count change)
**Impact on plan:** All gates pass per acceptance prose; no code changes; no bucket count drift; G3 verdict stability confirmed; Plan 02 produces authoritative dispatch knowledge that Plan 04 (human review) can use for borderline G4↔G2 decisions.

## Issues Encountered

- **`.planning/` is in `.gitignore`** — `git add .planning/audit/audit-report.md` produced an "ignored by .gitignore" hint but the file IS tracked from prior commits, so the modification was committed normally. Not a blocker.
- **audit-report.md E-NN rows appear 2x** — once in G2/G3/G4 verdict sections, once in Raw Evidence Appendix. The naive `grep -cE '^\| E-[0-9]+'` returns 34, breaking the Plan 02 bash verify literally but matching neither the acceptance prose nor the appendix size. Resolved via Rule 3 deviation (manual appendix-scoped re-verify).

## User Setup Required

None — Plan 02 is autonomous documentation work, no external services or environment configuration involved.

## Next Phase Readiness

- **Plan 03 (closed-profile air-gap re-proof) ready** — `docs/dispatch-reachability.md` E-17 footnote 명시: closed 빌드에서 `BusKind::Network` enum variant 자체는 존재하나 `handle_attach` Network arm 의 `#[cfg(not(feature = "tls-external"))]` split 가 즉시 Denied collapse 함; Plan 03 nm/objdump 검증이 이 사실을 산출 바이너리 차원에서 재증명할 입력 baseline 확보.
- **Plan 04 (human review checkpoint) 입력 보강** — E-09 `parse_handshake_header` borderline G4 verdict + E-01/E-02 의 path-reachability 추가 evidence (위 Deviation 2) 가 reviewer 의 G4↔G2 최종 결정에 보조 자료로 작동.
- **Phase 8~12 재조정 권한 quantitative input 안정** — bucket counts (G1=0, G2=11, G3=1, G4=5) Plan 02 종료 시점에 동일 유지; AUDIT-04 권한 행사 시 인용할 정량 근거 신뢰 보존.

## Self-Check: PASSED

- FOUND: `docs/dispatch-reachability.md`
- FOUND: `.planning/audit/audit-report.md` (Triage Revision Log section appended)
- FOUND: `.planning/phases/07-integration-gap-audit/07-02-SUMMARY.md`
- FOUND: commit `e0cbb0d` (Task 1: dispatch-reachability.md 신규)
- FOUND: commit `dde8882` (Task 2: audit-report.md Triage Revision Log 추가)
- VERIFIED: `## Triage Revision Log` header + literal "No revisions: Plan 01 verdicts upheld" present
- VERIFIED: `**SC #2 gate**: orphan_handler_count = 2 AND orphan_dispatch_entry_count = 0 → PASS` present

---
*Phase: 07-integration-gap-audit*
*Plan: 02*
*Completed: 2026-05-23*
