#!/usr/bin/env bash
# Phase 2 BUS-01/BUS-04 alloc-zero gate
#
# 목적:
#   src/bus.rs (BusDriver 트레이트 + BusInstance enum-dispatch + SoftwareBus / Ring3ProcessBus
#   구현 본체) 표면이 dynamic allocation 의존 0 임을 소스 레벨에서 정적 검증.
#   심볼 레벨 검사는 scripts/check-no-alloc.sh 가 별도로 수행 — 본 스크립트는 회귀 방지용
#   소스-grep 게이트 (BUS-01 의 "trait-surface alloc-free" invariant 를 노출).
#
# 검출 대상 (어느 하나라도 매칭 시 FAIL):
#   - extern crate alloc
#   - use alloc::
#   - alloc::vec / alloc::string / alloc::boxed / alloc::alloc
#   - Box<dyn ...>
#   - \bVec<
#   - \bString\b
#
# 사용 환경:
#   - 호스트 어디서나 동작 (cargo / objdump 의존 없음)
#   - CI 게이트 (ci-phase2) 의 비-바이너리 leg

set -euo pipefail

BUS_FILE="${BUS_FILE:-src/bus.rs}"

if [ ! -f "$BUS_FILE" ]; then
    echo "[CI] FAIL: $BUS_FILE 미존재 — Phase 2 BusDriver 표면 누락" >&2
    exit 1
fi

# 금지 패턴 (PCRE 가 아닌 grep -E 호환 정규식). \b 미사용으로 macOS BSD grep 호환.
PATTERNS=(
    '^[[:space:]]*extern[[:space:]]+crate[[:space:]]+alloc\b'
    'use[[:space:]]+alloc::'
    'alloc::vec'
    'alloc::string'
    'alloc::boxed'
    'alloc::alloc'
    'Box<dyn'
    '(^|[^A-Za-z0-9_])Vec<'
    '(^|[^A-Za-z0-9_])String([^A-Za-z0-9_]|$)'
)

PASS=true
FAIL_REASONS=()

for pat in "${PATTERNS[@]}"; do
    # grep -E 가 매칭하면 exit 0 — 매칭 시 FAIL
    if grep -nE "$pat" "$BUS_FILE" >/dev/null 2>&1; then
        PASS=false
        # 처음 매칭 라인 출력 (디버그 컨텍스트)
        FIRST_HIT=$(grep -nE "$pat" "$BUS_FILE" | head -1)
        FAIL_REASONS+=("pattern '$pat' matched: $FIRST_HIT")
    fi
done

if $PASS; then
    echo "[CI] PASS: src/bus.rs alloc 의존 0 (BUS-01 trait-surface alloc-free verified)"
    exit 0
fi

echo "[CI] FAIL: src/bus.rs 에 alloc 의존 패턴 검출" >&2
for r in "${FAIL_REASONS[@]}"; do
    echo "  - $r" >&2
done
exit 1
