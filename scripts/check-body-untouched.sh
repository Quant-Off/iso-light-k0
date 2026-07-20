#!/usr/bin/env bash
# Phase 9 HAL-04 본체 무변경 diff-stat 게이트 (2-tier base commit 파일 기반)
# tier 1 엄격 본체 추가+삭제 합계 < 50 hard gate
# tier 2 src/main.rs 합계 보고 + hard cap 150
#   ROADMAP SC #2 가 main.rs cfg 가드 제거 + re-export 정리를 명시 허용하므로 별도 tier (planner 결정)
# rename 추적 오염 방지 -M 플래그 필수 (RESEARCH Pitfall 6)
set -euo pipefail

BASE_REF="${BASE_REF:-$(cat scripts/phase9-base-commit)}"

TIER1_PATHS=(
    src/hsm.rs
    src/hsm_registry.rs
    src/hsm_attest.rs
    src/tls
    src/capability.rs
    src/ipc.rs
    src/elf.rs
    src/keystore.rs
    src/crypto_service.rs
    src/sign_service.rs
)

TIER1_SUM=$(git diff --numstat -M "$BASE_REF"..HEAD -- "${TIER1_PATHS[@]}" | awk '{a += $1 + $2} END {print a + 0}')
TIER2_SUM=$(git diff --numstat -M "$BASE_REF"..HEAD -- src/main.rs | awk '{a += $1 + $2} END {print a + 0}')

PASS=true

if [ "$TIER1_SUM" -ge 50 ]; then
    PASS=false
    echo "[CI] FAIL tier1 엄격 본체 diff ${TIER1_SUM} lines >= 50 (HAL-04)" >&2
    git diff --numstat -M "$BASE_REF"..HEAD -- "${TIER1_PATHS[@]}" >&2
fi

if [ "$TIER2_SUM" -gt 150 ]; then
    PASS=false
    echo "[CI] FAIL tier2 src/main.rs diff ${TIER2_SUM} lines > 150 hard cap" >&2
    git diff --numstat -M "$BASE_REF"..HEAD -- src/main.rs >&2
fi

if $PASS; then
    echo "[CI] PASS 본체 무변경 게이트 tier1=${TIER1_SUM}/50 tier2=${TIER2_SUM}/150 (HAL-04 base=$(echo "$BASE_REF" | cut -c1-12))"
    exit 0
fi
exit 1
