#!/usr/bin/env bash
# Phase 9 HAL-06 standing gate cfg(target_arch) 가 src/arch/ 외부 0 으로 수렴하는지 측정
# 주석 라인 (`// ...`) 은 위반 카운트에서 제외 bare 카운트 게이트 금지 (PLAN Task 1)
# 9-C 종료 전까지 비-0 FAIL 이 예상 상태 (수렴 게이트)
set -euo pipefail

VIOLATIONS=$(grep -rn "cfg(target_arch" src/ | grep -v "src/arch/" | grep -vE ':[0-9]+:[[:space:]]*//' || true)

if [ -n "$VIOLATIONS" ]; then
    COUNT=$(echo "$VIOLATIONS" | wc -l | tr -d '[:space:]')
    echo "[CI] FAIL cfg(target_arch) ${COUNT} sites outside src/arch/ (HAL-06 수렴 전 예상 상태)" >&2
    echo "$VIOLATIONS" >&2
    exit 1
fi

echo "[CI] PASS cfg(target_arch) 0 sites outside src/arch/ (HAL-06)"
exit 0
