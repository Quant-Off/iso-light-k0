#!/usr/bin/env bash
# Phase 9 HAL-04 본체 무변경 diff-stat 게이트 (2-tier base commit 파일 기반)
# tier 1 엄격 본체 추가+삭제 합계 < 50 hard gate
# tier 2 src/main.rs 합계 보고 + hard cap 852
#   ROADMAP SC #2 가 main.rs cfg 가드 제거 + re-export 정리를 명시 허용하므로 별도 tier (planner 결정)
#   Phase 10.1 D-2 sign-off (2026-07-21) _kernel_start (약 605 줄) + multiboot2 어댑터를
#   src/arch/x86_64/ 로 행위-무변경 이관(HAL-06 복원)하여 body arch-cfg 0 을 복원하며 이관
#   워킹트리(=커밋될 상태) delta 실측 832 + 20 고정 마진 = 852 로 tier2 캡을 명시 상향한다
#   (커밋 후 BASE..HEAD 가 832 로 반영되어도 852 이하 봉인 유지 W-1 commit-timing robust)
#   HAL-04 Phase-9 목적(HAL 추출이 body 를 재작성하지 않게)은 완료됨 tier1 50 무변경 게이트 무력화 아님
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

if [ "$TIER2_SUM" -gt 852 ]; then
    PASS=false
    echo "[CI] FAIL tier2 src/main.rs diff ${TIER2_SUM} lines > 852 hard cap" >&2
    git diff --numstat -M "$BASE_REF"..HEAD -- src/main.rs >&2
fi

if $PASS; then
    echo "[CI] PASS 본체 무변경 게이트 tier1=${TIER1_SUM}/50 tier2=${TIER2_SUM}/852 (HAL-04 base=$(echo "$BASE_REF" | cut -c1-12))"
    exit 0
fi
exit 1
