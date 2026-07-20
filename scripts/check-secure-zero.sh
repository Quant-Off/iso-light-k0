#!/usr/bin/env bash
# Phase 9 HAL-05 nm 게이트 (a) memset U-entry 0 (b) secure_zero 심볼 존재 (T 또는 t)
# Task 3 (secure_zero 구현) 전에는 (b) FAIL 이 예상 상태
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL secure_zero 검증용 release 바이너리 미존재 $KERNEL_BIN" >&2
    echo "       먼저 make build-rel 실행" >&2
    exit 1
fi

# 심볼 덤프 폴백 체인 nm (macOS/Linux 기본) -> gnm (Homebrew binutils)
NM_CMD=""
if command -v nm >/dev/null 2>&1; then
    NM_CMD="nm"
elif command -v gnm >/dev/null 2>&1; then
    NM_CMD="gnm"
else
    echo "[CI] FAIL nm / gnm 미존재 binutils 설치 필요" >&2
    exit 1
fi

PASS=true
FAIL_REASONS=()

# (a) memset U-entry (미해결 외부 심볼) 0 검증
# grep 무매칭 시 pipefail 조기 종료 방지 || true 가드
MEMSET_U=$($NM_CMD "$KERNEL_BIN" 2>/dev/null | grep -c " U memset" || true)
MEMSET_U=$(echo "$MEMSET_U" | tr -d '[:space:]')
if [ "${MEMSET_U:-0}" != "0" ]; then
    PASS=false
    FAIL_REASONS+=("memset U-entry ${MEMSET_U} 건 검출 (외부 memset 링크 금지)")
fi

# (b) secure_zero 심볼 존재 (T 또는 t) 검증
if ! $NM_CMD "$KERNEL_BIN" 2>/dev/null | grep -qE " [Tt] secure_zero"; then
    PASS=false
    FAIL_REASONS+=("secure_zero 심볼 미존재 (#[inline(never)] + #[unsafe(no_mangle)] 확인 필요)")
fi

if $PASS; then
    echo "[CI] PASS secure_zero 심볼 존재 + memset U-entry 0 (HAL-05)"
    exit 0
fi

echo "[CI] FAIL HAL-05 secure_zero nm 게이트" >&2
for r in "${FAIL_REASONS[@]}"; do
    echo "  - $r" >&2
done
exit 1
