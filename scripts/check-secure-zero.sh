#!/usr/bin/env bash
# Phase 9 HAL-05 nm 게이트 (a) memset U-entry 0 (b) k0_secure_zero 심볼 존재 (T 또는 t)
# WR-06 zeroize::secure_zero 와 심볼 충돌 회피 위해 커널 raw buffer 소거 심볼을
# k0_ 접두어로 개명 nm 게이트도 동기 갱신함
#
# Phase 10 ARM-11 ARCH=aarch64 분기 추가 (T-10A-02 mitigate)
#   aarch64 는 nm memset U-entry 0 + objdump -d bl.*memset 0 + k0_secure_zero 심볼 3 게이트
#   objdump 는 lib-objdump-fallback.sh 폴백 체인 사용 aarch64 ELF 미존재 시 soft-skip
#   x86_64 경로는 기존 동작 심볼명 무변경 (ARCH 기본값 x86_64)
set -euo pipefail

ARCH="${ARCH:-x86_64}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

if [ "$ARCH" = "aarch64" ]; then
    # ---- ARM-11 aarch64 분기 (Pitfall 1 memset libcall 재유입 방지) ----
    # shellcheck source=scripts/lib-objdump-fallback.sh
    . "${SCRIPT_DIR}/lib-objdump-fallback.sh"
    AARCH64_ELF="${AARCH64_ELF:-target/aarch64-unknown-none-softfloat/release/iso-light-k0}"

    if [ ! -f "$AARCH64_ELF" ]; then
        echo "[CI] SKIP ARM-11 secure_zero aarch64 게이트 ELF 미존재 ${AARCH64_ELF} (후속 wave 에서 GREEN)"
        exit 0
    fi

    OBJDUMP="$(resolve_objdump)"
    PASS=true
    FAIL_REASONS=()

    # (a) memset U-entry (미해결 외부 심볼) 0
    MEMSET_U=$($NM_CMD "$AARCH64_ELF" 2>/dev/null | grep -c " U memset" || true)
    MEMSET_U=$(echo "$MEMSET_U" | tr -d '[:space:]')
    if [ "${MEMSET_U:-0}" != "0" ]; then
        PASS=false
        FAIL_REASONS+=("memset U-entry ${MEMSET_U} 건 검출 (외부 memset 링크 금지)")
    fi

    # (b) bl.*memset 콜사이트 0 (컴파일러 memset libcall lowering 금지 str xzr 루프 강제)
    BL_MEMSET=$($OBJDUMP -d "$AARCH64_ELF" 2>/dev/null | grep -cE 'bl.*memset' || true)
    BL_MEMSET=$(echo "$BL_MEMSET" | tr -d '[:space:]')
    if [ "${BL_MEMSET:-0}" != "0" ]; then
        PASS=false
        FAIL_REASONS+=("bl.*memset 콜사이트 ${BL_MEMSET} 건 검출 (str xzr 루프 lowering 실패)")
    fi

    # (c) k0_secure_zero 심볼 존재 (T 또는 t)
    if ! $NM_CMD "$AARCH64_ELF" 2>/dev/null | grep -qE " [Tt] k0_secure_zero"; then
        PASS=false
        FAIL_REASONS+=("k0_secure_zero 심볼 미존재 (#[used] 앵커 확인 필요)")
    fi

    if $PASS; then
        echo "[CI] PASS ARM-11 aarch64 memset U-entry 0 + bl.*memset 0 + k0_secure_zero 심볼 존재"
        exit 0
    fi
    echo "[CI] FAIL ARM-11 aarch64 secure_zero 게이트" >&2
    for r in "${FAIL_REASONS[@]}"; do
        echo "  - $r" >&2
    done
    exit 1
fi

# ---- 기존 x86_64 경로 (HAL-05 무변경) ----
KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL k0_secure_zero 검증용 release 바이너리 미존재 $KERNEL_BIN" >&2
    echo "       먼저 make build-rel 실행" >&2
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

# (b) k0_secure_zero 심볼 존재 (T 또는 t) 검증
if ! $NM_CMD "$KERNEL_BIN" 2>/dev/null | grep -qE " [Tt] k0_secure_zero"; then
    PASS=false
    FAIL_REASONS+=("k0_secure_zero 심볼 미존재 (#[inline(never)] + #[unsafe(no_mangle)] 확인 필요)")
fi

if $PASS; then
    echo "[CI] PASS k0_secure_zero 심볼 존재 + memset U-entry 0 (HAL-05)"
    exit 0
fi

echo "[CI] FAIL HAL-05 k0_secure_zero nm 게이트" >&2
for r in "${FAIL_REASONS[@]}"; do
    echo "  - $r" >&2
done
exit 1
