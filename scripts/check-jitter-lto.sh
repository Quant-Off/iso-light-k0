#!/usr/bin/env bash
# Phase 8 ENTR-08 JitterRng LTO 보호 objdump CI gate
# Phase 1 check-no-alloc.sh + Phase 6 check-no-network.sh fallback chain mirror
# Wave 0 = skeleton mode (expected exit 1) -> Wave 2 = first PASS expectation -> Wave 4 = final PASS 재확인
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL JitterRng objdump 검증용 release 바이너리 미존재 $KERNEL_BIN" >&2
    echo "       먼저 make build-rel 실행" >&2
    exit 1
fi

# 심볼 덤프 폴백 체인 objdump (Linux/CI) gobjdump (macOS Homebrew binutils)
DUMP_CMD=""
DUMP_DISAS=""
if command -v objdump >/dev/null 2>&1; then
    DUMP_CMD="objdump --syms"
    DUMP_DISAS="objdump -d"
elif command -v gobjdump >/dev/null 2>&1; then
    DUMP_CMD="gobjdump --syms"
    DUMP_DISAS="gobjdump -d"
else
    echo "[CI] FAIL objdump / gobjdump 미존재 binutils 설치 필요" >&2
    exit 1
fi

# (a) jitter_fold_step 함수 instruction count >= 1024 검증
# grep 무매칭 시 pipefail 조기 종료로 진단 메시지가 생략되지 않도록 || true 가드
SYMBOL=$($DUMP_CMD "$KERNEL_BIN" 2>/dev/null | grep -E "jitter.*fold_step" | head -1 | awk '{print $NF}' || true)
if [ -z "$SYMBOL" ]; then
    echo "[CI] FAIL jitter_fold_step 심볼 미존재 #[inline(never)] 누락 의심" >&2
    exit 1
fi

INSTRUCTION_COUNT=$($DUMP_DISAS "$KERNEL_BIN" 2>/dev/null \
    | awk -v sym="$SYMBOL" '$0 ~ sym {found=1; next} found && /^$/ {exit} found' \
    | wc -l)

if [ "$INSTRUCTION_COUNT" -lt 1024 ]; then
    echo "[CI] FAIL jitter_fold_step instruction count $INSTRUCTION_COUNT < 1024 LTO DCE 의심" >&2
    exit 1
fi

# (b) black_box 호출 site 존재 검증 (Pitfall 4)
BB_COUNT=$($DUMP_DISAS "$KERNEL_BIN" 2>/dev/null | grep -cE "black_box" || true)
if [ "$BB_COUNT" -lt 2 ]; then
    echo "[CI] FAIL black_box markers $BB_COUNT < 2 core::hint::black_box 누락 의심" >&2
    exit 1
fi

echo "[CI] PASS JitterRng LTO 보호 검증 (instructions=$INSTRUCTION_COUNT black_box=$BB_COUNT)"
exit 0
