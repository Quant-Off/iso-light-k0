#!/usr/bin/env bash
# Phase 1 SC-1b alloc-symbol gate
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/debug/iso-light-k0}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL: 커널 바이너리 미존재 — $KERNEL_BIN (먼저 'make build' 실행)" >&2
    exit 1
fi

# 심볼 덤프 툴 폴백 체인: objdump (Linux/CI) → gobjdump (macOS Homebrew binutils) → nm --demangle (BSD/macOS 기본)
DUMP_CMD=""
if command -v objdump >/dev/null 2>&1; then
    DUMP_CMD="objdump --syms"
elif command -v gobjdump >/dev/null 2>&1; then
    DUMP_CMD="gobjdump --syms"
elif command -v nm >/dev/null 2>&1; then
    DUMP_CMD="nm --demangle"
else
    echo "[CI] FAIL: objdump / gobjdump / nm 모두 미존재 — binutils 설치 필요" >&2
    echo "       macOS: 'brew install binutils' 후 gobjdump 사용 가능" >&2
    exit 1
fi

# 금지 심볼 10종: 4 mangled __rust_alloc* 패밀리 + 4 demangled alloc::* 네임스페이스
# + 2 방어심도 추가 (dlmalloc / __rdl_alloc — 차후 talc/dlmalloc 기반 no_std 할당자 회귀 대비).
EXPECTED_ABSENT=(
    "__rust_alloc"
    "__rust_dealloc"
    "__rust_realloc"
    "__rust_alloc_zeroed"
    "alloc::alloc::"
    "alloc::vec::"
    "alloc::string::"
    "alloc::boxed::"
    "dlmalloc"
    "__rdl_alloc"
    # Phase 4 Plan 01 postcard alloc 회귀 차단 (D-15, RESEARCH Pitfall 3)
    "postcard::to_allocvec"
    "postcard::to_stdvec"
    "postcard::to_vec"
    "serde::std::"
)

PASS=true
FAIL_REASONS=()

for sym in "${EXPECTED_ABSENT[@]}"; do
    if $DUMP_CMD "$KERNEL_BIN" 2>/dev/null | grep -q "$sym"; then
        PASS=false
        FAIL_REASONS+=("symbol detected: $sym")
    fi
done

if $PASS; then
    echo "[CI] PASS: alloc 심볼 0개 확인 (alloc=0 verified)"
    exit 0
fi

echo "[CI] FAIL: alloc 심볼 검출 — 커널이 heap allocator 를 link 함" >&2
for r in "${FAIL_REASONS[@]}"; do
    echo "  - $r" >&2
done
exit 1
