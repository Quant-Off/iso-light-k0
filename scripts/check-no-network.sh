#!/usr/bin/env bash
# Phase 6 GAP-03 closed 프로필 Network 심볼 leak 가드
# Phase 1 check-no-alloc.sh + Phase 5 check-no-dev-sk.sh fallback chain mirror
# closed 빌드 산출물에 5 NETWORK_* 패턴 부재를 link 산출물 수준에서 검증
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL closed 프로필 바이너리 미존재 $KERNEL_BIN" >&2
    echo "       make build-rel 또는 cargo build --release --target x86_64-unknown-none 후 재실행" >&2
    exit 1
fi

# 심볼 덤프 폴백 체인 objdump (Linux/CI) gobjdump (macOS Homebrew binutils) nm --demangle (BSD/macOS 기본)
DUMP_CMD=""
if command -v objdump >/dev/null 2>&1; then
    DUMP_CMD="objdump --syms"
elif command -v gobjdump >/dev/null 2>&1; then
    DUMP_CMD="gobjdump --syms"
elif command -v nm >/dev/null 2>&1; then
    DUMP_CMD="nm --demangle"
else
    echo "[CI] FAIL objdump gobjdump nm 모두 미존재 binutils 설치 필요" >&2
    echo "       macOS brew install binutils 후 gobjdump 사용 가능" >&2
    exit 1
fi

# Phase 6 D-07 Layer 1 5 grep 패턴 (RESEARCH §5 grep 정확화)
# 각 패턴 (a) mangled Rust 심볼 (b) demangled 형태 (c) defense-in-depth 모듈 prefix
EXPECTED_ABSENT=(
    # (1) NETWORK_ATTACH_CAP BSS static `.bss.NETWORK_ATTACH_CAP` mangled
    "NETWORK_ATTACH_CAP"
    # (2) NETWORK_CAP_STATE BSS static
    "NETWORK_CAP_STATE"
    # (3) init_network_cap mangled `_ZN[..]air_gap[..]init_network_cap[..]E`
    "init_network_cap"
    # (4) take_network_cap handler 본문 (sys_network_cap_take dispatcher 본체)
    "take_network_cap"
    # (5) air_gap::network 모듈 경로 defense-in-depth prefix regex
    #     다른 모듈이 air_gap::network::* 우발 정의 시 검출
    "air_gap..network"
)

PASS=true
FAIL_REASONS=()

for sym in "${EXPECTED_ABSENT[@]}"; do
    if $DUMP_CMD "$KERNEL_BIN" 2>/dev/null | grep -qE "$sym"; then
        PASS=false
        FAIL_REASONS+=("symbol detected: $sym")
    fi
done

if $PASS; then
    echo "[CI] PASS closed 프로필 Network 심볼 0개 (GAP-03 verified)"
    exit 0
fi

echo "[CI] FAIL closed 프로필 Network 심볼 검출 tls-external 게이트 누설" >&2
for r in "${FAIL_REASONS[@]}"; do
    echo "  - $r" >&2
done
exit 1
