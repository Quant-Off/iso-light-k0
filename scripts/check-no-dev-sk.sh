#!/usr/bin/env bash
# Phase 5 D-19 closed 프로필 dev sk leak 가드
# closed 프로필 빌드 산출물에서 dev_trust_root.sk44 의 첫 16 옥텟 자료 부재 +
# dev_trust_root 심볼 부재 (objdump → gobjdump → nm fallback chain) 두 가지를 동시 검증
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"
DEV_SK="${DEV_SK:-keys/dev_trust_root.sk44}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL: closed 프로필 바이너리 미존재 ($KERNEL_BIN)" >&2
    echo "       'make build-rel' 또는 'cargo build --release --target x86_64-unknown-none' 후 재실행" >&2
    exit 1
fi

if [ ! -f "$DEV_SK" ]; then
    # dev sk 자체가 없으면 검증 자동 PASS (clean checkout 시나리오)
    echo "[CI] PASS: dev sk 파일 부재 자동 통과"
    exit 0
fi

# (1) dev sk 첫 16 옥텟 hex 추출
if ! command -v xxd >/dev/null 2>&1; then
    echo "[CI] FAIL: xxd 미설치 (dev sk hex prefix 추출 불가)" >&2
    exit 1
fi
DEV_SK_PREFIX=$(xxd -p -l 16 "$DEV_SK" | tr -d '\n')
if [ -z "$DEV_SK_PREFIX" ]; then
    echo "[CI] FAIL: dev sk hex prefix 추출 실패" >&2
    exit 1
fi

# (2) 빌드 산출물 hex dump 후 prefix 부재 grep
if xxd -p "$KERNEL_BIN" | tr -d '\n' | grep -q "$DEV_SK_PREFIX"; then
    echo "[CI] FAIL: closed 프로필 빌드에 dev sk 자료 leak 검출 ($DEV_SK_PREFIX)" >&2
    exit 1
fi

# (3) 심볼 grep 폴백 체인 (check-no-alloc 패턴 일관)
DUMP_CMD=""
if command -v objdump >/dev/null 2>&1; then
    DUMP_CMD="objdump --syms"
elif command -v gobjdump >/dev/null 2>&1; then
    DUMP_CMD="gobjdump --syms"
elif command -v nm >/dev/null 2>&1; then
    DUMP_CMD="nm --demangle"
else
    echo "[CI] FAIL: objdump / gobjdump / nm 미존재 binutils 설치 필요" >&2
    exit 1
fi

if $DUMP_CMD "$KERNEL_BIN" 2>/dev/null | grep -qi "dev_trust_root"; then
    echo "[CI] FAIL: closed 프로필 빌드에 dev_trust_root 심볼 leak" >&2
    exit 1
fi

echo "[CI] PASS: closed 프로필 dev sk 자료/심볼 부재 (Phase 5 D-19 통과)"
exit 0
