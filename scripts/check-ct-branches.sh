#!/usr/bin/env bash
# Phase 9 SC #8 CT 함수 분기 부재 objdump CI gate (Phase 12 MTRX-05(c) prior art)
# LTO + opt-level=z 재배치가 CT 함수에 je/jne/jz/jnz 를 재생성하지 않는지 상시 검증 (RESEARCH Pitfall 2)
#
# 대상 심볼 fragment 쌍 (PLAN 명명 대비 실측 정정 09-01-SUMMARY Deviations 참조)
#   1) hsm_registry + authenticate  capability 토큰 CT 인증 실구현 (PLAN 의 capability::authenticate 는 미실존 명명)
#   2) constant_time + CtLess       elib-k0-nt CT 프리미티브 (PLAN 의 hsm_attest::verify_signature 는 미실존 명명
#                                   실존 verify_attest 는 D-12 설계상 입력 독립 분기를 합법 보유하여 분기 0 게이트 부적합)
# hsm_attest::verify_attest 분기 수는 관측 전용으로만 보고 (게이트 비대상)
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL CT 분기 검증용 release 바이너리 미존재 $KERNEL_BIN" >&2
    echo "       먼저 make build-rel 실행" >&2
    exit 1
fi

# 심볼 덤프 폴백 체인 objdump (Linux/CI) gobjdump (macOS Homebrew binutils)
DUMP_DISAS=""
if command -v objdump >/dev/null 2>&1; then
    DUMP_DISAS="objdump -d"
elif command -v gobjdump >/dev/null 2>&1; then
    DUMP_DISAS="gobjdump -d"
else
    echo "[CI] FAIL objdump / gobjdump 미존재 binutils 설치 필요" >&2
    exit 1
fi

# 역어셈 1 회 실행 후 재사용
DISAS=$($DUMP_DISAS "$KERNEL_BIN" 2>/dev/null)

# 헤더 라인 (`^[0-9a-f]+ <sym>:`) 에서 fragment 쌍을 모두 포함한 심볼명 추출
find_symbols() {
    local frag1="$1" frag2="$2"
    { echo "$DISAS" | grep -E '^[0-9a-f]+ <.*>:' | grep -- "$frag1" | grep -- "$frag2" \
        | sed -E 's/^[0-9a-f]+ <(.*)>:.*/\1/'; } || true
}

# 심볼 header line (`<sym>:`) 만 anchor 로 사용 call site 텍스트 오매칭 차단
# awk 조기 exit 의 SIGPIPE 가 pipefail 로 전파되지 않도록 || true 가드
branch_count() {
    local sym="$1"
    local body
    body=$({ echo "$DISAS" | awk -v sym="$sym" 'index($0, "<" sym ">:") {found=1; next} found && /^$/ {exit} found'; } || true)
    echo "$body" | grep -cE '\bje\b|\bjne\b|\bjz\b|\bjnz\b' || true
}

PASS=true

check_pair() {
    local frag1="$1" frag2="$2" label="$3"
    local syms sym cnt
    syms=$(find_symbols "$frag1" "$frag2")
    if [ -z "$syms" ]; then
        echo "[CI] FAIL symbol not found ${label} (${frag1} + ${frag2}) LTO 인라이닝 의심 본체 수정 우회 금지 blocker 보고" >&2
        PASS=false
        return
    fi
    while IFS= read -r sym; do
        cnt=$(branch_count "$sym" | tr -d '[:space:]')
        if [ "${cnt:-0}" != "0" ]; then
            echo "[CI] FAIL ${label} ${sym} je/jne/jz/jnz ${cnt} 건 (CT 분기 재생성 의심)" >&2
            PASS=false
        else
            echo "[CI]  ok  ${label} ${sym} branch=0"
        fi
    done <<< "$syms"
}

check_pair "hsm_registry" "authenticate" "capability-token-CT-auth"
check_pair "constant_time" "CtLess" "ct-primitive"

# 관측 전용 verify_attest 분기 수 보고 (D-12 입력 독립 분기 합법 게이트 비대상)
OBS_SYMS=$(find_symbols "hsm_attest" "verify_attest")
if [ -n "$OBS_SYMS" ]; then
    while IFS= read -r sym; do
        OBS_CNT=$(branch_count "$sym" | tr -d '[:space:]')
        echo "[CI]  obs verify_attest ${sym} branch=${OBS_CNT:-0} (관측 전용)"
    done <<< "$OBS_SYMS"
fi

if $PASS; then
    echo "[CI] PASS CT 함수 je/jne/jz/jnz 0 확인 (SC #8)"
    exit 0
fi
exit 1
