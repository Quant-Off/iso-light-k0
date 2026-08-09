#!/usr/bin/env bash
# Phase 9 HAL-05 nm 게이트 (a) memset U-entry 0 (b) k0_secure_zero 심볼 존재 (T 또는 t)
# WR-06 zeroize::secure_zero 와 심볼 충돌 회피 위해 커널 raw buffer 소거 심볼을
# k0_ 접두어로 개명 nm 게이트도 동기 갱신함
#
# Phase 10 ARM-11 ARCH=aarch64 분기 추가 (T-10A-02 mitigate)
#   aarch64 는 nm memset U-entry 0 + secure-erase 심볼 스코프 memset 0 + k0_secure_zero 심볼 3 게이트
#   objdump 는 lib-objdump-fallback.sh 폴백 체인 사용 aarch64 ELF 미존재 시 soft-skip
#   x86_64 경로는 기존 동작 심볼명 무변경 (ARCH 기본값 x86_64)
#
# Phase 10.1 ARM-11 Pitfall 5 판정 (reseed_drbg 비밀-버퍼 memset 잔여 위험 종결)
#   capability::reseed_drbg 의 memset 콜사이트는 let mut entropy = [0u8; ENTROPY_LEN]
#   스택 버퍼 0-init 이며 (초기화 시점 비-비밀 aarch64 에서 memset 으로 lowering)
#   비밀 소거는 entropy.zeroize() volatile 경로로 memset 을 생성하지 않음
#   즉 비밀이 elidable memset 으로 새지 않음 소스 실측 확인 (src/capability.rs L268 0-init / L275 zeroize)
#   -> k0_secure_zero 라우팅 불요 capability.rs 무변경 스코프 게이트 대상 심볼은
#      k0_secure_zero + zeroize/Zeroize/secure_zero 계열로 확정 (아래 check(b') 입력)
#
# Phase 10.1 ARM-11 D-1 정밀화 (check(b) 재설계 사용자 sign-off 2026-07-21 CONTEXT D-1)
#   check(b) 를 whole-ELF bl.*memset 카운트에서 secure-erase 심볼 스코프 memset 0 으로 재설계함
#   근거 aarch64-softfloat 는 rep-stos NEON 등가 명령 부재로 비-비밀 버퍼 init 까지 memset
#   libcall 로 lowering 하여 whole-ELF 0 이 타깃 구조적 불가 (x86 은 rep-stos 단일 인라인)
#   보안 불변식 (비밀 소거 비-elidable/CT) 은 secure-erase 심볼 스코프에서 검증되며 실측 성립
#   약화가 아니라 정밀화 whole-ELF 는 target-inherent 비-비밀 memset 을 false-positive 로 잡음
#   check(a) memset U-entry 0 + check(c) k0_secure_zero 심볼 존재는 유지 x86 경로 무변경
#   W-4 zeroize 계열은 volatile write 라 opt-level=z + fat-LTO 인라인되어도 memset 을 생성하지 않으므로
#   (RESEARCH 실측 zeroize=volatile -> no memset) named 심볼 부재는 비밀 소거 비-elidability 를
#   약화시키지 않으며 k0_secure_zero (inline-asm str xzr) 앵커로 스코프 검증이 감사 가능하게 유지됨
#   심볼 목록 fail-closed (k0_secure_zero 앵커 nm 부재 시 빈 목록 조용한 통과 금지 T-10.1-04)
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

    # (b') secure-erase 심볼 스코프 memset 콜 0 (D-1 정밀화 비밀 소거 비-elidability 검증)
    #   whole-ELF bl.*memset 카운트 대신 k0_secure_zero + zeroize/Zeroize/secure_zero 계열
    #   심볼만 objdump --disassemble-symbols 스코프 디스어셈하여 각 branch-to-memset 0 을 검증함
    #   (aarch64-softfloat 비-비밀 버퍼 init 의 target-inherent memset 은 스코프 밖으로 분리)
    #   WR-03 패턴을 bl (일반 콜) 뿐 아니라 tail-call b <memset> 까지 포함하도록 확장함
    #   b[l]? 를 whitespace 로 감싸 mnemonic 컬럼에 앵커 (조건분기 b.eq, 레지스터분기 br 은 미매칭)
    BRANCH_MEMSET_RE='[[:space:]]b[l]?[[:space:]].*memset'
    SECURE_SYMS=()
    if $NM_CMD "$AARCH64_ELF" 2>/dev/null | grep -qE " [Tt] k0_secure_zero"; then
        # #[used] 앵커 최소 대상 (fail-closed 강제)
        SECURE_SYMS+=("k0_secure_zero")
        # nm 잔존 zeroize/Zeroize/secure_zero 계열도 스코프 검증 (coverage >= 2)
        # LTO 인라인으로 named 심볼 소거 시 k0_secure_zero 단독 축소 허용 (W-4 헤더 근거)
        while IFS= read -r zs; do
            [ -n "$zs" ] && SECURE_SYMS+=("$zs")
        done < <($NM_CMD "$AARCH64_ELF" 2>/dev/null | grep -E " [Tt] " \
                 | grep -Ei "zeroize|secure_zero" | grep -v "k0_secure_zero" \
                 | awk '{print $3}')
    fi

    # fail-closed 빈 목록 (k0_secure_zero 앵커 nm 부재) 조용한 통과 금지 (T-10.1-04 게이트 gaming 방지)
    SECURE_COVERAGE="${#SECURE_SYMS[@]}"
    if [ "$SECURE_COVERAGE" -eq 0 ]; then
        PASS=false
        FAIL_REASONS+=("secure-erase 스코프 게이트 앵커 k0_secure_zero nm 부재 (fail-closed 조용한 통과 금지)")
    else
        for sym in "${SECURE_SYMS[@]}"; do
            n=$($OBJDUMP -d --disassemble-symbols="$sym" "$AARCH64_ELF" 2>/dev/null | grep -cE "$BRANCH_MEMSET_RE" || true)
            n=$(echo "$n" | tr -d '[:space:]')
            if [ "${n:-0}" != "0" ]; then
                PASS=false
                FAIL_REASONS+=("secure-erase 심볼 ${sym} 이 memset 로 branch (bl 또는 tail-call b) ${n} 건 (비밀 소거 elidable 결함)")
            fi
        done
    fi

    # (c) k0_secure_zero 심볼 존재 (T 또는 t)
    if ! $NM_CMD "$AARCH64_ELF" 2>/dev/null | grep -qE " [Tt] k0_secure_zero"; then
        PASS=false
        FAIL_REASONS+=("k0_secure_zero 심볼 미존재 (#[used] 앵커 확인 필요)")
    fi

    if $PASS; then
        echo "[CI] PASS ARM-11 aarch64 memset U-entry 0 + secure-erase 심볼 스코프 memset 0 (${SECURE_COVERAGE:-0} 심볼) + k0_secure_zero 심볼 존재 (D-1 정밀화)"
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
