#!/usr/bin/env bash
# Phase 10 ARM-01 aarch64 QEMU virt 부팅 마커 하네스 골격 (bash 3.2 호환)
#
# x86 하네스(scripts/qemu-test.sh)와 근본 상이함
#   x86  GRUB multiboot2 ISO -cdrom 경유 부팅 + VGA 프레임버퍼 pmemsave
#   aarch64  GRUB/ISO 없이 qemu-system-aarch64 -M virt -kernel <elf> 직접 부팅 + PL011 직렬
#
# 본 plan(10-A)은 마커 grep 로직과 부팅 하네스 골격만 완성함
# 실제 7-line 마커는 커널 부팅 코드가 emit 하며 wave 별로 채워짐
#   10-B EL=1  10-C MMU=ON  10-D GICR/ChildrenAsleep/GRP1/IRQ/PSCI
# 완전한 7-line 실행 GREEN 은 10-D 이후 10-F 봉인에서 하드 판정됨
#
# 부분집합 완화 (EXPECTED_MARKERS / REQUIRE_MARKERS)
#   sub-step 이 아직 전체 마커를 emit 하지 않는 시점에는 요구 키를 부분집합으로 완화 실행
#   예 10-C EXPECTED_MARKERS="EL MMU" 로 앞 2 마커만 요구
set -euo pipefail

QEMU_BIN="qemu-system-aarch64"
AARCH64_ELF="${AARCH64_ELF:-target/aarch64-unknown-none-softfloat/release/iso-light-k0}"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-60}"

# 부팅 순서 마커 키 -> grep -E 패턴 (7-line proof)
MARKER_KEYS=(EL MMU GICR CHILDREN GRP1 IRQ PSCI)
marker_pattern() {
    case "$1" in
        EL)       echo 'EL=1' ;;
        MMU)      echo 'MMU=ON' ;;
        GICR)     echo 'GICR wake OK' ;;
        CHILDREN) echo 'ChildrenAsleep=0' ;;
        GRP1)     echo 'GRP1 enabled' ;;
        IRQ)      echo 'IRQ [0-9]+ delivered' ;;   # IRQ N delivered (N 은 실제 IRQ 번호)
        PSCI)     echo 'PSCI.*0x1' ;;              # PSCI >= 0x10000 (PSCI_VERSION via HVC)
        *)        echo '' ;;
    esac
}

# 요구 마커 키 집합 결정 EXPECTED_MARKERS -> REQUIRE_MARKERS -> 기본 7 전체
REQ_KEYS="${EXPECTED_MARKERS:-${REQUIRE_MARKERS:-${MARKER_KEYS[*]}}}"

# honest skip (silent skip 금지 Phase 8/9 선례) 미설치/미존재는 exit 3 로 명시
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    echo "[CI] SKIP-HONEST qemu-system-aarch64 미설치 aarch64 부팅 마커 검증 불가" >&2
    exit 3
fi
if [ ! -f "$AARCH64_ELF" ]; then
    echo "[CI] SKIP-HONEST aarch64 ELF 미존재 ${AARCH64_ELF} 부팅 마커 검증 불가 (10-B..10-D 산출 후 GREEN)" >&2
    exit 3
fi

# gtimeout(Homebrew coreutils) -> timeout 폴백 실행 상한 바운드
TIMEOUT_CMD=""
if command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
elif command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
fi

SERIAL_LOG="$(mktemp -t k0-aarch64-serial.XXXXXX)"
trap 'rm -f "$SERIAL_LOG"' EXIT

# -display none + -serial mon:stdio 로 PL011 직렬을 stdio 로 캡처
# (-nographic 은 stdio 를 선점하여 -serial mon:stdio 와 이중 점유 충돌하므로 -display none 사용)
# 정상 종료는 커널 PSCI SYSTEM_OFF 또는 timeout 상한 kill 로 바운드
QEMU_ARGS=(
    -M virt,gic-version=3
    -cpu cortex-a72
    -m 512M
    -display none
    -serial mon:stdio
    -kernel "$AARCH64_ELF"
)

set +e
if [ -n "$TIMEOUT_CMD" ]; then
    "$TIMEOUT_CMD" "$QEMU_TIMEOUT" "$QEMU_BIN" "${QEMU_ARGS[@]}" > "$SERIAL_LOG" 2>&1
    QEMU_EXIT=$?
else
    echo "[CI] WARN gtimeout/timeout 미존재 상한 없이 실행" >&2
    "$QEMU_BIN" "${QEMU_ARGS[@]}" > "$SERIAL_LOG" 2>&1
    QEMU_EXIT=$?
fi
set -e

# 마커 fail-accumulator 누락 마커 전량 보고
FAIL=false
MISSING=()
for key in $REQ_KEYS; do
    pat="$(marker_pattern "$key")"
    if [ -z "$pat" ]; then
        echo "[CI] WARN 알 수 없는 마커 키 ${key} 무시" >&2
        continue
    fi
    if grep -qE "$pat" "$SERIAL_LOG" 2>/dev/null; then
        echo "[CI]  ok  마커 ${key} 검출 (${pat})"
    else
        FAIL=true
        MISSING+=("${key} (${pat})")
    fi
done

echo "[CI] qemu-system-aarch64 종료 코드 ${QEMU_EXIT} (124=timeout 상한)"

if $FAIL; then
    echo "[CI] FAIL aarch64 부팅 마커 누락 (${#MISSING[@]} 건)" >&2
    for m in "${MISSING[@]}"; do
        echo "  - $m" >&2
    done
    exit 1
fi

echo "[CI] PASS aarch64 부팅 마커 전량 검출 (${REQ_KEYS})"
exit 0
