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

# 부팅 순서 마커 키 -> grep -E 패턴
# 앞 7 키는 7-line boot proof, 뒤 5 키는 커널 본체 합류 실증(park 해소)
MARKER_KEYS=(EL MMU GICR CHILDREN GRP1 IRQ PSCI VIRTIO DRBG QUORUM GAP JOIN)
marker_pattern() {
    case "$1" in
        EL)       echo 'EL=1' ;;
        MMU)      echo 'MMU=ON' ;;
        GICR)     echo 'GICR wake OK' ;;
        CHILDREN) echo 'ChildrenAsleep=0' ;;
        GRP1)     echo 'GRP1 enabled' ;;
        IRQ)      echo 'IRQ [0-9]+ delivered' ;;   # IRQ N delivered (N 은 실제 IRQ 번호)
        PSCI)     echo 'PSCI.*0x1' ;;              # PSCI >= 0x10000 (PSCI_VERSION via HVC)
        VIRTIO)   echo 'VIRTIO_RNG probe done' ;;  # virtio-mmio source-1 probe
        DRBG)     echo 'CAP_DRBG init OK' ;;        # Capability Hash-DRBG-SHA256 초기화
        QUORUM)   echo 'ENTROPY_QUORUM_2_OF_3_OK' ;; # entropy 2-of-3 quorum 게이트 통과
        GAP)      echo 'gap_self_check OK' ;;       # air-gap 2 층 self-check
        JOIN)     echo 'kernel init complete' ;;    # 커널 본체 합류 종료 (park 해소 실증)
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

SERIAL_LOG="$(mktemp -t k0-aarch64-serial.XXXXXX)"
QEMU_STDIO_LOG="$(mktemp -t k0-aarch64-stdio.XXXXXX)"
QEMU_PID=""
cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
    fi
    rm -f "$SERIAL_LOG" "$QEMU_STDIO_LOG"
}
trap cleanup EXIT

# -display none + -serial file: 로 PL011 직렬을 로그 파일로 직접 캡처
# (백그라운드 실행에서 mon:stdio 는 stdin 점유로 SIGTTIN/조기 EOF 위험 -> file: 로 회피)
# 커널은 7-line proof 후 wfi park 하여 스스로 종료하지 않으므로 요구 마커 전량 검출 시
# 조기 kill 로 종결함 (기존 full-timeout grep 대비 PASS/FAIL 판정 동일 실행 시간만 단축)
# -cpu max 로 FEAT_RNG(RNDR) TCG 에뮬레이션 활성 (entropy source-0 hw)
# -device virtio-rng-device 로 virtio-mmio entropy source-1 부착 (2-of-3 quorum 성립)
QEMU_ARGS=(
    -M virt,gic-version=3
    -cpu max
    -m 512M
    -display none
    -device virtio-rng-device
    -serial "file:$SERIAL_LOG"
    -kernel "$AARCH64_ELF"
)

# 요구 마커 키 전량이 로그에 존재하는지 판정 (조기 종료 조건)
all_markers_present() {
    local key pat
    for key in $REQ_KEYS; do
        pat="$(marker_pattern "$key")"
        [ -z "$pat" ] && continue
        grep -qE "$pat" "$SERIAL_LOG" 2>/dev/null || return 1
    done
    return 0
}

set +e
"$QEMU_BIN" "${QEMU_ARGS[@]}" </dev/null > "$QEMU_STDIO_LOG" 2>&1 &
QEMU_PID=$!

# 1s 간격 폴링 상한 QEMU_TIMEOUT 초 마커 전량 검출 또는 QEMU 자체 종료 시 루프 탈출
elapsed=0
EARLY_EXIT=false
while [ "$elapsed" -lt "$QEMU_TIMEOUT" ]; do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        break
    fi
    if all_markers_present; then
        EARLY_EXIT=true
        break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

# wfi park 은 스스로 종료하지 않으므로 SIGTERM 으로 종결
if kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
fi
wait "$QEMU_PID" 2>/dev/null
QEMU_EXIT=$?
QEMU_PID=""
set -e

if $EARLY_EXIT; then
    echo "[CI]  ok  요구 마커 전량 조기 검출 (${elapsed}s 경과 QEMU_TIMEOUT=${QEMU_TIMEOUT}s 미도달)"
fi

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

echo "[CI] qemu-system-aarch64 종료 코드 ${QEMU_EXIT} (143=SIGTERM 조기 종결 / 124=timeout 상한)"

if $FAIL; then
    echo "[CI] FAIL aarch64 부팅 마커 누락 (${#MISSING[@]} 건)" >&2
    for m in "${MISSING[@]}"; do
        echo "  - $m" >&2
    done
    if [ -s "$QEMU_STDIO_LOG" ]; then
        echo "[CI] --- qemu-system-aarch64 stdout/stderr ---" >&2
        cat "$QEMU_STDIO_LOG" >&2
    fi
    exit 1
fi

echo "[CI] PASS aarch64 부팅 마커 전량 검출 (${REQ_KEYS})"
exit 0
