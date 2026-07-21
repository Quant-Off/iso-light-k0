#!/usr/bin/env bash
# Phase 10 ARM-03 .vector_table 0x800 (2KiB) 정렬 objdump 게이트 (T-10A-01 mitigate)
#
# VBAR_EL1 은 예외 벡터 베이스 주소의 하위 11 bit == 0 (2KiB 정렬) 을 강제함
# (16 entry x 0x80 byte = 0x800) linker-aarch64.ld .vector_table ALIGN(0x800) 의
# 결과를 산출 ELF 에서 실측하여 objdump -h 섹션 VMA 하위 11 bit 를 검증함
#
# aarch64 ELF 또는 .vector_table 섹션 미존재 시 soft-skip (exit 0)
# 실제 하드 판정은 10-B 벡터 테이블 배치로 산출물이 생긴 후 GREEN 으로 전환됨
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib-objdump-fallback.sh
. "${SCRIPT_DIR}/lib-objdump-fallback.sh"

AARCH64_ELF="${AARCH64_ELF:-target/aarch64-unknown-none-softfloat/release/iso-light-k0}"

if [ ! -f "$AARCH64_ELF" ]; then
    echo "[CI] SKIP .vector_table 정렬 게이트 ELF 미존재 ${AARCH64_ELF} (후속 wave 에서 GREEN)"
    exit 0
fi

OBJDUMP="$(resolve_objdump)"

# objdump -h 섹션 헤더에서 .vector_table 라인 추출
# GNU objdump / llvm-objdump 공통 컬럼 순서 idx name size vma ... 이므로 4 번째 필드가 VMA
VEC_LINE="$($OBJDUMP -h "$AARCH64_ELF" 2>/dev/null | grep -E '[[:space:]]\.vector_table([[:space:]]|$)' || true)"

if [ -z "$VEC_LINE" ]; then
    echo "[CI] SKIP .vector_table 섹션 미존재 ${AARCH64_ELF} (벡터 배치 전 후속 wave 이월)"
    exit 0
fi

VMA_HEX="$(echo "$VEC_LINE" | awk '{print $4}' | sed 's/^0x//')"

if [ -z "$VMA_HEX" ]; then
    echo "[CI] FAIL .vector_table VMA 파싱 실패 라인 [${VEC_LINE}]" >&2
    exit 1
fi

# 하위 11 bit (0x7ff 마스크) == 0 검증 (2KiB 정렬 위반 여부)
MASKED=$(( 16#${VMA_HEX} & 0x7ff ))

if [ "$MASKED" -ne 0 ]; then
    echo "[CI] FAIL .vector_table VMA 0x${VMA_HEX} 하위 11 bit != 0 (잔여=0x$(printf '%x' "$MASKED")) 2KiB 정렬 위반 ARM-03" >&2
    exit 1
fi

echo "[CI] PASS .vector_table VMA 0x${VMA_HEX} 하위 11 bit == 0 (0x800 정렬 ARM-03)"
exit 0
