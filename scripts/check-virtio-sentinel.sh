#!/usr/bin/env bash
# Phase 8 ENTR-04 virtio-rng sentinel + verify-changed 패턴 회귀 가드
# check-no-alloc-bus.sh 소스 grep prior art mirror EXPECTED_PRESENT 형태
set -euo pipefail

TARGET="${TARGET:-src/arch/common/entropy/virtio_rng.rs}"

# Wave 0 단계 target 파일 부재 시 fail-fast (Wave 2 신설 예정)
if [ ! -f "$TARGET" ]; then
    echo "[CI] FAIL ENTR-04 virtio_rng.rs 부재 (Wave 2 신설 예정)" >&2
    exit 1
fi

# (1) 0xFE sentinel 채움 호출 site 존재
if ! grep -nE "SENTINEL.*=.*0xFE|0xFEu8" "$TARGET" >/dev/null 2>&1; then
    echo "[CI] FAIL ENTR-04 sentinel 0xFE 채움 미감지" >&2
    exit 1
fi

# (2) ct_eq sentinel 비교 호출 site 존재 (constant_time::CtEqOps)
if ! grep -nE "ct_eq" "$TARGET" >/dev/null 2>&1; then
    echo "[CI] FAIL ENTR-04 ct_eq sentinel verify-changed 미감지" >&2
    exit 1
fi

# (3) zeroize 강제 소거 회귀
if ! grep -nE "zeroize\(\)" "$TARGET" >/dev/null 2>&1; then
    echo "[CI] FAIL 5-게이트 Zeroize 의무 누락" >&2
    exit 1
fi

echo "[CI] PASS virtio sentinel + verify-changed + zeroize 3패턴 모두 감지"
exit 0
