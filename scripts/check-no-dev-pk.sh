#!/usr/bin/env bash
# 프로덕션 신뢰 루트 빌드에 dev 공개키 부재 게이트
#
# check-no-dev-sk.sh 가 dev 개인키(sk) 자료 부재를 검증하는 것과 짝을 이루어,
# 본 스크립트는 K0_TRUST_ROOT_KEYSTORE 지정 프로덕션 빌드 산출물에 dev
# 공개키(keys/trust_root.pk44, seed 0xAA*32 결정론 키)의 옥텟이 임베드되지
# 않았음을 실측한다. hsm_attest.rs 의 HSM_TRUST_ROOT_PK_CONST 가 keystore cfg 에서
# 프로덕션 PK 로 완전히 대체되므로 dev PK 는 바이너리에서 부재해야 한다.
#
# 사용
#   K0_TRUST_ROOT_KEYSTORE=<prod pk44 경로> make build-prod
#   KERNEL_BIN=target/x86_64-unknown-none/release/iso-light-k0 bash scripts/check-no-dev-pk.sh
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"
DEV_PK="${DEV_PK:-keys/trust_root.pk44}"

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[CI] FAIL: 프로덕션 바이너리가 존재하지 않음 ($KERNEL_BIN)" >&2
    echo "       K0_TRUST_ROOT_KEYSTORE=<pk44> make build-prod 후 재실행" >&2
    exit 1
fi

if [ ! -f "$DEV_PK" ]; then
    # dev pk 자체가 없으면 비교 기준 부재 자동 PASS (clean checkout)
    echo "[CI] PASS: dev pk 파일 부재 자동 통과"
    exit 0
fi

if ! command -v xxd >/dev/null 2>&1; then
    echo "[CI] FAIL: xxd가 존재하지 않음  (dev pk hex window 추출 불가)" >&2
    exit 1
fi

# dev PK 의 distinctive 256-옥텟 window (offset 32 = rho 이후 t1 자료)
# 프로덕션 PK 는 무작위이므로 이 연속 window 를 포함할 확률은 사실상 0
DEV_PK_WINDOW=$(xxd -p -s 32 -l 256 "$DEV_PK" | tr -d '\n')
if [ -z "$DEV_PK_WINDOW" ]; then
    echo "[CI] FAIL: dev pk 256-옥텟 window 추출 실패" >&2
    exit 1
fi

if xxd -p "$KERNEL_BIN" | tr -d '\n' | grep -q "$DEV_PK_WINDOW"; then
    echo "[CI] FAIL: 프로덕션 빌드에 dev 공개키 자료 leak 검출 (C1)" >&2
    echo "       HSM_TRUST_ROOT_PK_CONST 가 keystore cfg 에서 프로덕션 PK 로 대체되지 않음" >&2
    exit 1
fi

echo "[CI] PASS: 프로덕션 빌드에 dev 공개키 부재 (C1 신뢰 앵커 무결성)"
exit 0
