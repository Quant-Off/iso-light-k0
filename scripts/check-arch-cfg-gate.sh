#!/usr/bin/env bash
# Phase 9 HAL-06 standing gate cfg(target_arch) 가 src/arch/ 외부 production 코드에서
# 0 으로 수렴하는지 측정
# WR-07 강화 substring grep 을 정규식으로 확장하여 cfg(all/any/not(target_arch)) 중첩
# 형태와 인라인 주석 회피를 잡는다 라인별 // 주석을 선제거한 뒤 판정하며
# production(비-debug) arch cfg 는 하드 FAIL debug_assertions 게이트 site 는
# 테스트 스캐폴딩 arch-gating 으로 정당하므로 관측 전용 분리 보고 (게이트 약화 아님
# 스캐폴딩의 arch 가드 제거는 aarch64 하드 브레이크를 유발하므로 유지가 정답)
set -euo pipefail

# src/arch/ 외부에서 target_arch 를 언급하는 파일만 후보로 수집
CFG_FILES=$(grep -rlE 'target_arch' src/ | grep -v '^src/arch/' || true)

CFG_PROD=""
CFG_SCAFFOLD=""
if [ -n "$CFG_FILES" ]; then
    # 라인별 // 주석 제거 후 cfg( 와 target_arch 를 동시 포함하면 arch cfg 로 판정
    # cfg[ \t]*\( 는 cfg(all( / cfg(any( / cfg(not( / cfg(target_arch 형태를 모두 포괄하며
    # BSD awk 호환 위해 선택적 괄호 대신 2-조건 조합을 사용함
    # debug_assertions 유무로 production / 테스트 스캐폴딩 분류
    CFG_MATCHED=$(awk '
        {
            code = $0
            sub(/\/\/.*/, "", code)
            if (code ~ /cfg[ \t]*\(/ && code ~ /target_arch/) {
                tag = (code ~ /debug_assertions/) ? "SCAFFOLD" : "PROD"
                printf "%s:%d:%s:%s\n", FILENAME, FNR, tag, code
            }
        }
    ' $CFG_FILES || true)
    CFG_PROD=$(echo "$CFG_MATCHED" | grep ':PROD:' || true)
    CFG_SCAFFOLD=$(echo "$CFG_MATCHED" | grep ':SCAFFOLD:' || true)
fi

if [ -n "$CFG_PROD" ]; then
    PCOUNT=$(echo "$CFG_PROD" | grep -c ':PROD:' | tr -d '[:space:]')
    echo "[CI] FAIL production cfg(target_arch) ${PCOUNT} sites outside src/arch/ (HAL-06 위반)" >&2
    echo "$CFG_PROD" >&2
    exit 1
fi

if [ -n "$CFG_SCAFFOLD" ]; then
    SCOUNT=$(echo "$CFG_SCAFFOLD" | grep -c ':SCAFFOLD:' | tr -d '[:space:]')
    echo "[CI]  obs debug_assertions 게이트 arch cfg ${SCOUNT} sites (테스트 스캐폴딩 arch-gating 정당 관측 전용)"
fi

# WR-02 강화 레그 src/arch/ 외부 raw inline asm 잔존 검출
# 기존 게이트는 cfg 문자열만 세어 main.rs 의 cli/sti/hlt raw asm 을 놓쳤음
# core::arch::asm! / bare asm! 사용 site 는 ISA 의존이므로 HAL 표면(src/arch/)
# 으로 이관되어야 하며 행 선두 주석은 제외함
ASM_VIOLATIONS=$(grep -rn "asm!" src/ | grep -v "src/arch/" | grep -vE ':[0-9]+:[[:space:]]*//' || true)

if [ -n "$ASM_VIOLATIONS" ]; then
    ACOUNT=$(echo "$ASM_VIOLATIONS" | wc -l | tr -d '[:space:]')
    echo "[CI] FAIL raw asm! ${ACOUNT} sites outside src/arch/ (HAL-06 ISA 표면 이관 누락 WR-02)" >&2
    echo "$ASM_VIOLATIONS" >&2
    exit 1
fi

echo "[CI] PASS production cfg(target_arch) 0 + raw asm! 0 sites outside src/arch/ (HAL-06 WR-07 all/any/not 형태 + 인라인 주석 포괄)"
exit 0
