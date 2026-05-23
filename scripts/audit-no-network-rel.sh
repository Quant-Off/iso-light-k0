#!/usr/bin/env bash
# Phase 7 AUDIT-03 audit-time 1회 재증명 wrapper
# Phase 6 check-no-network.sh CI standing gate 와 분리
# 본 스크립트는 .planning/audit/airgap-reproof.log 에 evidence emit
# Issue 5 fallback chain 모든 분기에서 -C / --demangle 강제
#   ㄴ 패턴 `air_gap..network` 는 DEMANGLED 형태에만 매치
#   ㄴ mangled 심볼 false-positive PASS 차단 (AUDIT-03 중앙 보안 게이트 soundness)
set -euo pipefail

KERNEL_BIN="${KERNEL_BIN:-target/x86_64-unknown-none/release/iso-light-k0}"
LOG_OUT="${LOG_OUT:-.planning/audit/airgap-reproof.log}"

# 로그 디렉토리 보장
mkdir -p "$(dirname "$LOG_OUT")"

# 공통 메타 수집
PHASE="07"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
BUILD_CMD="cargo build --release --target x86_64-unknown-none"

# 빌드 실행 closed 프로필 default features only (NO --features tls-external)
# 실패 시 evidence log 에 BUILD_EXIT 기록 후 즉시 종료
set +e
$BUILD_CMD
BUILD_EXIT=$?
set -e

if [ "$BUILD_EXIT" -ne 0 ]; then
    {
        echo "# Phase 7 AUDIT-03 air-gap dual-gate re-proof evidence"
        echo "PHASE: $PHASE"
        echo "GENERATED_AT: $GENERATED_AT"
        echo "COMMIT: $COMMIT"
        echo "BUILD_CMD: $BUILD_CMD"
        echo "BUILD_EXIT: $BUILD_EXIT"
        echo "VERDICT: FAIL (build failure)"
    } > "$LOG_OUT"
    echo "[CI] FAIL audit-time air-gap dual-gate re-proof 빌드 실패 (exit $BUILD_EXIT) see $LOG_OUT" >&2
    exit 1
fi

# 산출 바이너리 존재 확인
if [ ! -f "$KERNEL_BIN" ]; then
    {
        echo "# Phase 7 AUDIT-03 air-gap dual-gate re-proof evidence"
        echo "PHASE: $PHASE"
        echo "GENERATED_AT: $GENERATED_AT"
        echo "COMMIT: $COMMIT"
        echo "BUILD_CMD: $BUILD_CMD"
        echo "BUILD_EXIT: $BUILD_EXIT"
        echo "KERNEL_BIN: $KERNEL_BIN"
        echo "VERDICT: FAIL (binary not found)"
    } > "$LOG_OUT"
    echo "[CI] FAIL closed 프로필 바이너리 미존재 $KERNEL_BIN see $LOG_OUT" >&2
    exit 1
fi

# 심볼 덤프 폴백 체인
# objdump (Linux/CI/macOS Apple LLVM) gobjdump (Homebrew binutils) nm --demangle (BSD/macOS)
# Issue 5 모든 분기 -C / --demangle 강제 mangled 심볼 false-positive PASS 차단
DUMP_CMD=""
if command -v objdump >/dev/null 2>&1; then
    DUMP_CMD="objdump -C --syms"     # -C 은 --demangle alias (binutils GNU LLVM 공통)
elif command -v gobjdump >/dev/null 2>&1; then
    DUMP_CMD="gobjdump -C --syms"    # Homebrew binutils 동일 flag
elif command -v nm >/dev/null 2>&1; then
    DUMP_CMD="nm --demangle"         # BSD/macOS nm -C 도 GNU nm 에서 동등
else
    {
        echo "# Phase 7 AUDIT-03 air-gap dual-gate re-proof evidence"
        echo "PHASE: $PHASE"
        echo "GENERATED_AT: $GENERATED_AT"
        echo "COMMIT: $COMMIT"
        echo "BUILD_CMD: $BUILD_CMD"
        echo "BUILD_EXIT: $BUILD_EXIT"
        echo "KERNEL_BIN: $KERNEL_BIN"
        echo "VERDICT: FAIL (binutils missing)"
    } > "$LOG_OUT"
    echo "[CI] FAIL objdump gobjdump nm 모두 미존재 binutils 설치 필요 see $LOG_OUT" >&2
    echo "       macOS brew install binutils 후 gobjdump 사용 가능" >&2
    exit 1
fi

# 바이너리 크기 및 SHA-256
KERNEL_BIN_SIZE="$(wc -c < "$KERNEL_BIN" | tr -d ' ')"
if command -v sha256sum >/dev/null 2>&1; then
    KERNEL_BIN_SHA256="$(sha256sum "$KERNEL_BIN" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    KERNEL_BIN_SHA256="$(shasum -a 256 "$KERNEL_BIN" | awk '{print $1}')"
else
    KERNEL_BIN_SHA256="UNKNOWN"
fi

# Phase 6 5 patterns + Plan 03 2 추가 (NETWORK_ATTACH 발급 경로 defense-in-depth)
# 7 patterns 전체 demangled 출력에 대해 매치
EXPECTED_ABSENT=(
    "NETWORK_ATTACH_CAP"          # (1) BSS static D-02 토큰 저장
    "NETWORK_CAP_STATE"           # (2) BSS static D-02 FSM enum
    "init_network_cap"            # (3) CAP_DRBG 2x 호출 site
    "take_network_cap"            # (4) sys_network_cap_take handler 본문
    "air_gap..network"            # (5) 모듈 path regex DEMANGLED 필수
    "handle_attach.*Network"      # (6) Plan 03 추가 D-01 dispatch 본문
    "gen_token_u64.*air_gap"      # (7) Plan 03 추가 CAP_DRBG → air_gap 경계
)

# 덤프 출력 1회 캐시 (반복 호출 비용 절감)
DUMP_OUTPUT="$($DUMP_CMD "$KERNEL_BIN" 2>/dev/null || true)"

PATTERNS_MATCHED=0
PER_PATTERN_LINES=()
PER_PATTERN_DETAIL=()

idx=0
for sym in "${EXPECTED_ABSENT[@]}"; do
    idx=$((idx + 1))
    HITS="$(printf '%s\n' "$DUMP_OUTPUT" | grep -cE "$sym" || true)"
    PER_PATTERN_LINES+=("[$idx] $sym: $HITS hits")
    if [ "$HITS" -gt 0 ]; then
        PATTERNS_MATCHED=$((PATTERNS_MATCHED + 1))
        MATCH_DETAIL="$(printf '%s\n' "$DUMP_OUTPUT" | grep -nE "$sym" || true)"
        PER_PATTERN_DETAIL+=("--- pattern [$idx] $sym matched lines ---")
        PER_PATTERN_DETAIL+=("$MATCH_DETAIL")
    fi
done

if [ "$PATTERNS_MATCHED" -eq 0 ]; then
    VERDICT="PASS"
else
    VERDICT="FAIL"
fi

# Evidence log 작성
{
    echo "# Phase 7 AUDIT-03 air-gap dual-gate re-proof evidence"
    echo "PHASE: $PHASE"
    echo "GENERATED_AT: $GENERATED_AT"
    echo "COMMIT: $COMMIT"
    echo "BUILD_CMD: $BUILD_CMD"
    echo "BUILD_EXIT: $BUILD_EXIT"
    echo "DUMP_TOOL: $DUMP_CMD"
    echo "KERNEL_BIN: $KERNEL_BIN"
    echo "KERNEL_BIN_SIZE: $KERNEL_BIN_SIZE"
    echo "KERNEL_BIN_SHA256: $KERNEL_BIN_SHA256"
    echo "PATTERNS_SEARCHED: 7"
    echo "PATTERNS_MATCHED: $PATTERNS_MATCHED"
    echo "--- per-pattern detail ---"
    for line in "${PER_PATTERN_LINES[@]}"; do
        echo "$line"
    done
    echo "--- end ---"
    if [ "${#PER_PATTERN_DETAIL[@]}" -gt 0 ]; then
        echo ""
        echo "--- matched-symbol detail (FAIL diagnostic) ---"
        for line in "${PER_PATTERN_DETAIL[@]}"; do
            echo "$line"
        done
        echo "--- end matched-symbol detail ---"
    fi
    echo "VERDICT: $VERDICT"
} > "$LOG_OUT"

if [ "$VERDICT" = "PASS" ]; then
    echo "[CI] PASS audit-time air-gap dual-gate re-proof (AUDIT-03 verified, log: $LOG_OUT)"
    exit 0
fi

echo "[CI] FAIL audit-time air-gap dual-gate re-proof Phase 6 dual-gate 회귀 검출 see $LOG_OUT" >&2
exit 1
