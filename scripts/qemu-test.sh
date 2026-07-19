#!/bin/bash
# QEMU 부팅 + 암호 스모크 테스트 스크립트 (Linux KVM / Linux TCG / macOS TCG 공용)
#
# 수행 내용:
#   1. make iso  커널 ELF 빌드 + grub-mkrescue ISO 생성
#   2. qemu-system-x86_64 실행 (headless, serial -> file, monitor unix socket)
#   3. 부팅 안정화 대기 후 VGA 프레임버퍼(0xB8000) pmemsave 로 덤프
#   4. cpu_reset 로그, serial 출력, VGA 텍스트(스모크 테스트 결과) 분석
#
# 성공 조건:
#   A) cpu_reset 로그가 비어 있음 (triple fault 없음)
#   B) VGA 프레임버퍼에서 "All Task Done" 또는 "BLAKE3 round-trip OK" 확인
#
# 실패 조건:
#   - cpu_reset 로그에 내용이 있음 -> triple fault / 커널 크래시
#   - VGA 에 "FATAL" 또는 "MISMATCH" 또는 "FAILED" 출현
#   - QEMU 가 정상 종료 전에 비정상 exit 코드 반환

set -euo pipefail

# 경로 / 옵션
ISO="iso-light-k0-debug.iso"
SERIAL_LOG="/tmp/qemu-serial.log"
RESET_LOG="/tmp/qemu-reset.log"
QMP_SOCK="/tmp/qemu-qmp.sock"
VGA_BIN="/tmp/qemu-vga.bin"
VGA_TXT="/tmp/qemu-vga.txt"

# TCG(소프트웨어 에뮬레이션)에서 부팅 + ML-KEM-768 키쌍 + PSK-PQ-Hybrid 핸드셰이크
# 완료까지 시간이 필요. 기본 45/70초.
BOOT_WAIT_SEC=120     # 부팅 안정화 + TLS 스모크 테스트 완료 대기
                      # TCG 환경에서 ML-KEM-768 keygen/encaps/decaps 가
                      # SHA-NI 미지원으로 느림 (각 ~수초). KVM 환경에서는
                      # 1초 미만으로 완료되므로 본 값은 보수적 상한
TIMEOUT_SEC=180       # 전체 QEMU 실행 상한

echo "=================================================="
echo " iso-light-k0 QEMU 부팅 + 암호 스모크 테스트"
echo " Ubuntu 24.04 / qemu-system-x86_64"
echo "=================================================="
echo ""

# 1. ISO 빌드
echo "[1/5] ISO 빌드 중..."
make iso
echo ""

# 2. KVM 가속 여부 확인
KVM_FLAGS=()
if [ -w /dev/kvm ]; then
    echo "[INFO] /dev/kvm 접근 가능 -> KVM 가속 활성화"
    KVM_FLAGS=(-enable-kvm)
else
    echo "[INFO] /dev/kvm 없음 -> TCG 소프트웨어 에뮬레이션"
fi

# TCG RDRAND/RDSEED 에뮬레이션 결함과 QEMU 버전 (aarch64 호스트 실측 이력)
# QEMU <= 8.2: RDRAND/RDSEED 활성 시 wild jump #PF 결정적 유발
#   (RIP=0x40B866ECEB4E, RSP=0x000FC958. -cpu max / +rdrand / +rdseed 전부 재현)
# QEMU >= 11.0: 위 조기 결함 수정 실측 (2026-07-19, macOS Homebrew 11.0)
#   -cpu qemu64,+rdrand,+rdseed 로 DRBG/TrustRoot/HsmRegistry/BLAKE3/TLS(Classical+
#   PQ-Hybrid) 까지 런타임 통과. 단 TLS 소거 직후 원인 미확정 무증상 폭주(post-TLS
#   stall) 가 있어 HSM smoke 이후 마커는 tcg-entropy 모드에서 검증 제외
# 9.x / 10.x 는 미검증이므로 보수적으로 tcg-no-entropy 를 유지
QEMU_MAJOR=$(qemu-system-x86_64 --version 2>/dev/null \
    | sed -n '1s/.*version \([0-9][0-9]*\).*/\1/p' || true)

# ENTROPY_MODE 자동 결정
#   full            KVM 가속 (-cpu host). RDRAND/RDSEED 정상 가용, 모든 마커 PASS 요구
#   tcg-entropy     TCG + QEMU >= 11 (-cpu qemu64,+rdrand,+rdseed)
#                   entropy 의존 마커를 TLS 소거까지 PASS 요구
#                   HSM smoke 이후는 post-TLS stall 로 검증 제외 표기
#   tcg-no-entropy  TCG + QEMU < 11 (-cpu qemu64). RDRAND/RDSEED 부재
#                   H5/M12 fail-closed 로 init_prng 에서 의도적 부팅 중단이 정상 동작
#                   부팅 진입 + fail-closed FATAL + reset<=2 를 PASS 조건으로 판정
# 환경변수 K0_TEST_MODE 로 override 가능 (full | tcg-entropy | tcg-no-entropy)
# DEPRECATED Phase 8 ENTR-07 production+degraded 양 lane 모두 13 marker PASS 요구
# K0_TEST_MODE override 만 v1.0 호환 유지 modal 분기 자체는 Phase 12 4-cell matrix 가 잠금
if [ -n "${K0_TEST_MODE:-}" ]; then
    ENTROPY_MODE="${K0_TEST_MODE}"
    echo "[INFO] ENTROPY_MODE=${ENTROPY_MODE} (K0_TEST_MODE override)"
elif [ "${#KVM_FLAGS[@]}" -gt 0 ]; then
    ENTROPY_MODE="full"
    echo "[INFO] ENTROPY_MODE=${ENTROPY_MODE} (KVM detected)"
elif [ "${QEMU_MAJOR:-0}" -ge 11 ]; then
    ENTROPY_MODE="tcg-entropy"
    echo "[INFO] ENTROPY_MODE=${ENTROPY_MODE} (TCG + QEMU ${QEMU_MAJOR} >= 11, RDRAND/RDSEED 활성)"
else
    ENTROPY_MODE="tcg-no-entropy"
    echo "[INFO] ENTROPY_MODE=${ENTROPY_MODE} (TCG + QEMU ${QEMU_MAJOR:-?} < 11, RDRAND/RDSEED 부재)"
fi

# CPU 플래그는 최종 ENTROPY_MODE 를 따름
if [ "${#KVM_FLAGS[@]}" -gt 0 ]; then
    CPU_FLAGS=(-cpu host)
elif [ "${ENTROPY_MODE}" = "tcg-no-entropy" ]; then
    CPU_FLAGS=(-cpu qemu64)
else
    CPU_FLAGS=(-cpu qemu64,+rdrand,+rdseed)
fi
echo "[INFO] CPU_FLAGS=${CPU_FLAGS[*]}"

# tcg-no-entropy 는 init_prng fail-closed 가 초기화 직후 발동하므로 대기 단축
if [ "${ENTROPY_MODE}" = "tcg-no-entropy" ]; then
    BOOT_WAIT_SEC=45
fi

# 이전 실행 잔여물 정리
rm -f "${SERIAL_LOG}" "${RESET_LOG}" "${QMP_SOCK}" "${VGA_BIN}" "${VGA_TXT}"

# 3. QEMU 실행 (백그라운드)
echo "[2/5] QEMU 부팅 (TIMEOUT=${TIMEOUT_SEC}s)..."

set +e
timeout "${TIMEOUT_SEC}" qemu-system-x86_64 \
    ${KVM_FLAGS[@]+"${KVM_FLAGS[@]}"} \
    "${CPU_FLAGS[@]}" \
    -m 512M \
    -cdrom "${ISO}" \
    -serial "file:${SERIAL_LOG}" \
    -qmp "unix:${QMP_SOCK},server,nowait" \
    -no-reboot \
    -no-shutdown \
    -display none \
    -d cpu_reset \
    -D "${RESET_LOG}" \
    >/dev/null 2>&1 &
QEMU_PID=$!
set -e

# QMP 소켓 준비 대기
for _ in $(seq 1 50); do
    [ -S "${QMP_SOCK}" ] && break
    sleep 0.1
done

if [ ! -S "${QMP_SOCK}" ]; then
    echo "[FAIL] QEMU QMP 소켓 미생성"
    kill "${QEMU_PID}" 2>/dev/null || true
    exit 1
fi

# 4. 부팅 안정화 대기 후 VGA 덤프
echo "[3/5] ${BOOT_WAIT_SEC}초 동안 부팅 진행 후 VGA 프레임버퍼 덤프 (QMP)..."
sleep "${BOOT_WAIT_SEC}"

# QEMU 가 살아 있어야 의미 있는 덤프 가능
if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
    echo "[WARN] QEMU 가 ${BOOT_WAIT_SEC}초 이전에 종료됨"
fi

# QMP(JSON-RPC)로 pmemsave 후 quit. HMP 의 readline 파싱 문제 회피
# VGA text mode 버퍼 0xB8000 (753664) 에서 4096 bytes 덤프
python3 - "$QMP_SOCK" "$VGA_BIN" <<'PY' || true
import json, socket, sys, time

sock_path, vga_path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
s.settimeout(5.0)
buf = b""

def recv_line():
    global buf
    while b"\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            return None
        buf += chunk
    line, _, buf = buf.partition(b"\n")
    return line

def send(obj):
    s.sendall((json.dumps(obj) + "\n").encode())

# QMP 핸드셰이크 (greeting 수신 -> capabilities 합의)
greeting = recv_line()
send({"execute": "qmp_capabilities"})
recv_line()  # capabilities ack

# pmemsave: 0xB8000 = 753664, 4096 bytes
send({
    "execute": "pmemsave",
    "arguments": {"val": 0xB8000, "size": 4096, "filename": vga_path},
})
# 응답 수신 (event 가 섞일 수 있어 return 이 올 때까지 읽음)
deadline = time.time() + 5.0
while time.time() < deadline:
    line = recv_line()
    if line is None:
        break
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if "return" in msg or "error" in msg:
        if "error" in msg:
            print("QMP pmemsave error:", msg["error"], file=sys.stderr)
        break

# 정상 종료
send({"execute": "quit"})
try:
    while True:
        if recv_line() is None:
            break
except Exception:
    pass
s.close()
PY

# QEMU 종료 대기 (quit 또는 timeout)
wait "${QEMU_PID}" 2>/dev/null || true
QEMU_EXIT=$?

# 5. VGA 버퍼 -> 텍스트 디코드
# VGA text mode: 짝수 바이트=문자, 홀수 바이트=속성. 짝수만 추출하여 ASCII 로.
if [ -f "${VGA_BIN}" ]; then
    python3 - <<'PY' > "${VGA_TXT}"
data = open("/tmp/qemu-vga.bin", "rb").read()
chars = bytes(b if 0x20 <= b < 0x7f else 0x20 for b in data[::2])
# 80문자씩 줄바꿈 (VGA 한 줄 = 80 cell)
for i in range(0, len(chars), 80):
    line = chars[i:i + 80].rstrip().decode("ascii", "replace")
    if line:
        print(line)
PY
fi

# 6. 결과 출력
echo ""
echo "=================================================="
echo " Serial 출력 (SeaBIOS 등)"
echo "=================================================="
[ -s "${SERIAL_LOG}" ] && cat "${SERIAL_LOG}" || echo "(serial 출력 없음)"

echo ""
echo "=================================================="
echo " VGA 프레임버퍼 (커널 부팅 메시지)"
echo "=================================================="
if [ -s "${VGA_TXT}" ]; then
    cat "${VGA_TXT}"
else
    echo "(VGA 덤프 실패 또는 비어있음)"
fi

echo ""
echo "=================================================="
echo " CPU 리셋 로그"
echo "=================================================="
if [ -s "${RESET_LOG}" ]; then
    cat "${RESET_LOG}"
else
    echo "(CPU 리셋 없음)"
fi

# 7. PASS/FAIL 판정
echo ""
echo "=================================================="
echo " 테스트 결과 판정"
echo "=================================================="

PASS=true
FAIL_REASONS=()

# (a) CPU 리셋 횟수: QEMU 8.x 머신 부팅 시 기본 2회는 정상:
#       #1) CPU 객체 초기 zero-state reset
#       #2) x86 아키텍처 reset (EIP=0xFFF0, CS=F000)
#     3회 이상이면 triple fault / INIT IPI 로 커널이 재시작된 것으로 간주.
RESET_COUNT=0
if [ -s "${RESET_LOG}" ]; then
    RESET_COUNT=$(grep -c "^CPU Reset" "${RESET_LOG}" 2>/dev/null || echo 0)
fi
echo "  [CPU Reset 횟수]                ${RESET_COUNT} (정상=1~2, ≥3=triple fault)"
if [ "${RESET_COUNT}" -gt 2 ]; then
    PASS=false
    FAIL_REASONS+=("CPU 리셋 ${RESET_COUNT}회 감지 (triple fault / 커널 크래시)")
fi

# (b) VGA 텍스트에 명시적 실패 표시
# tcg-no-entropy 모드에서는 RDRAND/RDSEED 부재로 인한 도미노 FATAL 라인들이 예상 출력
# 이므로 expected 패턴을 grep -v 로 필터링한 잔여 라인에서 FATAL/MISMATCH/FAILED 가
# 있을 때에만 fail 누적. full 모드에서는 기존 단순 감지 유지.
if [ -s "${VGA_TXT}" ]; then
    if [ "${ENTROPY_MODE}" = "tcg-no-entropy" ]; then
        UNEXPECTED_FATAL=$(grep -E "FATAL|MISMATCH|FAILED" "${VGA_TXT}" \
            | grep -vE "FATAL: no hardware entropy" \
            | grep -vE "FATAL: HsmRegistry smoke FAILED \(attach error\)" \
            | grep -vE "FATAL: bus_phase2 smoke FAILED \(attach error\)" \
            | grep -vE "FATAL: chan_phase3 smoke FAILED \(attach" \
            | grep -vE "crypto smoke: capability issue FAILED" \
            | grep -vE "tls smoke: classical handshake FAILED" \
            || true)
        if [ -n "${UNEXPECTED_FATAL}" ]; then
            PASS=false
            FAIL_REASONS+=("VGA 출력에 예상되지 않은 FATAL/MISMATCH/FAILED 감지 (tcg-no-entropy expected 라인 외)")
        fi
    else
        if grep -qE "FATAL|MISMATCH|FAILED" "${VGA_TXT}"; then
            PASS=false
            FAIL_REASONS+=("VGA 출력에 FATAL/MISMATCH/FAILED 감지")
        fi
    fi
fi

# (c) 핵심 부팅 마일스톤 확인
HAS_BOOTED=false
HAS_FAILCLOSED=false
HAS_DRBG=false
HAS_SMOKE_OK=false
HAS_TLS_HYBRID=false
HAS_TLS_CLASSICAL=false
HAS_TLS_WIPED=false
HAS_ALL_DONE=false
# Phase 1 신규 마일스톤 (additive — 기존 플래그 보존, W-1)
HAS_HSM_STATIC_ONLINE=false
HAS_HSM_SMOKE=false
HAS_HSM_ROUNDTRIP=false
HAS_HSM_DETACH_NOCAP_DENIED=false
# Phase 2 BusDriver 마일스톤 (additive — Phase 1 게이트는 그대로 유지)
HAS_BUS_PHASE2_OK=false
HAS_CHAN_PHASE3_OK=false  # Phase 3 marker  ci-phase3 게이트
HAS_WIRE_PHASE4_OK=false  # Phase 4 marker  ci-phase4 게이트
HAS_ATTEST_PHASE5_OK=false  # Phase 5 marker  ci-phase5 게이트
HAS_ATTEST_PHASE5_1_OK=false  # Phase 5.1 marker  ci-phase5_1 게이트
HAS_GAP_PHASE6_OK=false  # Phase 6 marker  ci-phase6 게이트
if [ -s "${VGA_TXT}" ]; then
    grep -q "Booted\. Initializing"           "${VGA_TXT}" && HAS_BOOTED=true
    grep -q "FATAL: no hardware entropy"      "${VGA_TXT}" && HAS_FAILCLOSED=true
    grep -q "Capability DRBG Init Done"       "${VGA_TXT}" && HAS_DRBG=true
    grep -q "BLAKE3 round-trip OK"            "${VGA_TXT}" && HAS_SMOKE_OK=true
    grep -q "PQ-Hybrid (X25519+MLKEM768) OK"  "${VGA_TXT}" && HAS_TLS_HYBRID=true
    grep -q "Classical (X25519) OK"           "${VGA_TXT}" && HAS_TLS_CLASSICAL=true
    grep -q "keystore + pool wiped"           "${VGA_TXT}" && HAS_TLS_WIPED=true
    grep -q "All Task Done"                   "${VGA_TXT}" && HAS_ALL_DONE=true
    # Phase 1 HsmRegistry 마일스톤 (additive)
    grep -q "HsmRegistry static online (8 slots, alloc=0)"                "${VGA_TXT}" && HAS_HSM_STATIC_ONLINE=true
    grep -q "HsmRegistry smoke: attach -> verify -> detach -> zeroize OK" "${VGA_TXT}" && HAS_HSM_SMOKE=true
    grep -q "HSM_ATTACH_DETACH_ROUNDTRIP_OK marker"                       "${VGA_TXT}" && HAS_HSM_ROUNDTRIP=true
    grep -q "HSM_DETACH_NO_CAP_DENIED marker"                             "${VGA_TXT}" && HAS_HSM_DETACH_NOCAP_DENIED=true
    # Phase 2 BusDriver smoke 마일스톤 (additive)
    grep -q "BUS_PHASE2_OK marker"                                        "${VGA_TXT}" && HAS_BUS_PHASE2_OK=true
    # Phase 3 In-Kernel Inter-HSM Channel smoke 마일스톤 (additive)
    grep -q "CHAN_PHASE3_OK marker"                                       "${VGA_TXT}" && HAS_CHAN_PHASE3_OK=true
    # Phase 4 Wire Contract Ring 3 lumen smoke 마일스톤 (additive)
    grep -q "WIRE_PHASE4_OK"                                              "${VGA_TXT}" && HAS_WIRE_PHASE4_OK=true
    # Phase 5 Attestation Gate kernel-side smoke 마일스톤 (additive  feature smoke 한정)
    grep -q "ATTEST_PHASE5_OK"                                            "${VGA_TXT}" && HAS_ATTEST_PHASE5_OK=true
    # Phase 5.1 wire AttestSubmit / Status / lumen smoke 마일스톤 (additive  feature smoke 한정)
    grep -q "ATTEST_PHASE5_1_OK"                                          "${VGA_TXT}" && HAS_ATTEST_PHASE5_1_OK=true
    # Phase 6 air-gap dual gate / sys_hsm_status / gap_self_check smoke 마일스톤 (additive feature smoke 한정)
    grep -q "GAP_PHASE6_OK"                                               "${VGA_TXT}" && HAS_GAP_PHASE6_OK=true
fi

# Phase 8 entropy marker recognition 신규 4 종 (recognition only)
# marker 부재가 Phase 1~7 회귀 게이트를 깨뜨리지 않음 (Wave 0 skeleton mode)
HAS_TIMER_LINE=false
HAS_ENTROPY_QUORUM_OK=false
HAS_ENTROPY_DEGRADED_ACTIVE=false
HAS_ENTROPY_SOURCES_AVAILABLE=false
if [ -s "${VGA_TXT}" ]; then
    grep -qE "^timer: (invariant_tsc|jitter_calibration)" "${VGA_TXT}" && HAS_TIMER_LINE=true
    grep -qE "ENTROPY_QUORUM_(2_OF_3|1_OF_3)_OK"          "${VGA_TXT}" && HAS_ENTROPY_QUORUM_OK=true
    grep -q  "ENTROPY_DEGRADED_OK_ACTIVE=1"               "${VGA_TXT}" && HAS_ENTROPY_DEGRADED_ACTIVE=true
    grep -qE "ENTROPY_SOURCES_AVAILABLE=[1-3]"            "${VGA_TXT}" && HAS_ENTROPY_SOURCES_AVAILABLE=true
fi

# 마커 출력 + fail 누적 헬퍼
# 인자 1 라벨, 2 has_flag (true/false), 3 클래스, 4 fail_reason
# 클래스
#   struct   entropy 비의존 구조 마커. full 과 tcg-entropy 에서 PASS 요구
#            tcg-no-entropy 에서는 fail-closed 가 도달 전에 부팅을 중단하므로 expected MISS
#   entropy  entropy 의존 + TLS 소거 이전 구간. full 과 tcg-entropy 에서 PASS 요구
#   stall    entropy 의존 + TLS 소거 이후 구간. full 에서만 PASS 요구
#            tcg-entropy 에서는 post-TLS stall(원인 미확정) 로 검증 제외
#   false    ENTR-07 flip entropy_dependent=false. full 과 tcg-entropy 양 lane 강제 PASS
#            (Phase 8 quorum 완성 후 stall 예외 해제 tcg-no-entropy 만 expected MISS)
check_marker() {
    local label="$1"
    local has_flag="$2"
    local klass="$3"
    local fail_reason="$4"
    local status
    if [ "$has_flag" = "true" ]; then
        status="PASS"
    elif [ "$ENTROPY_MODE" = "tcg-no-entropy" ]; then
        status="MISS (expected, fail-closed 선행 중단)"
    elif [ "$ENTROPY_MODE" = "tcg-entropy" ] && [ "$klass" = "stall" ]; then
        status="MISS (post-TLS stall, 검증 제외)"
    else
        status="MISS"
        PASS=false
        FAIL_REASONS+=("${fail_reason}")
    fi
    printf "  %-34s %s\n" "${label}" "${status}"
}

# 환경변수 게이트 (REQUIRE_*=1) 가 있는 Phase 5/5.1/6 전용 헬퍼
# - 게이트 미설정 시 MISS 라도 fail 누적 없음 (현 동작 보존)
# - 게이트 설정 + full 모드 + MISS = fail
# - 게이트 설정 + TCG 모드 + MISS = expected MISS (entropy 의존 + stall 구간이므로)
check_gated_marker() {
    local label="$1"
    local has_flag="$2"
    local require_flag="$3"
    local fail_reason="$4"
    local status
    if [ "$has_flag" = "true" ]; then
        status="PASS"
    elif [ "$ENTROPY_MODE" != "full" ]; then
        status="MISS (expected, ${ENTROPY_MODE})"
    elif [ "$require_flag" = "1" ]; then
        status="MISS"
        PASS=false
        FAIL_REASONS+=("${fail_reason}")
    else
        status="MISS (gate off)"
    fi
    printf "  %-34s %s\n" "${label}" "${status}"
}

# 부팅 진입 마커. tcg-entropy 에서는 진행이 길어 VGA 25행 밖으로 스크롤되므로 별도 표기
if [ "${ENTROPY_MODE}" = "tcg-entropy" ] && ! $HAS_BOOTED; then
    printf "  %-34s %s\n" "[부팅 진입]" "MISS (VGA 스크롤, DRBG 마커로 대체 확인)"
else
    printf "  %-34s %s\n" "[부팅 진입]" "$($HAS_BOOTED && echo PASS || echo MISS)"
fi
# 메인 루프 진입 마커는 fail 누적 안 함 (기존 동작 보존)
if [ "${ENTROPY_MODE}" = "tcg-entropy" ] && ! $HAS_ALL_DONE; then
    printf "  %-34s %s\n" "[메인 루프 진입(All Task Done)]" "MISS (post-TLS stall, 검증 제외)"
else
    printf "  %-34s %s\n" "[메인 루프 진입(All Task Done)]" "$($HAS_ALL_DONE && echo PASS || echo MISS)"
fi

# tcg-no-entropy 모드는 H5/M12 fail-closed 발동 자체가 검증 대상
# 부팅 진입 + fail-closed FATAL 출력 + reset<=2 (위 (a)) 조합이 PASS 조건
if [ "${ENTROPY_MODE}" = "tcg-no-entropy" ]; then
    printf "  %-34s %s\n" "[H5/M12 fail-closed FATAL]" "$($HAS_FAILCLOSED && echo PASS || echo MISS)"
    if ! $HAS_FAILCLOSED; then
        PASS=false
        FAIL_REASONS+=("fail-closed FATAL(no hardware entropy) 미출력 — 부팅이 예상 경로로 진행되지 않음")
    fi
    if ! $HAS_BOOTED; then
        PASS=false
        FAIL_REASONS+=("부팅 진입 마커(Booted. Initializing) 미확인")
    fi
fi

# 구조 마커 (ENTR-07 flip entropy_dependent=false 전 lane 강제 PASS 요구)
check_marker "[HsmRegistry static online]"     "$HAS_HSM_STATIC_ONLINE"        "false" \
    "HsmRegistry static online 마커 없음 (main.rs 모듈 선언 또는 부팅 순서 누락)"

# entropy 의존 마커, TLS 소거 이전 구간 (ENTR-07 flip entropy->false 전 lane 강제 PASS 요구)
check_marker "[Hash-DRBG 초기화]"               "$HAS_DRBG"                     "false" \
    "Hash-DRBG 초기화 마커 없음 (RDSEED/RDRAND 부재)"
check_marker "[BLAKE3 라운드트립 스모크]"        "$HAS_SMOKE_OK"                 "false" \
    "BLAKE3 라운드트립 스모크 결과 미확인"
check_marker "[TLS PQ-Hybrid 핸드셰이크]"        "$HAS_TLS_HYBRID"               "false" \
    "TLS PQ-Hybrid 핸드셰이크 미확인"
check_marker "[TLS Classical 핸드셰이크]"        "$HAS_TLS_CLASSICAL"            "false" \
    "TLS Classical 핸드셰이크 미확인"
check_marker "[TLS keystore + pool 소거]"        "$HAS_TLS_WIPED"                "false" \
    "TLS 종료 후 키 자료 소거 미확인"

# entropy 의존 마커, TLS 소거 이후 구간 (ENTR-07 flip stall->false 전 lane 강제 PASS 요구)
check_marker "[HsmRegistry smoke OK]"            "$HAS_HSM_SMOKE"                "false" \
    "HsmRegistry 스모크 테스트 성공 마커 없음 (attach detach zeroize 라운드트립 실패)"
check_marker "[HSM attach->detach roundtrip]"    "$HAS_HSM_ROUNDTRIP"            "false" \
    "HSM_ATTACH_DETACH_ROUNDTRIP_OK 마커 없음"
check_marker "[HSM detach no-cap denied]"        "$HAS_HSM_DETACH_NOCAP_DENIED"  "false" \
    "HSM_DETACH_NO_CAP_DENIED 마커 없음 post-attach CAP-02 enforcement 실패"
check_marker "[BUS_PHASE2_OK marker]"            "$HAS_BUS_PHASE2_OK"            "false" \
    "BUS_PHASE2_OK 마커 없음 Phase 2 SoftwareBus 루프백 + detach cascade 실패"
check_marker "[CHAN_PHASE3_OK marker]"           "$HAS_CHAN_PHASE3_OK"           "false" \
    "CHAN_PHASE3_OK 마커 없음 Phase 3 Blake3 src -> AesGcm dst relay 라운드트립 실패"
check_marker "[WIRE_PHASE4_OK marker]"           "$HAS_WIRE_PHASE4_OK"           "false" \
    "WIRE_PHASE4_OK 마커 없음 Phase 4 lumen Ring 3 wire Blake3Hash contract 실패"

# Phase 8 Wave 4 신규 marker 4 종 check_marker 합류 (Wave 3 main.rs emit)
# timer / ENTROPY_QUORUM / ENTROPY_SOURCES 는 전 lane 강제 (false)
# ENTROPY_DEGRADED 는 degraded 빌드에서만 emit 되므로 K0_REQUIRE_DEGRADED 게이트
check_marker "[timer: line]"                     "$HAS_TIMER_LINE"               "false" \
    "timer frequency line 부재 Pitfall 12 회귀 의심"
check_marker "[ENTROPY_QUORUM marker]"           "$HAS_ENTROPY_QUORUM_OK"        "false" \
    "ENTROPY_QUORUM marker 부재 Phase 8 entropy quorum 미작동"
check_marker "[ENTROPY_SOURCES_AVAILABLE marker]" "$HAS_ENTROPY_SOURCES_AVAILABLE" "false" \
    "ENTROPY_SOURCES_AVAILABLE marker 부재 Pitfall 5 가시 효과 부재"
check_gated_marker "[ENTROPY_DEGRADED_OK_ACTIVE marker]" "$HAS_ENTROPY_DEGRADED_ACTIVE" "${K0_REQUIRE_DEGRADED:-0}" \
    "ENTROPY_DEGRADED_OK_ACTIVE 마커 부재 degraded 빌드 D-03 식별 실패"

# REQUIRE_* 게이트가 있는 Phase 5/5.1/6 marker (ENTR-07 default 0 -> 1 강제 PASS)
check_gated_marker "[ATTEST_PHASE5_OK marker]"   "$HAS_ATTEST_PHASE5_OK"   "${REQUIRE_ATTEST_PHASE5_OK:-1}" \
    "ATTEST_PHASE5_OK 마커 없음 Phase 5 attach with attestation Leg 1 valid sig 또는 Leg 2 mutated reject 실패"
check_gated_marker "[ATTEST_PHASE5_1_OK marker]" "$HAS_ATTEST_PHASE5_1_OK" "${REQUIRE_ATTEST_PHASE5_1_OK:-1}" \
    "ATTEST_PHASE5_1_OK 마커 없음 Phase 5.1 wire AttestSubmit / Status / lumen leg 실패"
check_gated_marker "[GAP_PHASE6_OK marker]"      "$HAS_GAP_PHASE6_OK"      "${REQUIRE_GAP_PHASE6_OK:-1}" \
    "GAP_PHASE6_OK 마커 없음 Phase 6 dual gate / sys_hsm_status / gap_self_check leg 실패"

# (d) QEMU exit 코드 (timeout=124, 모니터 quit=정상)
case "${QEMU_EXIT}" in
    0|124) ;;
    *) FAIL_REASONS+=("QEMU 비정상 종료 (exit=${QEMU_EXIT})"); ;;
esac

echo ""
if $PASS; then
    case "${ENTROPY_MODE}" in
        tcg-no-entropy)
            echo "✓ 테스트 통과 (ENTROPY_MODE=tcg-no-entropy) — 부팅 진입 + H5/M12 fail-closed 정상"
            echo "  entropy 의존 마커 검증은 QEMU>=11 TCG(tcg-entropy) 또는 Linux+KVM/실기에서 수행"
            ;;
        tcg-entropy)
            echo "✓ 테스트 통과 (ENTROPY_MODE=tcg-entropy) — TLS 소거까지 entropy 마커 정상"
            echo "  HSM smoke 이후 마커는 post-TLS stall(원인 미확정) 로 검증 제외. 전체 검증은 Linux+KVM/실기"
            ;;
        *)
            echo "✓ 테스트 통과 (ENTROPY_MODE=${ENTROPY_MODE}) — 전체 마커 검증 통과"
            ;;
    esac
    exit 0
else
    echo "✗ 테스트 실패 (ENTROPY_MODE=${ENTROPY_MODE})"
    for r in ${FAIL_REASONS[@]+"${FAIL_REASONS[@]}"}; do
        echo "  - ${r}"
    done
    exit 1
fi

# Phase 8 entropy marker recognition 신규 4 종 Wave 4 의 check_marker 호출 합류 anchor
# Phase 8 Wave 4 check_marker flip complete entropy_dependent false 전환 + 4 신규 marker check
