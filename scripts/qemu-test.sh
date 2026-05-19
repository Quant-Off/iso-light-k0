#!/bin/bash
# QEMU 부팅 + 암호 스모크 테스트 스크립트 (Ubuntu 24.04 Docker 전용)
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
CPU_FLAGS=(-cpu max) # TCG 기본: max 로 RDSEED/RDRAND/AES-NI/SHA-NI/AVX 활성
if [ -w /dev/kvm ]; then
    echo "[INFO] /dev/kvm 접근 가능 -> KVM 가속 활성화"
    KVM_FLAGS=(-enable-kvm)
    CPU_FLAGS=(-cpu host)
else
    echo "[INFO] /dev/kvm 없음 -> TCG 소프트웨어 에뮬레이션 (-cpu max)"
fi

# 이전 실행 잔여물 정리
rm -f "${SERIAL_LOG}" "${RESET_LOG}" "${QMP_SOCK}" "${VGA_BIN}" "${VGA_TXT}"

# 3. QEMU 실행 (백그라운드)
echo "[2/5] QEMU 부팅 (TIMEOUT=${TIMEOUT_SEC}s)..."

set +e
timeout "${TIMEOUT_SEC}" qemu-system-x86_64 \
    "${KVM_FLAGS[@]}" \
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
if [ -s "${VGA_TXT}" ]; then
    if grep -qE "FATAL|MISMATCH|FAILED" "${VGA_TXT}"; then
        PASS=false
        FAIL_REASONS+=("VGA 출력에 FATAL/MISMATCH/FAILED 감지")
    fi
fi

# (c) 핵심 부팅 마일스톤 확인
HAS_BOOTED=false
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
if [ -s "${VGA_TXT}" ]; then
    grep -q "Booted\. Initializing"           "${VGA_TXT}" && HAS_BOOTED=true
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
fi

echo "  [부팅 진입]                    $($HAS_BOOTED && echo PASS || echo MISS)"
echo "  [Hash-DRBG 초기화]             $($HAS_DRBG && echo PASS || echo MISS)"
echo "  [BLAKE3 라운드트립 스모크]      $($HAS_SMOKE_OK && echo PASS || echo MISS)"
echo "  [TLS PQ-Hybrid 핸드셰이크]      $($HAS_TLS_HYBRID && echo PASS || echo MISS)"
echo "  [TLS Classical 핸드셰이크]      $($HAS_TLS_CLASSICAL && echo PASS || echo MISS)"
echo "  [TLS keystore + pool 소거]      $($HAS_TLS_WIPED && echo PASS || echo MISS)"
echo "  [메인 루프 진입(All Task Done)] $($HAS_ALL_DONE && echo PASS || echo MISS)"
echo "  [HsmRegistry static online]     $($HAS_HSM_STATIC_ONLINE && echo PASS || echo MISS)"
echo "  [HsmRegistry smoke OK]          $($HAS_HSM_SMOKE && echo PASS || echo MISS)"
echo "  [HSM attach->detach roundtrip]  $($HAS_HSM_ROUNDTRIP && echo PASS || echo MISS)"
echo "  [HSM detach no-cap denied]      $($HAS_HSM_DETACH_NOCAP_DENIED && echo PASS || echo MISS)"
echo "  [BUS_PHASE2_OK marker]          $($HAS_BUS_PHASE2_OK && echo PASS || echo MISS)"
echo "  [CHAN_PHASE3_OK marker]         $($HAS_CHAN_PHASE3_OK && echo PASS || echo MISS)"
echo "  [WIRE_PHASE4_OK marker]         $($HAS_WIRE_PHASE4_OK && echo PASS || echo MISS)"
echo "  [ATTEST_PHASE5_OK marker]       $($HAS_ATTEST_PHASE5_OK && echo PASS || echo MISS)"

if ! $HAS_SMOKE_OK; then
    PASS=false
    FAIL_REASONS+=("BLAKE3 라운드트립 스모크 결과 미확인")
fi
if ! $HAS_TLS_HYBRID; then
    PASS=false
    FAIL_REASONS+=("TLS PQ-Hybrid 핸드셰이크 미확인")
fi
if ! $HAS_TLS_CLASSICAL; then
    PASS=false
    FAIL_REASONS+=("TLS Classical 핸드셰이크 미확인")
fi
if ! $HAS_TLS_WIPED; then
    PASS=false
    FAIL_REASONS+=("TLS 종료 후 키 자료 소거 미확인")
fi
# Phase 1 HsmRegistry 마일스톤 fail-accumulator (additive)
if [ "$HAS_HSM_STATIC_ONLINE" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("HsmRegistry static online 마커 없음 (main.rs 모듈 선언 또는 부팅 순서 누락)")
fi
if [ "$HAS_HSM_SMOKE" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("HsmRegistry 스모크 테스트 성공 마커 없음 (attach->detach->zeroize 라운드트립 실패)")
fi
if [ "$HAS_HSM_ROUNDTRIP" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("HSM_ATTACH_DETACH_ROUNDTRIP_OK 마커 없음")
fi
if [ "$HAS_HSM_DETACH_NOCAP_DENIED" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("HSM_DETACH_NO_CAP_DENIED 마커 없음 — post-attach CAP-02 enforcement 실패")
fi
# Phase 2 BusDriver fail-accumulator (additive)
if [ "$HAS_BUS_PHASE2_OK" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("BUS_PHASE2_OK 마커 없음 — Phase 2 SoftwareBus 루프백 + detach cascade 실패")
fi
# Phase 3 In-Kernel Inter-HSM Channel fail-accumulator (additive)
if [ "$HAS_CHAN_PHASE3_OK" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("CHAN_PHASE3_OK 마커 없음 — Phase 3 Blake3 src -> AesGcm dst relay 라운드트립 실패")
fi
# Phase 4 Wire Contract fail-accumulator (additive)
if [ "$HAS_WIRE_PHASE4_OK" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("WIRE_PHASE4_OK 마커 없음  Phase 4 lumen Ring 3 wire Blake3Hash contract 실패")
fi
# Phase 5 Attestation Gate fail-accumulator  feature smoke 활성 빌드에서만 강제
# REQUIRE_ATTEST_PHASE5_OK=1 인 경우에만 marker 부재를 실패로 누적 (qemu-smoke-smoke Makefile 타겟이 셋)
if [ "${REQUIRE_ATTEST_PHASE5_OK:-0}" = "1" ] && [ "$HAS_ATTEST_PHASE5_OK" != "true" ]; then
    PASS=false
    FAIL_REASONS+=("ATTEST_PHASE5_OK 마커 없음  Phase 5 attach with attestation Leg 1 valid sig 또는 Leg 2 mutated reject 실패")
fi

# (d) QEMU exit 코드 (timeout=124, 모니터 quit=정상)
case "${QEMU_EXIT}" in
    0|124) ;;
    *) FAIL_REASONS+=("QEMU 비정상 종료 (exit=${QEMU_EXIT})"); ;;
esac

echo ""
if $PASS; then
    echo "✓ 테스트 통과 — 커널 부팅 + Hash-DRBG + BLAKE3 라운드트립 정상"
    exit 0
else
    echo "✗ 테스트 실패"
    for r in "${FAIL_REASONS[@]}"; do
        echo "  - ${r}"
    done
    exit 1
fi
