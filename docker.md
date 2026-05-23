# 이미지 빌드 (최초 1회)
docker compose build

# 커널 ELF 빌드만
docker compose run --rm build

# ISO 생성 (ELF 빌드 포함)
docker compose run --rm iso

# 전체 테스트 (ISO 빌드 + QEMU 30초 부팅 검증)
docker compose run --rm test

# 컨테이너 쉘 진입 (직접 디버깅)
docker compose run --rm test bash

qemu-test.sh 동작:
1. make iso -> grub-mkrescue로 ISO 생성
2. /dev/kvm 존재 시 KVM 가속 자동 활성화, 없으면 TCG 소프트웨어 에뮬레이션
3. 30초 타임아웃으로 QEMU 실행, serial 출력과 CPU 리셋 로그 캡처
4. PASS: timeout으로 종료 + CPU 리셋 없음 (커널이 hlt 루프 정상 실행 중)
5. FAIL: CPU 리셋 감지 (triple fault/크래시) 또는 QEMU 비정상 종료

# Apple Silicon (M1/M2/M3/M4/M5) 환경 한계

Apple Silicon macOS 호스트에서는 Docker Desktop 이 linux/amd64 컨테이너를 Rosetta 로 변환 실행하며, 그 내부의 qemu-system-x86_64 는 다시 TCG 로 x86 게스트 에뮬레이션 (이중 에뮬레이션). 이 환경에서 RDRAND 와 RDSEED 두 명령 모두 결함 에뮬레이션되어 게스트 커널에 결정적 wild jump #PF 를 유발함. 이 때문에 scripts/qemu-test.sh 는 -cpu qemu64 로 두 명령을 강제 비활성화함.

부작용
- capability::fill_hw_entropy 가 CapError::NoEntropy 반환
- BLAKE3/TLS/HSM attach/Phase 2~6 등 entropy 의존 마커 11/13 fail
- 다음 두 마커만 PASS [메인 루프 진입(All Task Done)] [HsmRegistry static online]

전체 마커 PASS 검증은 다음 환경에서만 가능
- Linux + KVM (CI 또는 native Linux 호스트, /dev/kvm 존재)
- 실기 부팅

근본 원인 분석 .planning/debug/kernel-pf-m5-rosetta.md 참조