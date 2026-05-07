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