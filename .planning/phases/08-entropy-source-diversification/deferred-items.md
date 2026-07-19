# Phase 08 Deferred Items

## 2026-07-19 Plan 01 (Wave 0) 실행 중 발견

### QEMU 11 TCG (Apple Silicon) 부팅 비결정 결함 (out-of-scope)

- 증상 1 tcg-entropy 모드에서 커널이 "MMU Typestate Init Done" 직후 무증상 정지 (300초 대기에도 진행 없음, CPU reset=2, triple fault 없음)
- 증상 2 동일 구성 재부팅에서 #UD Invalid Opcode RIP=0x0000000000000003 wild jump 패닉 (panic.rs hlt loop 정상 동작, reset=2)
- base commit 5205f1d 의 kernel (본 plan 변경 미포함 Cargo.toml 원복 재빌드) 로도 동일 재현 -> Plan 01 변경과 무관한 pre-existing 환경 결함
- 같은 날 오전 실측 (mac-qemu-boot-env 메모리) 에서는 동일 구성으로 TLS 소거까지 통과 -> 비결정적 재현, QEMU 8.2 wild-jump 결함의 QEMU 11 잔존 변형 의심
- 조치 후보 Wave 4 qemu-tcg lane 튜닝 시점 재평가, 13 marker 회귀의 정본 검증은 Linux+KVM lane (VALIDATION.md 정합)
- 2026-07-19 Plan 02 (Wave 1) 에서도 동일 재현 (`make qemu-smoke-smoke` 전 marker MISS + "RDSEED/RDRAND 부재") -> boot-path diff 는 main.rs 모듈 선언 1 줄뿐 (`git diff --stat` 실측) 본 plan 변경과 무관, Linux+KVM lane 위임 유지
