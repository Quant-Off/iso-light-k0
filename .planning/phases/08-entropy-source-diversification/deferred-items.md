# Phase 08 Deferred Items

## 2026-07-19 Plan 01 (Wave 0) 실행 중 발견

### QEMU 11 TCG (Apple Silicon) 부팅 비결정 결함 (out-of-scope)

- 증상 1 tcg-entropy 모드에서 커널이 "MMU Typestate Init Done" 직후 무증상 정지 (300초 대기에도 진행 없음, CPU reset=2, triple fault 없음)
- 증상 2 동일 구성 재부팅에서 #UD Invalid Opcode RIP=0x0000000000000003 wild jump 패닉 (panic.rs hlt loop 정상 동작, reset=2)
- base commit 5205f1d 의 kernel (본 plan 변경 미포함 Cargo.toml 원복 재빌드) 로도 동일 재현 -> Plan 01 변경과 무관한 pre-existing 환경 결함
- 같은 날 오전 실측 (mac-qemu-boot-env 메모리) 에서는 동일 구성으로 TLS 소거까지 통과 -> 비결정적 재현, QEMU 8.2 wild-jump 결함의 QEMU 11 잔존 변형 의심
- 조치 후보 Wave 4 qemu-tcg lane 튜닝 시점 재평가, 13 marker 회귀의 정본 검증은 Linux+KVM lane (VALIDATION.md 정합)
- 2026-07-19 Plan 02 (Wave 1) 에서도 동일 재현 (`make qemu-smoke-smoke` 전 marker MISS + "RDSEED/RDRAND 부재") -> boot-path diff 는 main.rs 모듈 선언 1 줄뿐 (`git diff --stat` 실측) 본 plan 변경과 무관, Linux+KVM lane 위임 유지

## 2026-07-19 Plan 03 (Wave 2) 실행 중 발견

### Wave 4 Makefile entropy-host-test leg 명령 형태 (in-scope 이월)

- `CARGO_BUILD_TARGET=` 빈 env 는 cargo 1.98 에서 "target was empty" 즉시 오류 -> VALIDATION 의 명령 형태 사용 불가
- 확정 형태 `cargo test --release --target $(rustc -vV | sed -n 's/^host: //p') --no-default-features --test NAME`
- `--no-default-features` 는 kernel-bin 기본 feature 를 꺼서 host 에서 컴파일 불가한 kernel bin 빌드를 제외 (08-03 deviation 4 5 참조)
- fault-inject leg 는 `-- --include-ignored` 필요 (panic 경로 test 가 ignore 표기)

## 2026-07-19 Plan 04 (Wave 3) 실행 중 발견

### AUDIT_RING sub-code SUB_APT_FAIL(2) 예약 (health.rs verdict 세분화 후속)

- quorum.rs collect_from_source 의 health fail audit 는 SUB_RCT_FAIL(1) 로 통합 emit
- 원인 StreamHealth::check 가 RCT 와 APT 실패를 HealthVerdict::Fail 단일 값으로 병합해 quorum 계층에서 두 test 구분 불가
- SUB_APT_FAIL(2) const 는 정의만 유지 예약 상태 health.rs 가 verdict 에 실패 test 종류를 실으면 배선 가능 (health.rs 는 Task 1 <files> scope 밖이라 미변경)
- 영향 audit sub-code 정밀도 한정 fail 자체 검출/차단은 정상 동작 (SUMMARY deviation 참조)

### smoke feature 빌드는 gitignored dev sk 자료 필요 (worktree 환경 이월)

- `cargo build --features smoke --target x86_64-unknown-none` 은 `keys/dev_trust_root.sk44` include_bytes 의존 (main.rs L1678 L1848)
- 본 파일은 `.gitignore` 의 `keys/*.sk*` 로 worktree 에 부재 -> 코드 무관 환경 결함
- 본 wave 검증은 main checkout 의 dev sk 를 worktree 로 임시 복사 (gitignore 유지 커밋 0) 후 smoke 컴파일 GREEN 실측
- Wave 4 CI lane 은 dev sk 자료 provisioning 전제 필요

## 2026-07-20 Plan 05 (Wave 4) 실행 중 발견

### QEMU 13-marker boot 회귀 (make qemu-kvm / qemu-tcg) Linux+KVM lane 이연

- 본 macOS 호스트는 /dev/kvm 부재 (full lane 불가) + QEMU 11 TCG pre-existing RDRAND/RDSEED · post-TLS stall 결함 (Wave 0~3 기록) 으로 13-marker boot 회귀 실행 불가
- Task 1 의 qemu-test.sh check_marker flip (entropy_dependent=false) + 신규 4 marker check + Task 2 의 BOOT_SELF_TEST_BUF 16384 옥텟 dump 는 코드/스크립트 edit 완료 (b371f83 / 03d2146)
- 정본 검증 (VALIDATION.md ENTR-07) 은 Linux+KVM lane 에 이연
  - `make qemu-kvm` production strict 2-of-3 13 marker PASS
  - `make qemu-tcg` degraded-ok virtio-rng 13 marker PASS + ENTROPY_DEGRADED_OK_ACTIVE=1 + ENTROPY_QUORUM_1_OF_3_OK
  - `make ci-phase8` 6-leg composite
- Task 3 checkpoint 의 stage 2/3/5 가 본 항목에 해당 stage 1 (build-rel + check-jitter-lto) 는 본 macOS 호스트에서 PASS 실측 (instructions=1819 black_box=273)

### 16384 sample min-entropy >= 0.5 host-side 분석 이연 (ENTR-03 / ROADMAP SC #2)

- BOOT_SELF_TEST_BUF dump 는 real QEMU boot serial 출력이 있어야 추출 가능 (JITTER_BOOT_DUMP_BEGIN N=16384 ~ END 사이 64 line)
- 본 호스트는 real boot serial 미생성 (위 QEMU 결함) 으로 ea_iid / Most Common Value 추정 입력 부재
- Linux+KVM lane 에서 boot serial 확보 후 `ea_iid` (NIST SP 800-90B) 또는 tools inline Python 으로 min-entropy >= 0.5 확인 필요
- Task 3 checkpoint 의 stage 4 가 본 항목에 해당

### K0_REQUIRE_DEGRADED env 게이트 Makefile qemu-tcg export 미배선 (Wave 5 후속)

- qemu-test.sh 에 ENTROPY_DEGRADED_OK_ACTIVE marker 를 K0_REQUIRE_DEGRADED 게이트로 신규 추가함
- degraded lane 에서 강제 PASS 하려면 Makefile qemu-tcg 가 `K0_REQUIRE_DEGRADED=1` export 필요 (현재 미배선 default 0 이라 MISS gate off 로 non-fail)
- Task 1 <files> 는 scripts/qemu-test.sh 한정이라 Makefile 미변경 Wave 5 ci-phase8 sealing 시 배선 권고

## 2026-07-20 Plan 06 (Wave 5) 종료 게이트 실행 중 처리

### Makefile qemu-tcg K0_REQUIRE_DEGRADED=1 export 배선 완료 (08-05 deviation #3 해소)

- Makefile::qemu-tcg 의 qemu-test.sh 호출 앞에 `K0_REQUIRE_DEGRADED=1` 추가
- degraded TCG cell 에서 ENTROPY_DEGRADED_OK_ACTIVE gated marker 를 강제 PASS 로 승격 (default 0 게이트 off 해소)
- production qemu-kvm lane 은 K0_REQUIRE_DEGRADED 미설정 유지 (degraded marker 미emit 이 정상 동작)

### ci-phase8 QEMU 2-leg (qemu-kvm + qemu-tcg) Linux+KVM lane 이연 (Wave 0~4 패턴 계승)

- 본 macOS 호스트는 /dev/kvm 부재 + QEMU 11 TCG RDRAND/RDSEED 결함 + post-TLS stall 로 두 QEMU leg 실행 불가
- ci-phase8 6-leg 중 host-runnable 4 leg 전수 PASS 실측
  - check-alloc-zero PASS (alloc 심볼 0)
  - check-machete PASS (dead-dep 0)
  - check-jitter-lto PASS (instructions=1819 black_box=273)
  - check-virtio-sentinel PASS (3 패턴 감지)
- 보조 host gate 도 PASS (check-entropy-mutex + entropy-host-test 18/18)
- 이연 정본 검증 (Linux+KVM lane)
  - make qemu-kvm production strict 2-of-3 13 marker PASS
  - make qemu-tcg degraded-ok virtio-rng 13 marker PASS + ENTROPY_DEGRADED_OK_ACTIVE=1 (K0_REQUIRE_DEGRADED=1 강제)
  - make ci-phase8 6-leg composite 최종 GREEN
  - 16384 sample jitter min-entropy >= 0.5 (ENTR-03 boot-serial 확보 후 host 추정)
