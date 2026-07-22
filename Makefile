# iso-light-k0 Makefile
#
# 타겟:
#   all        - 커널 빌드 + ISO 생성 (기본)
#   build      - 커널 ELF 빌드 (debug)
#   build-rel  - 커널 ELF 빌드 (release)
#   iso        - ISO 이미지 생성 (debug 커널 사용)
#   iso-rel    - ISO 이미지 생성 (release 커널 사용)
#   run        - QEMU로 실행 (debug ISO, VGA 창 표시)
#   run-rel    - QEMU로 실행 (release ISO, VGA 창 표시)
#   run-dbg    - QEMU 헤드리스 실행 (CPU 예외/리셋 로그 기록)
#   clean      - 빌드 산출물 제거
#
# Docker:
#   docker compose run --rm build      - 컨테이너에서 ELF 빌드
#   docker compose run --rm iso        - 컨테이너에서 ISO 생성
#   docker compose run --rm test       - 컨테이너에서 QEMU 테스트

#
# 경로 설정
#
TARGET       := x86_64-unknown-none
KERNEL_NAME  := iso-light-k0

TARGET_DIR   := target/$(TARGET)
KERNEL_DEBUG := $(TARGET_DIR)/debug/$(KERNEL_NAME)
KERNEL_REL   := $(TARGET_DIR)/release/$(KERNEL_NAME)

# Phase 10 aarch64 크로스 빌드 변수 (ci-phase10 봉인 게이트)
# AARCH64_ELF 은 기본 산출물 PSCI_ELF 은 SC1 ARM-01 이 명시한 서술적 명명 산출물
TARGET_AARCH64 := aarch64-unknown-none-softfloat
AARCH64_ELF    := target/$(TARGET_AARCH64)/release/$(KERNEL_NAME)
PSCI_ELF       := iso-light-k0-aarch64-psci.elf

ISO_DIR      := isodir
BOOT_DIR     := $(ISO_DIR)/boot
GRUB_DIR     := $(BOOT_DIR)/grub

ISO_DEBUG    := $(KERNEL_NAME)-debug.iso
ISO_REL      := $(KERNEL_NAME)-release.iso

#
# 툴 설정
#
CARGO        := cargo
GRUB_MKRES   := grub-mkrescue
QEMU         := qemu-system-x86_64
QEMU_AARCH64 := qemu-system-aarch64

# macOS에서 Homebrew로 설치된 GRUB 위치 탐색
ifeq ($(shell uname),Darwin)
    GRUB_MKRES := $(shell \
        for p in \
            /opt/homebrew/bin/grub-mkrescue \
            /usr/local/bin/grub-mkrescue \
            /opt/homebrew/opt/grub/bin/grub-mkrescue \
            $$HOME/.local/bin/grub-mkrescue; do \
            [ -x "$$p" ] && echo "$$p" && break; \
        done)
    # Homebrew x86_64-elf-grub(x86_64-efi 전용) + 추출한 i386-pc 모듈 조합 폴백
    # i386-pc 모듈 준비 절차는 docs/vm-kernel-test.md macOS 섹션 참조
    ifeq ($(GRUB_MKRES),)
        GRUB_MKRES := $(shell \
            if [ -x /opt/homebrew/bin/x86_64-elf-grub-mkrescue ] \
               && [ -d "$$HOME/.local/share/grub/i386-pc" ]; then \
                echo "/opt/homebrew/bin/x86_64-elf-grub-mkrescue -d $$HOME/.local/share/grub/i386-pc"; \
            fi)
    endif
    ifeq ($(GRUB_MKRES),)
        GRUB_MKRES := grub-mkrescue
    endif
    QEMU := $(shell \
        for p in \
            /opt/homebrew/bin/qemu-system-x86_64 \
            /usr/local/bin/qemu-system-x86_64; do \
            [ -x "$$p" ] && echo "$$p" && break; \
        done)
    ifeq ($(QEMU),)
        QEMU := qemu-system-x86_64
    endif
    QEMU_AARCH64 := $(shell \
        for p in \
            /opt/homebrew/bin/qemu-system-aarch64 \
            /usr/local/bin/qemu-system-aarch64; do \
            [ -x "$$p" ] && echo "$$p" && break; \
        done)
    ifeq ($(QEMU_AARCH64),)
        QEMU_AARCH64 := qemu-system-aarch64
    endif
endif

#
# QEMU 옵션
#
QEMU_FLAGS := \
    -m 512M \
    -cdrom $(ISO_DEBUG) \
    -serial stdio \
    -no-reboot \
    -no-shutdown

QEMU_FLAGS_REL := $(QEMU_FLAGS:-cdrom $(ISO_DEBUG)=-cdrom $(ISO_REL))

# 디버그 실행 플래그: CPU 예외·리셋 로그 + 헤드리스(시리얼만)
QEMU_DEBUG_FLAGS := \
    -m 512M \
    -cdrom $(ISO_DEBUG) \
    -serial stdio \
    -no-reboot \
    -no-shutdown \
    -display none \
    -d int,cpu_reset \
    -D /tmp/qemu-$(KERNEL_NAME).log

#
# aarch64 QEMU 옵션 (GRUB/ISO 없이 -kernel 직접 부팅 + PL011 직렬)
#
# 헤드리스 마커 하네스는 scripts/qemu-test-aarch64.sh 가 자체적으로 -serial file: 로
# 캡처하므로 여기서는 대화형 run 용 flag (mon:stdio 로 7-line proof 라이브 관측) 만 정의함.
# 커널은 proof 후 wfi park 하여 스스로 종료하지 않으므로 run-aarch64 는 상한(timeout) 후
# 자동 종결하되, 그 상한 만료(exit 124)는 정상 종료로 처리하고 진짜 QEMU 오류만 노출함.
AARCH64_SMOKE_TIMEOUT := 30
AARCH64_RUN_TIMEOUT   := 12

QEMU_AARCH64_FLAGS := \
    -M virt,gic-version=3 \
    -cpu cortex-a72 \
    -m 512M \
    -display none \
    -serial mon:stdio \
    -no-reboot

# 대화형 run 상한 종결용 timeout 커맨드 (gtimeout -> timeout 폴백 미존재 시 무상한)
TIMEOUT_CMD := $(shell command -v gtimeout 2>/dev/null || command -v timeout 2>/dev/null || true)

# run-aarch64 실행 커맨드 timeout 존재 시 상한 래핑 부재 시 무상한(사용자 Ctrl-A X 종료)
ifeq ($(TIMEOUT_CMD),)
RUN_AARCH64_CMD := $(QEMU_AARCH64) $(QEMU_AARCH64_FLAGS) -kernel $(PSCI_ELF)
else
RUN_AARCH64_CMD := $(TIMEOUT_CMD) $(AARCH64_RUN_TIMEOUT) $(QEMU_AARCH64) $(QEMU_AARCH64_FLAGS) -kernel $(PSCI_ELF)
endif

#
# 사용자 ELF (Ring 3 스모크 테스트 / lumen 와이어 호환 검증)
#
USER_HELLO_DIR := crates/iso-user-hello
USER_HELLO_ELF := $(USER_HELLO_DIR)/target/$(TARGET)/release/iso-user-hello

USER_LUMEN_DIR := crates/iso-user-lumen
USER_LUMEN_ELF := $(USER_LUMEN_DIR)/target/$(TARGET)/release/iso-user-lumen

#
# 기본 타겟
#
.PHONY: all build build-rel iso iso-rel run run-rel run-dbg clean userspace user-hello user-lumen clean-user check-alloc-zero check-alloc-bus qemu-smoke ci-phase1 ci-phase2 ci-phase3 ci-phase4 chan-dudect check-no-dev-sk qemu-smoke-smoke ci-phase5 wire-attest-host-test ci-phase5_1 ci-phase6 check-no-network qemu-smoke-tls-external check-machete ci-phase7 ci-phase8 check-jitter-lto check-virtio-sentinel check-entropy-mutex qemu-tcg qemu-kvm entropy-host-test check-arch-cfg-gate check-ct-branches check-secure-zero check-body-untouched check-mmu-typestate ci-phase9 ci-phase10 build-aarch64 run-aarch64 qemu-smoke-aarch64 test-aarch64

all: iso

#
# 사용자 ELF 빌드 (커널 prerequisite)
#
# 사용자 크레이트는 워크스페이스 외부 (별도 .cargo/config.toml + linker.ld + build-std=core).
# 본 Makefile 룰에서 별도 cargo invocation 으로 ELF 를 산출함.
user-hello:
	cd $(USER_HELLO_DIR) && $(CARGO) build --release

# Phase D 가 추가될 때 활성화. 없으면 무시(`|| true`).
user-lumen:
	@if [ -d $(USER_LUMEN_DIR) ]; then \
		cd $(USER_LUMEN_DIR) && $(CARGO) build --release; \
	else \
		echo "[user-lumen] not yet introduced (Phase D), skipping"; \
	fi

userspace: user-hello user-lumen

#
# 커널 빌드 (사용자 ELF prerequisite)
#
build: userspace
	$(CARGO) build --target $(TARGET)

build-rel: userspace
	$(CARGO) build --target $(TARGET) --release

clean-user:
	@if [ -d $(USER_HELLO_DIR)/target ]; then $(CARGO) clean --manifest-path $(USER_HELLO_DIR)/Cargo.toml; fi
	@if [ -d $(USER_LUMEN_DIR)/target ]; then $(CARGO) clean --manifest-path $(USER_LUMEN_DIR)/Cargo.toml; fi

#
# ISO 생성 공통 함수
#
$(GRUB_DIR)/grub.cfg:
	@mkdir -p $(GRUB_DIR)
	@printf '%s\n' \
	    'set timeout=0' \
	    'set default=0' \
	    'menuentry "iso-light-k0" {' \
	    '    multiboot2 /boot/kernel.bin' \
	    '    boot' \
	    '}' > $@
	@echo "[ISO] grub.cfg 생성: $@"

#
# debug ISO
#
iso: build $(GRUB_DIR)/grub.cfg
	@mkdir -p $(BOOT_DIR)
	@cp $(KERNEL_DEBUG) $(BOOT_DIR)/kernel.bin
	@echo "[ISO] 커널 복사: $(KERNEL_DEBUG) → $(BOOT_DIR)/kernel.bin"
	$(GRUB_MKRES) -o $(ISO_DEBUG) $(ISO_DIR)
	@echo "[ISO] 생성 완료: $(ISO_DEBUG)"

#
# release ISO
#
iso-rel: build-rel $(GRUB_DIR)/grub.cfg
	@mkdir -p $(BOOT_DIR)
	@cp $(KERNEL_REL) $(BOOT_DIR)/kernel.bin
	@echo "[ISO] 커널 복사: $(KERNEL_REL) → $(BOOT_DIR)/kernel.bin"
	$(GRUB_MKRES) -o $(ISO_REL) $(ISO_DIR)
	@echo "[ISO] 생성 완료: $(ISO_REL)"

#
# QEMU 실행
#
run: iso
	$(QEMU) $(QEMU_FLAGS)

run-rel: iso-rel
	$(QEMU) $(QEMU_FLAGS_REL)

# 헤드리스 디버그 실행: CPU 예외/리셋 로그를 /tmp/qemu-iso-light-k0.log에 기록
run-dbg: iso
	@echo "[DBG] QEMU 로그: /tmp/qemu-$(KERNEL_NAME).log"
	$(QEMU) $(QEMU_DEBUG_FLAGS)

#
# aarch64 환경 테스트 (x86 build / run / qemu-smoke 대응 -kernel 직접 부팅 레인)
#
#   build-aarch64       aarch64 release ELF 빌드 + 명명 산출물 $(PSCI_ELF) 생성
#   run-aarch64         QEMU virt 대화형 부팅 (PL011 직렬로 7-line proof 라이브 관측 상한 종결)
#   qemu-smoke-aarch64  헤드리스 7-line proof 마커 전량 하드 판정 (조기 종료 하네스)
#   test-aarch64        aarch64 전용 게이트 전량 (정적 3 + arch_parity + qemu-smoke) macOS GREEN 레인
#
build-aarch64:
	$(CARGO) build --target $(TARGET_AARCH64) --release
	@cp $(AARCH64_ELF) $(PSCI_ELF)
	@echo "[aarch64] ELF 빌드 완료: $(PSCI_ELF)"

run-aarch64: build-aarch64
	@echo "[aarch64] QEMU virt 대화형 부팅 (Ctrl-A X 종료 상한 $(AARCH64_RUN_TIMEOUT)s)"
	@rc=0; $(RUN_AARCH64_CMD) || rc=$$?; \
	 case $$rc in \
	   0)       echo "[aarch64] 부팅 세션 정상 종료 (rc=0)" ;; \
	   124)     echo "[aarch64] 상한 $(AARCH64_RUN_TIMEOUT)s 도달 자동 종료 (정상 커널은 proof 후 wfi park 하여 스스로 멈추지 않음)" ;; \
	   130|143) echo "[aarch64] 사용자 인터럽트 종료 (rc=$$rc)" ;; \
	   *)       echo "[aarch64] QEMU 비정상 종료 rc=$$rc" >&2; exit $$rc ;; \
	 esac

qemu-smoke-aarch64: build-aarch64
	@AARCH64_ELF=$(PSCI_ELF) \
	    EXPECTED_MARKERS="EL MMU GICR CHILDREN GRP1 IRQ PSCI" \
	    QEMU_TIMEOUT=$(AARCH64_SMOKE_TIMEOUT) \
	    bash scripts/qemu-test-aarch64.sh
	@echo "[aarch64] qemu-smoke-aarch64 7-line proof 마커 전량 검출 PASS"

# aarch64 전용 회귀 레인 (ci-phase10 은 x86 ci-phase9 를 상속해 macOS 에서 FAIL 하므로
# 그 x86 baggage 없이 aarch64 산출물만 검증하는 macOS GREEN 레인을 별도 제공)
test-aarch64: qemu-smoke-aarch64
	@echo "[aarch64] 정적 게이트 3종 (vector-align / secure-zero / ct-branches)"
	@AARCH64_ELF=$(PSCI_ELF) bash scripts/check-vector-align.sh
	@ARCH=aarch64 AARCH64_ELF=$(PSCI_ELF) bash scripts/check-secure-zero.sh
	@ARCH=aarch64 AARCH64_ELF=$(PSCI_ELF) bash scripts/check-ct-branches.sh
	@echo "[aarch64] arch_parity host test (5 알고리즘 x86 aarch64 byte-diff 0)"
	@HOST_TRIPLE=$$(rustc -vV | sed -n 's/^host: //p') && \
	    $(CARGO) test --no-default-features --target $$HOST_TRIPLE --test arch_parity
	@echo "[aarch64] test-aarch64 전량 PASS (정적 3 + arch_parity + qemu-smoke)"

#
# 정리
#
clean: clean-user
	$(CARGO) clean
	@rm -rf $(ISO_DIR) $(ISO_DEBUG) $(ISO_REL)
	@echo "[clean] 완료"

#
# Phase 1 CI 게이트
#
check-alloc-zero: build
	@bash scripts/check-no-alloc.sh
	@echo "[CI] alloc-zero 게이트 통과"

qemu-smoke: iso
	@bash scripts/qemu-test.sh
	@echo "[CI] QEMU 부팅 smoke 통과"

ci-phase1: check-alloc-zero qemu-smoke
	@cd /Library/Quant/Repository/projects/elib-k0-nt && $(CARGO) test -p constant-time --tests
	@echo "[CI] Phase 1 ci 게이트 전체 통과"

#
# Phase 2 CI 게이트 (BUS-01..BUS-04 + 부팅 smoke)
#
# 3-leg 구조 (ci-phase1 의 패턴을 그대로 답습):
#   1) check-alloc-zero  — 바이너리 alloc 심볼 0 (재검증; Phase 1 게이트)
#   2) check-alloc-bus   — src/bus.rs 소스 alloc 의존 0 (BUS-01)
#   3) qemu-smoke        — QEMU 부팅 + Phase 1 마커 + BUS_PHASE2_OK 마커 (BUS-03)
#
check-alloc-bus: build
	@bash scripts/check-no-alloc-bus.sh
	@echo "[CI] BUS-01 alloc-zero 게이트 통과"

ci-phase2: check-alloc-zero check-alloc-bus qemu-smoke
	@echo "[CI] Phase 2 ci 게이트 전체 통과 (BUS-01..BUS-04 + smoke)"

#
# Phase 3 host-side dudect leg
#
# elib-k0-nt sibling 크레이트의 chan_* CT 회귀 테스트  Welch t < 4.5 게이트
#
chan-dudect:
	@cd /Library/Quant/Repository/projects/elib-k0-nt && $(CARGO) test -p constant-time --tests --release -- --ignored chan_
	@echo "[CI] Phase 3 chan-dudect 게이트 통과"

#
# Phase 5.1 host-side wire attest leg (Plan 05.1-01 Wave 0 신설)
#
# elib-k0-nt sibling 크레이트의 wire_attest_* / wire_status_* CT 회귀 테스트
# AttestSubmit dispatcher 성공/실패 + Status response byte-exact roundtrip
# + payload 3733 옥텟 split + re-attestation slot mutation 0 회귀 가드 4 종
#
# 본 leg 는 Plan 05.1-04 의 GREEN fill-in 후 PASS Wave 0 단계는
# sibling test 컴파일 표면 잠금만 의무 실 실행 PASS 는 Plan 05.1-04 이후
#
wire-attest-host-test:
	@HOST_TRIPLE=$$(rustc -vV | sed -n 's/^host: //p') && \
	 cd /Library/Quant/Repository/projects/elib-k0-nt && \
	 $(CARGO) test -p constant-time --release --target $$HOST_TRIPLE \
	   --test wire_attest_submit_dispatch \
	   --test wire_attest_payload_layout \
	   --test wire_status_audit_serialize \
	   --test wire_attest_no_slot_mutation
	@echo "[CI] Phase 5.1 wire-attest-host-test 게이트 통과"

#
# Phase 3 CI 게이트 (CHAN-01..CHAN-04 + smoke + dudect)
#
# 4-leg 구조 (ci-phase2 mirror + dudect leg):
#   1) check-alloc-zero  바이너리 alloc 심볼 0 (Phase 1 게이트 재검증)
#   2) check-alloc-bus   src/bus.rs 소스 alloc 의존 0 (BUS-01 재검증)
#   3) qemu-smoke        QEMU 부팅 + Phase 1/2 마커 + CHAN_PHASE3_OK 마커
#   4) chan-dudect       elib-k0-nt chan_* CT timing balance (Pitfall 1 + CHAN-04)
#
ci-phase3: check-alloc-zero check-alloc-bus qemu-smoke chan-dudect
	@echo "[CI] Phase 3 ci 게이트 전체 통과 (CHAN-01..CHAN-04 + smoke + dudect)"

#
# Phase 4 CI 게이트 (WIRE-01..WIRE-05 + smoke + Phase 3 dudect 재사용)
#
# 4-leg 구조 (ci-phase3 mirror):
#   1) check-alloc-zero  바이너리 alloc 심볼 0 (Phase 1 게이트 + postcard 4 패턴 추가)
#   2) check-alloc-bus   src/bus.rs 소스 alloc 의존 0 (BUS-01 재검증)
#   3) qemu-smoke        QEMU 부팅 + Phase 1/2/3 마커 + WIRE_PHASE4_OK 마커
#   4) chan-dudect       elib-k0-nt chan_* CT timing balance (Phase 3 leg 재사용)
#
ci-phase4: check-alloc-zero check-alloc-bus qemu-smoke chan-dudect
	@echo "[CI] Phase 4 ci 게이트 전체 통과 (WIRE-01..WIRE-05 + smoke + dudect)"

#
# Phase 5 closed 프로필 dev sk leak 가드 (D-19)
#
# 본 타겟은 closed 프로필 빌드 산출물에 dev_trust_root.sk44 의 K 시드 16 옥텟이
# 누설되지 않았음을 xxd grep 으로 검증함  Plan 05-01 D-02 dev sk include 게이트
# (feature smoke 미활성) 가 closed 프로필에서 cfg-out 되는지 회귀 가드 역할
#
check-no-dev-sk: build-rel
	@bash scripts/check-no-dev-sk.sh
	@echo "[CI] Phase 5 D-19 dev sk leak 가드 통과 (closed profile)"

#
# Phase 5 QEMU smoke (feature smoke 활성)
#
# 본 타겟은 feature smoke 를 활성화한 debug 빌드로 ISO 를 만들고 QEMU 부팅 후
# ATTEST_PHASE5_OK 마커 노출을 강제함  CARGO_FLAGS env var 로 attest_phase5_smoke_test
# 함수를 활성화하며 REQUIRE_ATTEST_PHASE5_OK=1 이 qemu-test.sh 의 fail-accumulator 를
# Phase 5 마커 부재 시 PASS=false 로 떨어트림
#
qemu-smoke-smoke:
	@$(CARGO) build --target $(TARGET) --features smoke
	@mkdir -p $(BOOT_DIR)
	@cp $(KERNEL_DEBUG) $(BOOT_DIR)/kernel.bin
	@$(GRUB_MKRES) -o $(ISO_DEBUG) $(ISO_DIR)
	@REQUIRE_ATTEST_PHASE5_OK=1 REQUIRE_ATTEST_PHASE5_1_OK=1 REQUIRE_GAP_PHASE6_OK=1 bash scripts/qemu-test.sh
	@echo "[CI] Phase 5 QEMU smoke (feature smoke) 통과"

#
# Phase 5 CI 게이트 (ENROLL-01..ENROLL-04 + CAP-02 + smoke + dudect + dev sk leak 가드)
#
# 5-leg 구조 (ci-phase4 + check-no-dev-sk + qemu-smoke-smoke 확장):
#   1) check-alloc-zero       바이너리 alloc 심볼 0 (Phase 1 게이트 + ATTEST_BUF 4 KiB BSS 가산 회귀)
#   2) check-alloc-bus        src/bus.rs 소스 alloc 의존 0 (BUS-01 재검증)
#   3) check-no-dev-sk        closed 프로필 dev sk K 시드 16 옥텟 부재 (D-19)
#   4) qemu-smoke-smoke       feature smoke 한정 ATTEST_PHASE5_OK 마커 + Phase 1/2/3/4 마커 보존
#   5) chan-dudect            elib-k0-nt chan_* CT timing balance (Phase 3 leg 재사용)
#
ci-phase5: check-alloc-zero check-alloc-bus check-no-dev-sk qemu-smoke-smoke chan-dudect
	@echo "[CI] Phase 5 ci 게이트 전체 통과 (ENROLL-01..ENROLL-04 + CAP-02 + smoke + dudect + dev sk leak 가드)"

#
# Phase 5.1 CI 게이트 (ENROLL-01/02/04 + CAP-02 + DOC-01 + 기존 phase 5 5-leg + wire host test)
#
# 6-leg 구조 (ci-phase5 + wire-attest-host-test 확장):
#   1) check-alloc-zero       handle_attest_submit / handle_status alloc 0 회귀
#   2) check-alloc-bus        bus.rs alloc 의존 0 회귀
#   3) check-no-dev-sk        closed 프로필 dev sk K 시드 16 옥텟 부재 (Phase 5 D-19 보존)
#   4) qemu-smoke-smoke       ATTEST_PHASE5_OK + 신규 ATTEST_PHASE5_1_OK 두 마커 강제
#   5) chan-dudect            elib-k0-nt chan_* CT timing balance (Phase 3 leg 재사용)
#   6) wire-attest-host-test  elib-k0-nt wire_attest_* / wire_status_* 4 sibling host tests
#
ci-phase5_1: check-alloc-zero check-alloc-bus check-no-dev-sk qemu-smoke-smoke chan-dudect wire-attest-host-test
	@echo "[CI] Phase 5.1 ci 게이트 전체 통과 (ENROLL-01/02/04 + CAP-02 + DOC-01 + wire-attest-host-test)"

#
# Phase 6 CI 게이트 (GAP-01 ~ GAP-04 + 본 마일스톤 종료 게이트)
#
# 4-leg 구조 (ci-phase5_1 6-leg 의 축소 wire-attest / chan-dudect 는 Phase 3/5 leg 재활용):
#   1) check-alloc-zero       바이너리 alloc 심볼 0 회귀 (Phase 1 ~ 6 누적)
#   2) check-no-network       closed 프로필 NETWORK_ATTACH_CAP / NETWORK_CAP_STATE / init_network_cap / take_network_cap / air_gap..network 5 패턴 부재 (GAP-03)
#   3) qemu-smoke-smoke       Phase 1 ~ 5.1 marker 보존 + 신규 GAP_PHASE6_OK marker 강제 (GAP-01 ~ GAP-04 종료 게이트)
#   4) check-no-dev-sk        closed 프로필 dev sk leak 가드 회귀 보존 (Phase 5 D-19)
# 5th leg (선택 Open Q3 채택) qemu-smoke-tls-external tls-external + smoke 빌드 양방향 회귀 가드
#
ci-phase6: check-alloc-zero check-no-network qemu-smoke-smoke check-no-dev-sk qemu-smoke-tls-external
	@echo "[CI] Phase 6 ci 게이트 전체 통과 (GAP-01 ~ GAP-04 + 본 마일스톤 종료 게이트)"

check-no-network: build-rel
	@bash scripts/check-no-network.sh
	@echo "[CI] check-no-network gate 통과 (GAP-03)"

# 5th leg tls-external + smoke 빌드의 양방향 회귀 가드 (Open Q3 결정 채택)
qemu-smoke-tls-external:
	@$(CARGO) build --target $(TARGET) --features tls-external,smoke
	@mkdir -p $(BOOT_DIR)
	@cp $(KERNEL_DEBUG) $(BOOT_DIR)/kernel.bin
	@$(GRUB_MKRES) -o $(ISO_DEBUG) $(ISO_DIR)
	@REQUIRE_GAP_PHASE6_OK=1 bash scripts/qemu-test.sh
	@echo "[CI] qemu-smoke-tls-external gate 통과 (tls-external 양 프로필 회귀)"

#
# Phase 7 SC #5 cargo-machete dead-dep + dead-pub-item 표준 게이트
#
# v2.0 마일스톤의 모든 후속 phase (8~12) 가 동일 leg 재사용 prior art
# .machete.toml ignore 화이트리스트는 proc-macro 위양성만 허용 정본 제한
#
check-machete:
	@echo "[machete] cargo-machete dead-dep + dead-pub-item gate"
	@command -v cargo-machete >/dev/null 2>&1 || { echo "[machete] FAIL cargo-machete 미설치 cargo install --locked cargo-machete 실행 필요"; exit 1; }
	@cargo machete

ci-phase7: check-alloc-zero check-machete
	@echo "[ci-phase7] PASS Phase 7 audit gates green alloc-zero plus cargo-machete"

#
# Phase 8 CI 게이트 (ENTR-01..ENTR-08 종료 게이트)
#
# 6-leg 구조
#   1) check-alloc-zero        Phase 1 standing (BSS 가산 회귀)
#   2) check-machete           Phase 7 standing (dead-dep 가드)
#   3) check-jitter-lto        Phase 8 신규 (ENTR-08 LTO 보호 objdump CI)
#   4) check-virtio-sentinel   Phase 8 신규 (ENTR-04 sentinel + verify-changed 회귀)
#   5) qemu-kvm                Phase 8 신규 (production strict 2-of-3 13 marker PASS)
#   6) qemu-tcg                Phase 8 신규 (degraded TCG cell virtio-rng-only 13 marker PASS)
#
# Wave 0 단계는 skeleton 호출 가능 표면만 보증 (본문 채움은 Wave 1~4)
# check-jitter-lto 와 check-virtio-sentinel 은 target 부재 시 expected fail-fast
#
check-jitter-lto: build-rel
	@bash scripts/check-jitter-lto.sh

check-virtio-sentinel:
	@bash scripts/check-virtio-sentinel.sh

# Phase 8 ENTR-05 compile_error mutex 게이트
# Wave 0 (mod.rs compile_error 부재) 는 진짜 컴파일 통과가 일어나므로 expected exit 1
# Wave 1 의 compile_error 신설 후 PASS 전환
check-entropy-mutex:
	@$(CARGO) build --features tls-external,entropy-degraded-ok 2>&1 | grep -q "compile_error" \
	    || (echo "[CI] FAIL ENTR-05 compile_error trigger 누락" && exit 1)
	@echo "[CI] PASS ENTR-05 entropy-degraded-ok 와 tls-external mutex compile_error 확인"

# Phase 8 host-side entropy host test leg
# 본 repo tests/ 디렉토리 4 host test (BLOCKER-5 정합 cross-repo elib-k0-nt 의존 제거)
# Wave 0 단계 (test 파일 부재) fail-fast expected Plan 03 의 4 test 본문 채움 후 PASS
entropy-host-test:
	@HOST_TRIPLE=$$(rustc -vV | sed -n 's/^host: //p') && \
	 $(CARGO) test --release --no-default-features --target $$HOST_TRIPLE \
	   --test entropy_quorum_fault_inject \
	   --test entropy_health_rct_apt \
	   --test entropy_virtio_sentinel \
	   --test audit_entropy_schema -- --include-ignored
	@echo "[CI] Phase 8 entropy-host-test 게이트 통과"

# Phase 8 D-03 entropy-degraded-ok TCG cell 한정 build + qemu-test
# production 산출 경로 오염 방지 별도 산출물 경로
qemu-tcg:
	@$(CARGO) build --release --target $(TARGET) --features smoke,entropy-degraded-ok
	@mkdir -p $(BOOT_DIR)
	@cp $(KERNEL_REL) $(BOOT_DIR)/kernel.bin
	@cp $(KERNEL_REL) target/$(TARGET)/release/iso-light-k0-tcg.elf
	@$(GRUB_MKRES) -o $(ISO_REL) $(ISO_DIR)
	@K0_REQUIRE_DEGRADED=1 K0_TEST_MODE=full bash scripts/qemu-test.sh
	@echo "[CI] Phase 8 qemu-tcg degraded-ok build smoke 통과"

# Phase 8 production KVM lane qemu-kvm 강제 + strict 2-of-3
qemu-kvm: qemu-smoke-smoke
	@echo "[CI] Phase 8 qemu-kvm production strict 2-of-3 통과 (qemu-smoke-smoke leg 재사용)"

ci-phase8: check-alloc-zero check-machete check-jitter-lto check-virtio-sentinel qemu-kvm qemu-tcg
	@echo "[CI] Phase 8 ci 게이트 전체 통과 (ENTR-01..ENTR-08 + 13 marker PASS)"

#
# Phase 9 CI 게이트 (HAL-01..HAL-09 종료 게이트)
#
# 10-leg 구조
#   1) check-alloc-zero       Phase 1 standing (BSS 가산 회귀)
#   2) check-machete          Phase 7 standing (dead-dep 가드)
#   3) check-entropy-mutex    Phase 8 standing (ENTR-05 compile_error mutex)
#   4) check-jitter-lto       Phase 8 standing (ENTR-08 LTO 보호 objdump CI)
#   5) check-arch-cfg-gate    Phase 9 신규 (HAL-06 cfg(target_arch) src/arch/ 외부 0 수렴 9-C 전 비-0 FAIL 예상)
#   6) check-ct-branches      Phase 9 신규 (SC #8 CT 함수 je/jne/jz/jnz 0 objdump Phase 12 MTRX-05(c) prior art)
#   7) check-secure-zero      Phase 9 신규 (HAL-05 memset U-entry 0 + k0_secure_zero 심볼 nm)
#   8) check-body-untouched   Phase 9 신규 (HAL-04 본체 diff-stat 2-tier base=scripts/phase9-base-commit)
#   9) check-mmu-typestate    Phase 9 신규 (HAL-07 Mmu typestate E0599 음성 probe)
#  10) qemu-smoke             Phase 1 standing (macOS 차단 시 Linux+KVM lane 이연 Phase 8 선례)
#
check-arch-cfg-gate:
	@bash scripts/check-arch-cfg-gate.sh

check-ct-branches: build-rel
	@bash scripts/check-ct-branches.sh

check-secure-zero: build-rel
	@bash scripts/check-secure-zero.sh

check-body-untouched:
	@bash scripts/check-body-untouched.sh

# Phase 9 HAL-07 Mmu typestate 음성 probe 게이트
# E0599 grep 성공 = 잘못된 typestate 호출이 컴파일 거부됨 (check-entropy-mutex 패턴 변형)
check-mmu-typestate:
	@$(CARGO) check --target $(TARGET) --features mmu-typestate-probe 2>&1 | grep -q "E0599" \
	    || (echo "[CI] FAIL HAL-07 Mmu typestate E0599 미검출" && exit 1)
	@echo "[CI] PASS HAL-07 Mmu typestate activate 오호출 컴파일 거부 확인"

ci-phase9: check-alloc-zero check-machete check-entropy-mutex check-jitter-lto check-arch-cfg-gate check-ct-branches check-secure-zero check-body-untouched check-mmu-typestate qemu-smoke
	@echo "[CI] Phase 9 ci 게이트 전체 통과 (HAL standing + 신규 5 leg PASS)"

#
# Phase 10 CI 봉인 게이트 (ARM-01..ARM-12 aarch64 native port 종료 게이트)
#
# 7-leg 구조 (ci-phase9 standing 상속 + aarch64 신규 6 leg)
#   1)  aarch64 크로스 빌드        cargo build --target aarch64 --release (ARM-01)
#   1b) 명명 산출물 생성           iso-light-k0-aarch64-psci.elf (SC1 ARM-01 서술적 명칭)
#   2)  check-vector-align         .vector_table 0x800 정렬 objdump (ARM-03)
#   3)  check-secure-zero aarch64  memset U-entry 0 + bl memset 0 + k0_secure_zero (ARM-11)
#   4)  check-ct-branches aarch64  조건부 분기 6 mnemonic 카운트 0 (ARM-12)
#   5)  arch_parity                5 알고리즘 x86 aarch64 byte-diff 0 host test (ARM-10 HOST_TRIPLE)
#   6)  qemu-test-aarch64          7-line 마커 전량 하드 판정 (boot-join 종결 10.1-01)
#   7)  ci-phase9                  x86 HAL standing 회귀 leg 상속 (하드)
#
ci-phase10:
	@echo "[CI] Phase 10 ci-phase10 봉인 게이트 시작 (ARM-01..ARM-12)"
	$(CARGO) build --target $(TARGET_AARCH64) --release
	@cp $(AARCH64_ELF) $(PSCI_ELF)
	@test -f $(PSCI_ELF) && echo "[CI]  ok  명명 산출물 $(PSCI_ELF) 생성 (SC1 ARM-01)"
	@AARCH64_ELF=$(AARCH64_ELF) bash scripts/check-vector-align.sh
	@ARCH=aarch64 AARCH64_ELF=$(AARCH64_ELF) bash scripts/check-secure-zero.sh
	@ARCH=aarch64 AARCH64_ELF=$(AARCH64_ELF) bash scripts/check-ct-branches.sh
	@HOST_TRIPLE=$$(rustc -vV | sed -n 's/^host: //p') && \
	 $(CARGO) test --no-default-features --target $$HOST_TRIPLE --test arch_parity
	@echo "[CI] qemu-test-aarch64 leg 7-line 마커 전량 하드 판정 (boot-join 종결 10.1-01 EL MMU GICR CHILDREN GRP1 IRQ PSCI)"
	@AARCH64_ELF=$(PSCI_ELF) EXPECTED_MARKERS="EL MMU GICR CHILDREN GRP1 IRQ PSCI" QEMU_TIMEOUT=30 bash scripts/qemu-test-aarch64.sh
	@echo "[CI] x86 회귀 leg ci-phase9 standing 상속 실행"
	@$(MAKE) ci-phase9
	@echo "[CI] Phase 10 ci 게이트 전체 통과 (ARM-01..ARM-12 static host GREEN + qemu 7-line 마커 전량 하드 판정)"
