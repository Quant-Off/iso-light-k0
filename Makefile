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

# macOS에서 Homebrew로 설치된 GRUB 위치 탐색
ifeq ($(shell uname),Darwin)
    GRUB_MKRES := $(shell \
        for p in \
            /opt/homebrew/bin/grub-mkrescue \
            /usr/local/bin/grub-mkrescue \
            /opt/homebrew/opt/grub/bin/grub-mkrescue; do \
            [ -x "$$p" ] && echo "$$p" && break; \
        done)
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
# 사용자 ELF (Ring 3 스모크 테스트 / lumen 와이어 호환 검증)
#
USER_HELLO_DIR := crates/iso-user-hello
USER_HELLO_ELF := $(USER_HELLO_DIR)/target/$(TARGET)/release/iso-user-hello

USER_LUMEN_DIR := crates/iso-user-lumen
USER_LUMEN_ELF := $(USER_LUMEN_DIR)/target/$(TARGET)/release/iso-user-lumen

#
# 기본 타겟
#
.PHONY: all build build-rel iso iso-rel run run-rel run-dbg clean userspace user-hello user-lumen clean-user check-alloc-zero check-alloc-bus qemu-smoke ci-phase1 ci-phase2 ci-phase3 ci-phase4 chan-dudect check-no-dev-sk qemu-smoke-smoke ci-phase5 wire-attest-host-test ci-phase5_1 ci-phase6 check-no-network qemu-smoke-tls-external

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
