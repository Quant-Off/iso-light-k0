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
# 기본 타겟
#
.PHONY: all build build-rel iso iso-rel run run-rel run-dbg clean

all: iso

#
# 커널 빌드
#
build:
	$(CARGO) build --target $(TARGET)

build-rel:
	$(CARGO) build --target $(TARGET) --release

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
clean:
	$(CARGO) clean
	@rm -rf $(ISO_DIR) $(ISO_DEBUG) $(ISO_REL)
	@echo "[clean] 완료"
