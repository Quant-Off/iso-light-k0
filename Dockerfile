# Ubuntu 24.04 베어메탈 커널 빌드 + QEMU 테스트 환경
#
# 포함 툴체인:
#   - Rust nightly (rust-toolchain.toml 자동 적용)
#   - grub-mkrescue (BIOS 부팅 ISO 생성)
#   - qemu-system-x86_64 (커널 테스트)
#   - xorriso (ISO 백엔드)

FROM --platform=linux/amd64 ubuntu:24.04

# 패키지 설치 중 대화형 프롬프트 방지
ENV DEBIAN_FRONTEND=noninteractive

# ── 시스템 패키지 ─────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # 기본 빌드 도구
    curl \
    ca-certificates \
    git \
    gcc \
    libc6-dev \
    make \
    # ISO 생성 도구
    xorriso \
    grub-pc-bin \
    grub-common \
    # QEMU (x86_64 타겟)
    qemu-system-x86 \
    # QEMU 모니터(unix socket) + VGA 프레임버퍼 디코딩용 보조 도구
    socat \
    python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# ── Rust 툴체인 (시스템 전역 설치) ───────────────────────────────────────────
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# rustup 설치 + nightly 기본 툴체인
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y \
        --no-modify-path \
        --default-toolchain nightly \
        --component rust-src,rustfmt,clippy \
        --target x86_64-unknown-none \
    && rustup --version \
    && cargo --version \
    && rustc --version

WORKDIR /workspace
