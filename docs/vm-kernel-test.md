# QEMU 커널 부팅 테스트 가이드 (macOS / Ubuntu VM 공용)

`make qemu-smoke` 하나로 macOS(Apple Silicon)와 UTM 호스팅 Ubuntu 24.04 가상환경 어디서든 부팅 테스트를 수행하는 방법. 하네스가 환경(KVM 유무, QEMU 버전)을 자동 감지해 판정 기준을 맞춘다. 검증 결과 기록은 `../task-kernel-eval-improve-vm-result.md` 참조.

## 개요

- 대상 VM: UTM 게스트 Ubuntu 24.04.4, 접속 `ssh qtfelix@192.168.64.5` (비밀번호는 별도 전달, 문서에 기재하지 않음)
- 중요한 제약: VM 호스트가 aarch64이므로 `qemu-system-x86_64`는 TCG(소프트웨어 에뮬레이션) 전용. `/dev/kvm` 부재로 x86 게스트 KVM 가속 불가
- 소스 배치: path 의존(`../elib-k0-nt`) 보존을 위해 `~/k0test/iso-light-k0`와 `~/k0test/elib-k0-nt`를 형제로 둠

## 1. 빠른 실행 (환경 구축 완료 상태)

VM에 툴체인·소스·GRUB 우회가 이미 세팅돼 있으므로 아래 세 줄이면 됩니다.

```bash
ssh qtfelix@192.168.64.5
cd ~/k0test/iso-light-k0
make qemu-smoke      # ISO 빌드 + QEMU 부팅 + 마커 판정 (약 2~3분)
```

빌드만 하려면:

```bash
make build       # debug 커널 + 유저스페이스 ELF
make build-rel   # release 커널 (LTO + opt-level=z)
make iso         # debug ISO
make iso-rel     # release ISO
```

## 2. 판정 모드와 결과 해석 (중요)

하네스(`scripts/qemu-test.sh`)는 ENTROPY_MODE를 자동 결정하고, 각 모드에 맞는 PASS 조건을 적용합니다. `K0_TEST_MODE` 환경변수로 강제 지정할 수 있습니다(full | tcg-entropy | tcg-no-entropy).

| 모드 | 자동 선택 조건 | CPU 플래그 | PASS 조건 |
|---|---|---|---|
| full | /dev/kvm 존재 (x86 Linux) | -cpu host | 전 마커 PASS |
| tcg-entropy | TCG + QEMU >= 11 (현 Mac) | -cpu qemu64,+rdrand,+rdseed | TLS 소거까지 entropy 마커 PASS |
| tcg-no-entropy | TCG + QEMU < 11 (현 VM) | -cpu qemu64 | 부팅 진입 + H5/M12 fail-closed FATAL + reset<=2 |

- **tcg-no-entropy** (VM, QEMU 8.2): RDRAND/RDSEED가 없어 커널이 `init_prng`(`src/main.rs`)에서 의도적으로 부팅을 중단합니다(fail-closed). `FATAL: no hardware entropy` 출력 + CPU Reset 2회가 곧 정상이며 하네스가 이를 PASS로 판정합니다.
- **tcg-entropy** (Mac, QEMU 11.0): QEMU 11.0에서 aarch64 TCG의 RDRAND/RDSEED wild-jump 결함(8.2에서 RIP=0x40B866ECEB4E)이 수정되어 DRBG -> Trust Root -> HsmRegistry -> BLAKE3 -> TLS Classical/PQ-Hybrid까지 런타임 검증됩니다. 단 **TLS 소거 직후 원인 미확정 무증상 폭주(post-TLS stall)** 가 있어 HSM smoke 이후 마커는 "검증 제외"로 표기됩니다(별도 조사 과제). QEMU 9.x·10.x는 미검증이라 보수적으로 tcg-no-entropy로 처리합니다.
- **"CPU Reset 횟수 2"** 는 트리플폴트 없이 깨끗이 halt한 것(정상)입니다. 3 이상이면 크래시입니다.
- QEMU 8.2 환경에서 RDRAND/RDSEED를 수동으로 켜지 마세요(`-cpu max` 등). wild-jump #PF가 결정적으로 발생합니다.
- **full 검증(HSM/BUS/CHAN/WIRE 포함 전 마커)은 여전히 x86 실기 또는 x86+KVM CI가 필요**합니다.

release 커널은 `src/vga.rs`의 출력 함수가 `#[cfg(not(debug_assertions))]` no-op이라 VGA 출력이 전혀 없이 조용히 부팅합니다. release 부팅을 눈으로 보려면 `src/panic.rs`를 시리얼(COM1 포트 0x3F8) 출력으로 임시 계측하세요.

## 2.5. macOS 로컬 실행 (Apple Silicon)

사전 준비(1회):

```bash
brew install qemu xorriso mtools x86_64-elf-grub

# BIOS(i386-pc) GRUB 모듈 준비. Homebrew x86_64-elf-grub은 x86_64-efi 모듈만 제공하므로
# Ubuntu grub-pc-bin(버전 일치 필수, 현재 2.12)에서 i386-pc 모듈을 추출해 배치한다
# (VM이 있으면 scp qtfelix@192.168.64.5:/usr/lib/grub/i386-pc 복사가 가장 빠름)
mkdir -p ~/.local/share/grub
scp -r qtfelix@192.168.64.5:/usr/lib/grub/i386-pc ~/.local/share/grub/i386-pc
```

이후 실행은 VM과 동일하게 `make qemu-smoke` 한 줄입니다. Makefile Darwin 분기가 `x86_64-elf-grub-mkrescue -d ~/.local/share/grub/i386-pc` 폴백을 자동 선택합니다. 시스템 bash 3.2에서도 그대로 동작합니다.

## 3. 정적·빌드타임 보안 게이트 (엔트로피 무관, 항상 검증 가능)

```bash
make check-alloc-zero    # 바이너리 alloc 심볼 0
make check-alloc-bus     # src/bus.rs 소스 alloc 의존 0
make build-rel && make check-no-network   # release 네트워크 심볼 0 (GAP-03)
make check-no-dev-sk     # release dev sk 부재 (Phase 5 D-19)

# C1 build.rs dev 신뢰 루트 게이트
K0_REQUIRE_PROD_TRUST_ROOT=1 cargo build --target x86_64-unknown-none                       # dev 키면 FATAL
K0_REQUIRE_PROD_TRUST_ROOT=1 K0_ALLOW_DEV_TRUST_ROOT=1 cargo build --target x86_64-unknown-none  # override PASS
```

## 4. 소스를 수정했을 때: Mac에서 재전송

VM엔 git이 없으므로 rsync로 동기화합니다. **Mac 터미널**에서 실행:

```bash
cd /Library/Quant/code-projects
rsync -az --delete \
  --exclude 'target/' --exclude '.git/' --exclude '.planning/' \
  --exclude '.idea/' --exclude '*.iso' --exclude 'isodir/' --exclude '.DS_Store' \
  iso-light-k0/ qtfelix@192.168.64.5:k0test/iso-light-k0/
rsync -az --delete --exclude 'target/' --exclude '.git/' --exclude '.DS_Store' \
  elib-k0-nt/ qtfelix@192.168.64.5:k0test/elib-k0-nt/
```

`--delete`는 삭제된 파일도 동기화하되 exclude 대상(target 등 빌드 산출물)은 보존합니다. 전송 후 VM에서 다시 `make qemu-smoke`.

## 5. 처음부터 환경 재구축 (VM 초기화·새 VM)

VM 안에서 순서대로 실행합니다. sudo 비밀번호는 별도 전달.

```bash
# (1) 시스템 도구
sudo apt-get update
sudo apt-get install -y --no-install-recommends qemu-system-x86 xorriso mtools build-essential

# (2) i386-pc GRUB 모듈 (arm64엔 grub-pc-bin이 없어 amd64 deb에서 추출)
#     버전은 VM grub과 일치시킬 것: `dpkg -l grub-common` 로 확인
cd /tmp
curl -sSLO http://archive.ubuntu.com/ubuntu/pool/main/g/grub2/grub-pc-bin_2.12-1ubuntu7.3_amd64.deb
dpkg-deb -x grub-pc-bin_2.12-1ubuntu7.3_amd64.deb grubpc
sudo cp -r grubpc/usr/lib/grub/i386-pc /usr/lib/grub/i386-pc

# (3) Rust (rust-toolchain.toml이 nightly + x86_64-unknown-none + rust-src 자동 설치)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
source ~/.cargo/env
rustup default nightly

# (4) cargo를 모든 셸 모드에서 찾도록 /usr/local/bin 심링크 (6번 참조)
sudo ln -sf ~/.cargo/bin/cargo ~/.cargo/bin/rustc ~/.cargo/bin/rustup \
            ~/.cargo/bin/rustfmt ~/.cargo/bin/cargo-clippy /usr/local/bin/

# (5) Mac에서 소스 rsync (4번) 후
cd ~/k0test/iso-light-k0 && make qemu-smoke
```

## 6. 트러블슈팅: `cargo not found`

증상: `make qemu-smoke` 실행 시 `cargo: not found` 오류.

원인: rustup은 `~/.profile`과 `~/.bashrc`에 `. "$HOME/.cargo/env"`를 추가하지만, 이 파일들은 **로그인·대화형 셸에서만** 소싱됩니다. `ssh host '...make...'` 같은 비로그인 원샷이나 make 레시피(`/bin/sh`)에서는 소싱되지 않아 `~/.cargo/bin`이 PATH에 없습니다.

해결(택1, 위에서 아래로 권장):

```bash
# 방법 A (영구·모든 셸 모드): rustup 프록시를 이미 PATH에 있는 /usr/local/bin에 심링크
sudo ln -sf ~/.cargo/bin/cargo ~/.cargo/bin/rustc ~/.cargo/bin/rustup \
            ~/.cargo/bin/rustfmt ~/.cargo/bin/cargo-clippy /usr/local/bin/
rustup default nightly     # 프로젝트 밖에서도 bare cargo 동작

# 방법 B (세션 한정): make 전에 환경 소싱
source ~/.cargo/env && make qemu-smoke

# 방법 C: 대화형 로그인 셸로 접속해서 실행 (ssh 접속 후 프롬프트에서 실행하면 프로필 소싱됨)
```

현재 VM에는 방법 A가 이미 적용돼 있습니다.

## 7. 한계와 후속 과제

- VM(aarch64/TCG + QEMU 8.2)에서는 부팅 진입·초기화 경로·fail-closed·정적 게이트까지 검증 가능. VM QEMU를 11 이상으로 소스 빌드하면 Mac과 동일한 tcg-entropy 검증도 가능할 것으로 추정(미실험)
- Mac(TCG + QEMU 11)에서는 추가로 TLS 소거까지의 entropy 의존 마커 검증 가능
- **post-TLS stall 원인 미확정**: tcg-entropy 부팅이 TLS 소거 직후 HSM smoke 진입 전에 무증상 폭주함(RIP 선형 증가, #PF·리셋 없음). QEMU 11 TCG 결함 또는 커널 버그(elib 신 API 마이그레이션 구간) 양쪽 다 배제 불가. 이 경로는 최초 런타임 도달이므로 별도 디버그 과제로 조사 필요
- HSM smoke 이후 전 마커(full 검증)는 x86 실기 또는 x86+KVM CI에서 수행 필요
