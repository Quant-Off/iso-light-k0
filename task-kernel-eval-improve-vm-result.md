# task-kernel-eval-improve VM 부팅 검증 결과

`task-kernel-eval-improve.md`의 개선 항목을 UTM 호스팅 Ubuntu 24.04.4 가상환경에서 실제 부팅 검증한 기록. 2026-07-18 수행. 커밋 없음(사용자 지시). macOS 호스트에서 불가했던 QEMU 부팅 검증을 수행하는 것이 목적.

## 1. 요약

- H5/M12 fail-closed 패닉이 debug·release 양 프로필에서 런타임 실증됨(`src/main.rs:464`). 이번 작업의 최대 성과
- C1 build.rs dev 신뢰 루트 게이트의 fatal/override 동작이 문서 기대와 정확히 일치함을 실측
- 커널 전체 초기화 경로(SIMD/FPU, TSS, GDT, IDT, W^X, syscall ABI, Multiboot2 mmap 파싱[M7], MMU, 선형매핑)가 실 GRUB 부팅에서 정상 통과
- 단, entropy 의존 보안 마커(DRBG/TLS/HSM/BUS/CHAN/WIRE)는 본 VM에서도 검증 불가. 원인은 aarch64 호스트 QEMU TCG의 RDRAND/RDSEED 에뮬레이션 결함이며, x86 실기 또는 x86+KVM이 필요함을 2번째 플랫폼에서 확증

## 2. 검증 환경

- 접속: `ssh qtfelix@192.168.64.5` (UTM 게스트)
- OS: Ubuntu 24.04.4 LTS, **aarch64(ARM64)**, 6 vCPU, RAM 3.8 GiB, 디스크 여유 22 GiB
- 핵심 제약: 호스트가 aarch64이므로 `qemu-system-x86_64`는 TCG(소프트웨어 에뮬레이션) 전용. `/dev/kvm` 부재로 x86 게스트 KVM 가속 불가
- 초기 상태: git, rust, qemu, grub x86 모듈 전부 미설치(에어갭 유사). 인터넷은 HTTP/HTTPS 가용(ICMP 차단)

### 2.1 설치·전송

- apt 설치: `qemu-system-x86`(8.2.2), `xorriso`, `mtools`, `build-essential`(gcc 13.3)
- rustup nightly + 타깃 `x86_64-unknown-none` + `rust-src`. 커널은 네이티브 aarch64에서 x86으로 크로스 컴파일(에뮬레이션 아님, 빠름)
- 소스 전송: `iso-light-k0`와 path 의존 대상 `elib-k0-nt`(1.1.0)를 형제 레이아웃으로 `~/k0test/`에 rsync(키 인증, target·.git 제외)

### 2.2 arm64 GRUB 우회 (기록 필요)

커널은 multiboot2 헤더 전용(magic 0xE85250D6)이라 GRUB이 필수인데, x86 BIOS ISO 생성용 `grub-pc-bin`이 arm64 apt에 없음(`grub-efi-amd64-bin`도 후보 없음). 우회:

1. amd64 `grub-pc-bin_2.12-1ubuntu7.3_amd64.deb`를 archive.ubuntu.com에서 다운로드(VM grub 버전과 정확히 일치)
2. `dpkg-deb -x`로 풀어 `i386-pc` 모듈 디렉터리를 `/usr/lib/grub/i386-pc`에 복사
3. arm64 `grub-mkimage`가 i386-pc 코어 이미지를 정상 생성 확인 후 `grub-mkrescue`로 BIOS 부팅 ISO 생성

i386-pc 모듈은 타깃 아키텍처 바이트코드라 호스트 아키텍처와 무관하게 이식 가능. 이 우회로 arm64 호스트에서 x86 BIOS 부팅 ISO를 만들 수 있었음.

## 3. 빌드 결과

- `make build`(debug): 유저스페이스 hello·lumen + 커널 debug ELF 통과
- `make build-rel`(release, LTO + opt-level=z): 통과
- `make iso` / `make iso-rel`: debug ISO 16 MB, release ISO 11.5 MB 생성(둘 다 `file` 상 bootable DOS/MBR)
- 빌드 중 C1 dev 신뢰 루트 `cargo:warning` 출력 확인(build.rs 게이트 정상 작동)

## 4. 정적·빌드타임 보안 게이트 (실측)

| 게이트 | 조건 | 결과 |
|---|---|---|
| C1 build.rs | `K0_REQUIRE_PROD_TRUST_ROOT=1` | 빌드 FATAL, exit 101, 명확한 C1 메시지 |
| C1 build.rs | `+K0_ALLOW_DEV_TRUST_ROOT=1` | override PASS(warning + Finished) |
| check-alloc-zero | debug 바이너리 | alloc 심볼 0 통과 |
| check-alloc-bus | src/bus.rs 소스 | alloc 의존 0 통과(BUS-01) |
| check-no-network | release 바이너리 | 네트워크 심볼 0 통과(GAP-03) |
| check-no-dev-sk | release 바이너리 | dev sk 자료·심볼 부재 통과(Phase 5 D-19) |

이번 신설 개선인 C1 게이트의 런타임 동작(dev 키 -> require 시 fatal, allow 시 통과)이 `task-kernel-eval-improve.md` 문서 기대와 정확히 일치함.

## 5. QEMU 부팅 검증

### 5.1 H5/M12 fail-closed 패닉 실증 (핵심)

`make qemu-smoke`(표준 경로, `-cpu qemu64`, 자동 tcg-no-entropy 모드) 실행 시 커널이 초기화 전 과정을 통과한 뒤 `init_prng()`에서 fail-closed:

관측된 VGA 부팅 로그(발췌):

```
[iso-light-k0] Booted. Initializing...
[iso-light-k0] CPU SIMD/FPU Context Ready.
[iso-light-k0] TSS Init... Done.
[iso-light-k0] GDT Init & Apply TSS... Done.
[iso-light-k0] IDT Init... Done.
[iso-light-k0] CR0.WP + CR4.SMEP/SMAP/UMIP + EFER.SCE Ready.
[iso-light-k0] Syscall ABI Installed (STAR/LSTAR/SFMASK).
[iso-light-k0] Multiboot2 Memory Map Parsing(1/2)... (2/2)...
[iso-light-k0] Physic Frame Allocator Init... Done.
[iso-light-k0] MMU Typestate Init Done.
[iso-light-k0] Linear Mapping Done.
[iso-light-k0] Kernel Segment Mapped (W^X + IST Guards).
[iso-light-k0] VGA: linear addr computed (pending activate()).
[iso-light-k0] FATAL: no hardware entropy (RDSEED/RDRAND).
```

이후 `panic!`(`src/main.rs:464`) -> panic.rs의 cli;hlt 무한 루프로 halt. CPU Reset 횟수 2회(정상 전원 리셋만, 트리플폴트 없음). `init_prng`이 CPUID로 RDRAND/RDSEED 부재를 감지해 `CapError::NoEntropy`를 우아하게 반환하므로 #UD 트리플폴트가 아니라 깨끗한 halt로 귀결됨.

즉 하드웨어 엔트로피 부재 시 BOOT_CHALLENGE·capability 토큰을 전부 0으로 발급하지 않고 부팅을 중단하는 **fail-closed가 런타임에서 정확히 발동**함이 실증됨. 이것이 본 검증의 최대 성과.

### 5.2 릴리스 프로필 동일 검증

release ISO는 부팅해도 VGA 출력이 전혀 없어 초기엔 "부팅 실패"로 보였으나, 원인은 `src/vga.rs`의 출력 함수(clear/print/println/print_hex)가 `#[cfg(not(debug_assertions))]`에서 no-op 스텁이라 **릴리스는 VGA 콘솔이 설계상 전무**하기 때문. 실제 동작 확인을 위해 panic.rs를 시리얼(COM1 포트 0x3F8) 출력으로 임시 계측한 결과:

```
[PANIC-DIAG] at src/main.rs:0x1d0 col 0x11
```

0x1d0 = 464행, 0x11 = 17열. 즉 릴리스 커널도 초기화 전 과정을 조용히 통과한 뒤 debug와 **동일하게 `src/main.rs:464`의 H5/M12 fail-closed 패닉**을 실행함. GRUB verbose 계측으로 multiboot2 로드·핸드오프도 정상임을 확인. 진단 후 panic.rs는 원본으로 복원.

결론: H5/M12 fail-closed는 debug·release 양 프로필에서 검증됨.

### 5.3 qemu-smoke 판정과 하네스 정합성

`make qemu-smoke`는 위 부팅에 대해 `✗ 실패`로 판정함. 사유는 구조 마커 `[HsmRegistry static online]` MISS. 그러나 이는 신규 fail-closed가 해당 마커 출력(`src/main.rs:522`)보다 앞선 `init_prng`(452행)에서 부팅을 중단시키기 때문. `scripts/qemu-test.sh`의 tcg-no-entropy 예외 처리는 구(舊) continue-on-error 커널(엔트로피 없어도 구조 마커까지 진행)을 전제로 작성돼 있어 신규 동작과 어긋남.

정리: **커널 동작은 올바르고, 테스트 하네스의 기대가 신규 fail-closed와 정합되지 않음**. 후속으로 tcg-no-entropy 모드에서 "init_prng fail-closed halt + reset<=2"를 PASS 조건으로 갱신 권장.

### 5.4 entropy 의존 마커 검증 불가 (환경 제약 확증)

full-entropy 부팅을 위해 RDRAND/RDSEED를 활성화하면 커널 주석이 예고한 wild-jump가 결정론적으로 재현됨:

```
[KERNEL EXCEPTION] #PF Page Fault  Error Code 0x10 (instruction fetch)
  RIP 0x000040B866ECEB4E   RSP 0x00000000000FC958
```

- RIP·RSP가 커널 주석(`scripts/qemu-test.sh`)에 기록된 맥 Rosetta 값과 **정확히 동일**
- `-cpu qemu64,+rdrand,+rdseed`, `-cpu max`, `-cpu Haswell`, `-cpu Skylake-Client`, `-cpu qemu64,+rdseed` 5종 전부 동일 주소로 재현. CPU 모델 무관
- 커널측 RDRAND/RDSEED 인라인 asm(`src/capability.rs` rdseed64/rdrand64)은 표준 `rdseed {v}` + `setc {c}` 패턴으로 정상. 즉 커널 버그가 아니라 **aarch64 호스트 QEMU TCG의 RDRAND/RDSEED 코드젠 결함**
- 커널 #PF 핸들러가 이를 트리플폴트 없이 깨끗이 처리("System halted. EAL4+ panic.rs hlt loop active", reset=2)하여 예외 경로 견고성도 부수 입증

이 결함은 맥 Rosetta 전용이 아니라 aarch64 호스트 QEMU 전반의 문제임이 네이티브 Linux ARM에서 2번째로 확인됨. 따라서 DRBG·TLS·HSM·BUS·CHAN·WIRE 등 entropy 의존 마커는 본 VM에서 검증 불가하고, **x86 실기 또는 x86+KVM CI가 필수**. 이는 `task-kernel-eval-improve.md`의 후속 인계 판단과 일치.

## 6. 개선 항목별 검증 매트릭스

| 항목 | 검증 방법 | 상태 |
|---|---|---|
| H5/M12 init_prng fail-closed | debug·release 실부팅, 시리얼로 main.rs:464 확인 | 런타임 실증 |
| C1 build.rs 게이트 | require=fatal / allow=override 실측 | 실증 |
| M7 mmap 경계 검증 | 실 GRUB mmap으로 파싱·프레임할당 통과 | 실부팅 통과 |
| M1 getrandom off-by-one | capability 발급 이후 syscall 경로(entropy 의존) 미도달 | 정적 검증까지 |
| SYS-05/H3 NULL 하한 | user-copy 경로(entropy 이후) 미도달 | 정적 검증까지 |
| M3 전영 논스 거부 | crypto_service 경로(entropy 이후) 미도달 | 정적 검증까지 |
| CRY-02 X448 sk zeroize | handle_dh 경로(entropy 이후) 미도달 | 정적 검증까지 |
| TLS-02 ct_eq / TLS-03 zeroize | TLS 핸드셰이크(entropy 의존) 미도달 | 정적 검증까지 |
| DRBG/TLS/HSM/BUS/CHAN/WIRE 마커 | TCG RDRAND 결함으로 부팅 미완주 | 검증 불가(x86 HW/KVM 필요) |
| H1/H2/H4 등 아키텍처 재배치 | 범위 밖, 미착수 | 미수행 |

entropy 의존 경로(M1·SYS-05/H3·M3·CRY-02·TLS-02/TLS-03)는 capability 발급 이후에 실행되므로 tcg-no-entropy 부팅에서 도달하지 못함. 정적(컴파일·린트) 검증 상태를 유지하며, 런타임 검증은 x86 실기/KVM에서 수행 필요.

## 7. 부수 발견

1. **릴리스 VGA 무출력은 정상**: `src/vga.rs`가 릴리스에서 출력 함수를 no-op 스텁으로 대체. 릴리스 부팅 검증은 VGA 대신 시리얼 계측 필요
2. **qemu-test.sh 하네스 stale**: tcg-no-entropy 예외 처리가 신규 fail-closed와 불일치(5.3 참조). 갱신 권장
3. **QEMU TCG RDRAND 결함의 호스트 비종속성**: 맥·Linux-ARM 두 플랫폼에서 동일 RIP 재현. aarch64 QEMU 전반 이슈

## 8. 결론 및 후속 과제

macOS에서 불가했던 실부팅 검증을 수행하여 H5/M12 fail-closed(양 프로필)와 C1 게이트를 런타임 실증했고, 커널 초기화 전 경로의 정상 부팅을 확인함. entropy 의존 마커는 aarch64 호스트 QEMU의 TCG RDRAND 결함으로 본 VM에서도 검증 불가함이 확증됨.

후속 과제:

- entropy 의존 마커·경로(M1·M3·CRY-02·TLS-02/TLS-03·Phase 2~6) 런타임 검증을 x86 실기 또는 x86+KVM CI에서 수행
- `scripts/qemu-test.sh` tcg-no-entropy 모드를 신규 fail-closed 정합되게 갱신(init_prng halt + reset<=2를 PASS 조건화)
- 릴리스 부팅 회귀 검증용 시리얼 계측 절차 표준화
- `task-kernel-eval-improve.md`의 기존 후속 인계(H1·H2·H4·H6·M2·M4~M6·M8~M11 등) 유지
