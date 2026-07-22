# ISO-LIGHT-K0

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

고보안 엣지 게이트웨이, 항공·군수 임베디드 단말, 폐쇄망 데이터 다이오드를 타겟으로 하는 **초경량 `no_std` 보안 마이크로커널**입니다. Rust의 소유권 시스템으로 메모리 안전성을 보장하고, x86_64와 aarch64 두 아키텍처를 단일 코드베이스에서 지원하며, 동적 할당(`alloc`) 없이 정적 할당과 스택만으로 동작합니다.

핵심 목표는 **Multi-HSM Connector**입니다. 사용자가 임의의 신뢰 가능한 HSM(소프트 키스토어, Ring 3 lumen, 향후 USB·SPI·스마트카드)을 커널에 안전하게 부착하고, 커널이 그들 사이의 데이터 중계를 제로 트러스트·상수-시간·동적 할당 0(보안 소거; zeroize)으로 매개합니다.

> [!TIP]
> 자세한 기능 및 아키텍처 설명은 [INTRODUCTION.md](INTRODUCTION.md)를 참고하세요.

## 기능

이 커널은 다음의 기능을 제공합니다.

**멀티 아키텍처 (HAL)**

- x86_64와 aarch64를 단일 코드베이스에서 지원하며, 아키텍처 중립적 요소(기능)을 6개 HAL 트레이트로 강제합니다.
- x86_64는 GRUB Multiboot2 ISO로, aarch64는 QEMU virt `-kernel` 직접 부팅(GICv3, PSCI over HVC, PL011 UART, MMU stage1)으로 진입합니다.
- 펌웨어 중립 `BootInfo` 구조가 Multiboot2·UEFI·DTB 핸드오프를 단일 합류점으로 수렴시킵니다.

**Zero-Trust 격리**

- **Capability-based Access Control**으로 위조 불가 토큰 없이는 IPC 엔드포인트에 접근할 수 없습니다.
- **W^X**으로 쓰기 가능 페이지(writeable page)의 실행을 MMU 레벨에서 차단하고, **Higher-Half**으로 커널(Ring 0) 및 사용자 공간을 완전히 분리합니다.
- x86_64의 `CR0.WP` + `CR4.SMEP/SMAP/UMIP`, aarch64의 PAN으로 사용자 메모리 접근 창을 이중으로 통제합니다.
- 가드 페이지 기반 스택 보호로 IST 및 부트 스택 오버플로를 즉시 탐지합니다.

**Ring 3 사용자 공간**

- 정적 ELF64 로더와 `syscall` ABI로 사용자 프로세스를 격리하고, x86_64는 `iretq`, aarch64는 EL0 강하로 진입합니다.
- 동기 IPC(랑데부 모델)로 메시지 패싱 기반 프로세스 간 통신을 구현합니다.

**커널 내장 암호 서비스**

- **Crypto Service** `EP_CRYPTO` (AES-256-GCM, ChaCha20-Poly1305, BLAKE3 등)
- **PQ Sign Service** `EP_SIGN` (ML-DSA-44 청크 프로토콜)
- **TLS 1.3 PSK** 핸드셰이크 (Closed/External 프로필, `psk_pq_hybrid_ke` = X25519 + ML-KEM-768 하이브리드)

**Multi-HSM Connector**

- 최대 8개 슬롯의 HSM 레지스트리와 `HsmDriver` 추상 트레이트로 다양한 HSM을 동시 부착합니다.
- attach 시점 ML-DSA-44 어테스테이션 게이트(attestation gate)로 신뢰 루트를 검증하고, HSM 미공급 환경은 `SoftKeystore` 폴백을 제공합니다.
- lumen 와이어 호환 버스로 데이터를 중계하며, 감사(audit) ring buffer가 부착 및 중계 이벤트를 기록합니다.

**Air-Gapped Ready**

- 외부망 통신은 `tls-external` feature + 런타임 capability 이중 게이트를 모두 통과해야만 허용됩니다.
- 기본 `closed` 프로필은 네트워크 심볼 자체가 부재해 공격면이 0이며, 부팅 시 self-check로 이를 검증합니다.
- 감사 query syscall로 부착 상태와 이벤트를 원자적으로 조회합니다.

**엔트로피 쿼럼(quorum)**

- virtio-rng, jitter, 하드웨어 난수(x86 RDRAND/RDSEED, aarch64 RNDR/RNDRRS)를 다중 소스로 결합하고 health check로 검증합니다.

**동적 할당 0**

- 모든 버퍼는 정적 할당 또는 스택이며, 토큰·MAC 비교는 `constant-time`으로 부채널 공격을 차단하고, 민감 데이터는 `zeroize`로 소거합니다.
- 암호 프리미티브는 [`elib-k0-nt 1.1.0`](https://github.com/Quant-Off/elib-k0-nt/pull/9) 크레이트만 사용합니다.

## 요구 사항

Rust nightly와 `grub-mkrescue`, `qemu-system-x86_64`이 필요합니다. x86_64는 `x86_64-unknown-none` 타겟을, aarch64 크로스 빌드는 `aarch64-unknown-none-softfloat` 타겟과 `qemu-system-aarch64`을 추가로 사용합니다. 컨테이너로 빌드하는 경우 Docker만으로 충분합니다.

## 빌드

로컬 환경에서는 `make`을 사용합니다.

```bash
$ make user-hello      # 사용자 ELF 빌드 (build-std=core)
$ make user-lumen      # lumen 와이어 호환 사용자 ELF 빌드 (옵션)
$ make build           # 커널 빌드 (debug), 사용자 ELF 자동 prerequisite
$ make iso             # ISO 이미지 생성
$ make run             # QEMU 실행 (x86_64)
$ make run-rel         # Release 빌드 + 실행
$ make run-dbg         # CPU 예외 디버그 (헤드리스, 로그 기록)

$ make build-aarch64   # aarch64 커널 ELF 빌드 (release)
$ make run-aarch64     # QEMU virt 대화형 부팅 (aarch64)
$ make test-aarch64    # aarch64 게이트 전량 (정적 3종 + arch_parity + qemu-smoke)
```

## Docker (Ubuntu 24.04)

호스트에 Rust 툴체인이 없어도 컨테이너로 동일한 결과를 얻을 수 있습니다.

```bash
$ docker compose run --rm build # 컨테이너에서 ELF 빌드
$ docker compose run --rm iso   # 컨테이너에서 ISO 생성
$ docker compose run --rm test  # 컨테이너에서 QEMU 테스트
```

## AI 에이전트 적용 범위

이 프로젝트는 1인 개발 체제이며, AI 에이전트는 **문서 작업**, **감사(audit)**, **Docstring 및 주석 작성**에 한해서만 보조 수단으로 사용합니다. 사용 모델은 Claude Code의 Sonnet 5 / Fable 5 / Opus 4.8이며, 이 프로젝트에서 수행하는 작업은 다음 네 가지로 제한됩니다.

- 명세 및 설명체의 가독성 개선(맥락 정리, 표현 간결화 등)
- Mermaid 다이어그램 생성
- 일반(소개) 문서의 영문 번역본(`*_EN.md`) 작성
- Rust Docstring(`///`, `//!`) 및 팀 단위 기능 흐름 이해를 위한 일반(1레벨) 주석 추가
- 새로 작성된 코드 및 전체 코드베이스 감사(엣지 케이스, 사소한 버그 등)
- 테스트 작성

반대로, 보안에 민감한 부분은 모두 사람이 직접 작성하고 검토합니다. AI 에이전트는 다음 영역에 접근할 수 없도록 작업 범위와 도구 권한 양쪽에서 제한합니다.

- 암호 알고리즘 구현(`elib-k0-nt` 등)
- 커널 시스템 콜 / IPC 핵심 로직
- Capability 검증 및 권한 강제 경로
- 그 외 모든 보안 민감 로직 및 그에 대응되는 명세

각 암호 알고리즘 크레이트, 본 `README.md`, `INTRODUCTION.md`는 [EntanglementLib](https://github.com/Quant-Off/entanglementlib)의 Rust 네이티브 개발 단계부터 사람이 직접 엄밀한 검토와 함께 작성했으며, 소개 문서의 영문 번역본(`*_EN.md`)만 Claude Code의 Sonnet 4.6 / 5가 작성했음을 분명히 밝힙니다. **이 명시는 AI를 활용하는 다른 개발 방식에 대한 평가가 아니라, 본 프로젝트의 신뢰 경계 안에서 AI 사용 범위를 독자에게 투명하게 공개하기 위한 것**입니다.

## 라이선스

이 프로젝트는 [MIT LICENSE](LICENSE)하에 있습니다.
