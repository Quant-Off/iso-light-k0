# ISO-LIGHT-K0

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

다양한 아키텍처와 베어메탈 환경을 타겟으로 하는 **초경량 보안 마이크로커널**입니다. Rust `no_std`에서 메모리 안전성을 보장하며, **Capability-based Access Control**, **동기 IPC**, **Ring 3 사용자 프로세스 로더**(syscall/sysret + SMEP/SMAP/UMIP/W^X 4중 격리)로 최소 권한 원칙을 구현합니다.

> [!TIP]
> 자세한 기능 및 아키텍처 설명은 [INTRODUCTION.md](INTRODUCTION.md)를 참고하세요.

## 요구 사항

Rust nightly와 `x86_64-unknown-none` 타겟, `grub-mkrescue`, `qemu-system-x86_64`이 필요합니다. 컨테이너로 빌드하는 경우 Docker만으로 충분합니다.

## 빌드

로컬 환경에서는 `make`을 사용합니다.

```bash
make user-hello   # 사용자 ELF 빌드 (build-std=core)
make user-lumen   # lumen 와이어 호환 사용자 ELF 빌드 (옵션)
make build        # 커널 빌드 (debug) — 사용자 ELF 자동 prerequisite
make iso          # ISO 이미지 생성
make run          # QEMU 실행
make run-rel      # Release 빌드 + 실행
make run-dbg      # CPU 예외 디버그 (헤드리스, 로그 기록)
```

## Docker (Ubuntu 24.04)

호스트에 Rust 툴체인이 없어도 컨테이너로 동일한 결과를 얻을 수 있습니다.

```bash
docker compose run --rm build # 컨테이너에서 ELF 빌드
docker compose run --rm iso   # 컨테이너에서 ISO 생성
docker compose run --rm test  # 컨테이너에서 QEMU 테스트
```

## AI 에이전트 적용 범위

이 프로젝트는 1인 개발 체제이며, AI 에이전트는 **문서 작업에 한해서만** 보조 수단으로 사용합니다. 사용 모델은 Claude Code의 Sonnet 4.6이며, 수정 가능한 파일 범위는 `.md` 문서로 한정됩니다.

Claude Code가 이 프로젝트에서 수행하는 작업은 다음 네 가지로 제한됩니다.

- 명세·설명체의 가독성 개선(맥락 정리, 표현 간결화 등)
- Mermaid 다이어그램 생성
- 노멀(소개) 문서의 영문 번역본(`*_EN.md`) 작성
- Rust Docstring(`///`, `//!`) 및 일반 주석 추가

반대로, 보안에 민감한 부분은 모두 사람이 직접 작성하고 검토합니다. AI 에이전트는 다음 영역에 접근할 수 없도록 작업 범위와 도구 권한 양쪽에서 제한합니다.

- 암호 알고리즘 구현(`elib-k0-nt` 등)
- 커널 syscall / IPC 핵심 로직
- Capability 검증 및 권한 강제 경로
- 그 외 모든 보안 민감 로직 및 그에 대응되는 명세

각 암호 알고리즘 크레이트, 본 `README.md`, `INTRODUCTION.md`는 EntanglementLib의 Rust 네이티브 개발 단계부터 사람이 직접 엄밀한 검토와 함께 작성했으며, 소개 문서의 영문 번역본(`*_EN.md`)만 Claude Code의 Sonnet 4.6이 작성했음을 분명히 밝힙니다. 이 명시는 AI를 활용하는 다른 개발 방식에 대한 평가가 아니라, 본 프로젝트의 신뢰 경계 안에서 AI 사용 범위를 독자에게 투명하게 공개하기 위한 것입니다.

## 라이선스

이 프로젝트는 [MIT LICENSE](LICENSE)하에 있습니다.