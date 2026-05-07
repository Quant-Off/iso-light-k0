# iso-light-k0

[![Language](https://img.shields.io/badge/README-English_Ver-blue?style=for-the-badge)](README_EN.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

다양한 아키텍처와 베어메탈 환경을 타겟으로 하는 **초경량 보안 마이크로커널**입니다. Rust `no_std`에서 메모리 안전성을 보장하며, **Capability-based Access Control**과 **동기 IPC**으로 최소 권한 원칙을 구현합니다.

> [!TIP]
> 자세한 기능 및 아키텍처 설명은 [INTRODUCTION.md](INTRODUCTION.md)를 참고하세요.

## 요구 사항

Rust nightly와 `x86_64-unknown-none` 타겟, `grub-mkrescue`, `qemu-system-x86_64`이 필요합니다. 컨테이너로 빌드하는 경우 Docker만으로 충분합니다.

## 빌드

로컬 환경에서는 `make`을 사용합니다.

```bash
make build   # 커널 빌드 (debug)
make iso     # ISO 이미지 생성
make run     # QEMU 실행
make run-rel # Release 빌드 + 실행
make run-dbg # CPU 예외 디버그 (헤드리스, 로그 기록)
```

## Docker (Ubuntu 24.04)

호스트에 Rust 툴체인이 없어도 컨테이너로 동일한 결과를 얻을 수 있습니다.

```bash
docker compose run --rm build # 컨테이너에서 ELF 빌드
docker compose run --rm iso   # 컨테이너에서 ISO 생성
docker compose run --rm test  # 컨테이너에서 QEMU 테스트
```

## 라이선스

이 프로젝트는 [MIT LICENSE](LICENSE)하에 있습니다.