# iso-light-k0

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://github.com/Quant-Off/)

An **ultra-lightweight security microkernel** targeting diverse architectures and bare-metal environments. Guarantees memory safety in Rust `no_std`, and enforces the principle of least privilege through **Capability-based Access Control** and **synchronous IPC**.

> [!TIP]
> For detailed features and architecture description, see [INTRODUCTION_EN.md](INTRODUCTION_EN.md).

## Prerequisites

Rust nightly, the `x86_64-unknown-none` target, `grub-mkrescue`, and `qemu-system-x86_64` are required. When building with a container, Docker alone is sufficient.

## Build

Use `make` in a local environment.

```bash
make build   # Build kernel (debug)
make iso     # Generate ISO image
make run     # Run with QEMU
make run-rel # Release build + run
make run-dbg # Debug CPU exceptions (headless, log output)
```

## Docker (Ubuntu 24.04)

You can get the same results in a container even without a Rust toolchain on the host.

```bash
docker compose run --rm build # Build ELF in container
docker compose run --rm iso   # Generate ISO in container
docker compose run --rm test  # Run QEMU tests in container
```

## License

This project is under the [MIT LICENSE](LICENSE).
