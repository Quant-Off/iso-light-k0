# ISO-LIGHT-K0

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

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

## AI Agent Scope

This project is developed by a single maintainer, and AI agents are used as an auxiliary tool **strictly for documentation work only**. The model in use is Claude Code's Sonnet 4.6, and the editable file scope is limited to `.md` documents. The work that Claude Code performs in this project is restricted to the following four items.

- Improving the readability of specifications and explanatory prose (context arrangement, concise phrasing, etc.)
- Generating Mermaid diagrams
- Producing English translations (`*_EN.md`) of general (introductory) documents
- Adding Rust Docstrings (`///`, `//!`) and ordinary comments

Conversely, every security-sensitive part is written and reviewed directly by a human. AI agents are constrained — through both work scope and tool permissions — so that they cannot reach the following areas.

- Cryptographic algorithm implementations (e.g. `elib-k0-nt`)
- Kernel system call / IPC core logic
- Capability validation and permission enforcement paths
- All other security-sensitive logic and its corresponding specifications

Each cryptographic algorithm crate, the original `README.md`, and `INTRODUCTION.md` have been written by a human with rigorous review since the Rust-native development stage of [EntanglementLib](https://github.com/Quant-Off/entanglementlib); we make it explicit that only the English translations (`*_EN.md`) of the introductory documents were produced by Claude Code's Sonnet 4.6. **This disclosure is not a judgment on other development practices that leverage AI, but is intended to transparently communicate to readers the scope of AI use within this project's trust boundary.**

## License

This project is under the [MIT LICENSE](LICENSE).
