# ISO-LIGHT-K0

[![Language](https://img.shields.io/badge/README-Korean_Ver-blue?style=for-the-badge)](README.md)
[![Qu4nt-Space-Discord](https://img.shields.io/badge/Qu4nt_Space-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/9utg4hp3m8)

An **ultra-lightweight `no_std` security microkernel** targeting high-security edge gateways, avionics and defense embedded terminals, and air-gapped data diodes. It guarantees memory safety via Rust's ownership system, supports both the x86_64 and aarch64 architectures from a single codebase, and operates using only static allocation and the stack, with no dynamic allocation (`alloc`).

Its core goal is the **Multi-HSM Connector**. Users can safely attach any trustworthy HSM (soft keystore, Ring 3 lumen, and USB/SPI/smartcard in the future) to the kernel, and the kernel mediates data relay between them with zero-trust, constant-time, and zero dynamic allocation (secure zeroing; zeroize).

> [!TIP]
> For detailed features and architecture, see [INTRODUCTION_EN.md](INTRODUCTION_EN.md).

## Features

This kernel provides the following features.

**Multi-architecture (HAL)**

- Supports x86_64 and aarch64 from a single codebase, enforcing architecture-neutral elements through 6 HAL traits.
- x86_64 boots via a GRUB Multiboot2 ISO; aarch64 boots directly through QEMU virt `-kernel` (GICv3, PSCI over HVC, PL011 UART, MMU stage1).
- A firmware-neutral `BootInfo` structure converges Multiboot2/UEFI/DTB handoffs into a single join point.

**Zero-Trust isolation**

- **Capability-based Access Control** makes IPC endpoints unreachable without an unforgeable token.
- **W^X** blocks execution of writable pages at the MMU level, and **Higher-Half** fully separates kernel (Ring 0) and user space.
- x86_64's `CR0.WP` + `CR4.SMEP/SMAP/UMIP` and aarch64's PAN doubly control the user-memory access window.
- Guard-page-based stack protection immediately detects IST and boot stack overflows.

**Ring 3 user space**

- Isolates user processes with a static ELF64 loader and the `syscall` ABI; x86_64 enters via `iretq`, aarch64 via EL0 descent.
- Implements message-passing inter-process communication through synchronous IPC (rendezvous model).

**Kernel-embedded cryptographic services**

- **Crypto Service** `EP_CRYPTO` (AES-256-GCM, ChaCha20-Poly1305, BLAKE3, and more)
- **PQ Sign Service** `EP_SIGN` (ML-DSA-44 chunk protocol)
- **TLS 1.3 PSK** handshake (Closed/External profiles, `psk_pq_hybrid_ke` = X25519 + ML-KEM-768 hybrid)

**Multi-HSM Connector**

- Attaches diverse HSMs concurrently through an up-to-8-slot HSM registry and the `HsmDriver` abstract trait.
- An ML-DSA-44 attestation gate verifies the trust root at attach time, and a `SoftKeystore` fallback covers environments with no HSM.
- Relays data over a lumen wire-compatible bus, and an audit ring buffer records attach and relay events.

**Air-Gapped Ready**

- External-network communication is permitted only after passing both the `tls-external` feature gate and a runtime capability double gate.
- The default `closed` profile has zero attack surface because the network symbols are absent altogether, verified by a boot-time self-check.
- An audit query syscall atomically inspects attach state and events.

**Entropy quorum**

- Combines multiple sources, virtio-rng, jitter, and hardware RNG (x86 RDRAND/RDSEED, aarch64 RNDR/RNDRRS), and validates them with a health check.

**Zero dynamic allocation**

- Every buffer is statically allocated or on the stack; token/MAC comparisons block side-channel attacks via `constant-time`, and sensitive data is wiped with `zeroize`.
- Cryptographic primitives use only the [`elib-k0-nt 1.1.0`](https://github.com/Quant-Off/elib-k0-nt/pull/9) crates.

## Prerequisites

Rust nightly, `grub-mkrescue`, and `qemu-system-x86_64` are required. x86_64 uses the `x86_64-unknown-none` target; aarch64 cross builds additionally use the `aarch64-unknown-none-softfloat` target and `qemu-system-aarch64`. When building with a container, Docker alone is sufficient.

## Build

Use `make` in a local environment.

```bash
$ make user-hello      # Build user ELF (build-std=core)
$ make user-lumen      # Build lumen wire-compatible user ELF (optional)
$ make build           # Build kernel (debug), user ELF is an automatic prerequisite
$ make iso             # Generate ISO image
$ make run             # Run with QEMU (x86_64)
$ make run-rel         # Release build + run
$ make run-dbg         # Debug CPU exceptions (headless, log output)

$ make build-aarch64   # Build aarch64 kernel ELF (release)
$ make run-aarch64     # QEMU virt interactive boot (aarch64)
$ make test-aarch64    # Full aarch64 gate (3 static gates + arch_parity + qemu-smoke)
```

## Docker (Ubuntu 24.04)

You can get the same results in a container even without a Rust toolchain on the host.

```bash
$ docker compose run --rm build # Build ELF in container
$ docker compose run --rm iso   # Generate ISO in container
$ docker compose run --rm test  # Run QEMU tests in container
```

## AI Agent Scope

This project is developed by a single maintainer, and AI agents are used as an auxiliary tool only for **documentation work**, **audits**, and **Docstring and comment writing**. The models in use are Claude Code's Sonnet 5 / Fable 5 / Opus 4.8, and the work performed in this project is restricted to the following.

- Improving the readability of specifications and explanatory prose (context arrangement, concise phrasing, etc.)
- Generating Mermaid diagrams
- Producing English translations (`*_EN.md`) of general (introductory) documents
- Adding Rust Docstrings (`///`, `//!`) and ordinary (level-1) comments for team-wide understanding of feature flow
- Auditing newly written code and the entire codebase (edge cases, minor bugs, etc.)
- Writing tests

Conversely, every security-sensitive part is written and reviewed directly by a human. AI agents are constrained, through both work scope and tool permissions, so that they cannot reach the following areas.

- Cryptographic algorithm implementations (e.g. `elib-k0-nt`)
- Kernel system call / IPC core logic
- Capability validation and permission enforcement paths
- All other security-sensitive logic and its corresponding specifications

Each cryptographic algorithm crate, this `README.md`, and `INTRODUCTION.md` have been written by a human with rigorous review since the Rust-native development stage of [EntanglementLib](https://github.com/Quant-Off/entanglementlib); we make it explicit that only the English translations (`*_EN.md`) of the introductory documents were produced by Claude Code's Sonnet 4.6 / 5. **This disclosure is not a judgment on other development practices that leverage AI, but is intended to transparently communicate to readers the scope of AI use within this project's trust boundary.**

## License

This project is under the [MIT LICENSE](LICENSE).
