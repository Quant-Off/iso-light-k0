---
phase: 08-entropy-source-diversification
verified: 2026-07-19T22:36:46Z
status: human_needed
score: 8/8 ENTR host-verifiable (ENTR-07 boot-run + ENTR-03 min-entropy sub-criterion CI-deferred)
overall_verdict: ACHIEVED-WITH-CI-DEFERRALS
re_verification: No — initial verification
verifier_environment: "macOS dev host (no /dev/kvm, QEMU 11 TCG RDRAND/RDSEED defect) — QEMU boot verification impossible here by design"
human_verification: # CI-deferred to Linux+KVM lane (pending, NOT failed — approved Phase 08 deferral pattern)
  - test: "make qemu-kvm — production strict 2-of-3, 13 entropy markers MISS->PASS on real boot serial"
    expected: "13 markers PASS + ENTROPY_QUORUM_2_OF_3_OK + ENTROPY_SOURCES_AVAILABLE=[2-3] + timer: line N>0"
    why_human: "Requires real QEMU boot serial on Linux+KVM; macOS host has no /dev/kvm and QEMU 11 TCG has RDRAND/RDSEED defect. Code + wiring host-verified; only the boot RUN is deferred (ENTR-07, ROADMAP SC #5/#7)"
  - test: "make qemu-tcg (K0_REQUIRE_DEGRADED=1) — degraded-ok virtio-rng-only 13 markers + ENTROPY_DEGRADED_OK_ACTIVE=1 + ENTROPY_QUORUM_1_OF_3_OK"
    expected: "degraded lane markers PASS with gated ENTROPY_DEGRADED_OK_ACTIVE forced-required"
    why_human: "Requires real QEMU boot serial; TCG post-TLS stall on macOS blocks the run. Makefile K0_REQUIRE_DEGRADED=1 wiring host-verified (Makefile L427)"
  - test: "16384-sample jitter min-entropy >= 0.5 bits/sample host-side estimation (ea_iid / NIST SP 800-90B)"
    expected: "min-entropy estimate over BOOT_SELF_TEST_BUF dump >= 0.5"
    why_human: "Requires JITTER_BOOT_DUMP_BEGIN..END boot-serial hex dump from a real boot; no boot serial producible on this host (ENTR-03 sub-criterion, ROADMAP SC #2). RCT/APT core host-verified 6/6"
  - test: "make ci-phase8 — full 6-leg composite final GREEN"
    expected: "4 host legs (already GREEN here) + qemu-kvm + qemu-tcg all pass"
    why_human: "Composite includes the two QEMU legs above; only runnable on Linux+KVM"
---

# Phase 08: Entropy Source Diversification Verification Report

**Phase Goal:** `capability::fill_hw_entropy` 의 RDSEED/RDRAND 단일 소스 의존을 HW + virtio-rng + in-tree JitterRng **3-source quorum (production strict 2-of-3 fail-stop) + NIST SP 800-90B RCT/APT inline health test** 로 교체 — 호출자 (hsm_attest / tls / keystore / DRBG seed) 시그니처 변경 0.
**Verified:** 2026-07-19T22:36:46Z
**Status:** human_needed (all host-verifiable gates GREEN; 2 boot-dependent items CI-deferred to Linux+KVM lane)
**Overall Phase-Goal Verdict:** ACHIEVED-WITH-CI-DEFERRALS
**Re-verification:** No — initial verification
**Verifier stance:** Independent re-run of every host gate; SUMMARY.md claims treated as unverified until reproduced.

## Per-ENTR Verdict Table

| ENTR | Requirement | Verdict | Concrete evidence (independently re-run / read) |
|------|-------------|---------|--------------------------------------------------|
| ENTR-01 | 3 independent sources (HW RDSEED/RDRAND + virtio-rng + in-tree JitterRng) | **PASS-host** | `quorum.rs::collect_from_source` has all 3 branches (0=hw via `x86_64::entropy::hw::collect_hw_into`, 1=`virtio_rng::virtio_collect`, 2=`jitter::jitter_collect_byte`). `virtio-drivers 0.13 default-features=false` in Cargo.toml; `virtio_transport.rs::probe_virtio_rng` genuinely enumerates PCI bus for `DeviceType::EntropySource`. In-tree JitterRng is Müller-derived (no `rand_jitter` crate). `cargo build --target x86_64-unknown-none` **exit 0** (compiles virtio-drivers). |
| ENTR-02 | production strict 2-of-3 fail-stop, no degraded path | **PASS-host** | `quorum.rs` `QUORUM_MIN=2` under `#[cfg(not(feature="entropy-degraded-ok"))]`; `collect` returns `Err(QuorumFailed)` + `audit_enqueue(0xFE, 12, SUB_QUORUM_MIN)` + zeroize when `live_sources < QUORUM_MIN`; `collect_with_retry` `panic!("entropy quorum cannot be restored...")` on budget/spin-ceiling exceed. `capability::fill_hw_entropy` maps to `CapError::NoEntropy`. Host test `entropy_quorum_fault_inject` **3/3** (`one_source_only_panics_within_budget` `should_panic`, real `StreamHealth` evaluator). Boot-halt RUN itself is the qemu-kvm CI-deferred leg. |
| ENTR-03 | NIST SP 800-90B RCT + APT inline per-source | **PASS-host (core)** / DEFERRED-CI (min-entropy sub) | `health.rs` `RCT_CUTOFF=41`, `APT_CUTOFF=793` (W=1024, corrected from plan's 730), applied per-sample in `collect_from_source`. Host test `entropy_health_rct_apt` **6/6** — recomputes binomial CRITBINOM in-host and asserts `APT_CUTOFF == reference (793)` + `RCT == 1+ceil(20/0.5)=41`. **16384-sample min-entropy >= 0.5** needs real boot-serial dump -> CI-deferred. |
| ENTR-04 | virtio 0xFE sentinel + verify-changed silent-pass block | **PASS-host** | `virtio_rng.rs::sentinel_collect_with`: pre-fills 0xFE, calls request, `ct_eq_bytes` verify-changed blocks all-sentinel residue, `zeroize()` on every exit path. `bash scripts/check-virtio-sentinel.sh` -> **PASS (3 patterns)**. Host test `entropy_virtio_sentinel` **4/4** incl. `device_no_write_silent_pass_blocked`. |
| ENTR-05 | build-time feature mutex `compile_error!` | **PASS-host** | `arch/common/entropy/mod.rs` `#[cfg(all(feature="entropy-degraded-ok", feature="tls-external"))] compile_error!(...)`. Independently confirmed: `cargo build --target x86_64-unknown-none --features tls-external,entropy-degraded-ok` -> **`error: entropy-degraded-ok cannot coexist with tls-external`** (build fails). Each feature alone builds **exit 0**. |
| ENTR-06 | single-point `fill_hw_entropy` swap, caller signatures unchanged | **PASS-host** | `capability.rs:188` `unsafe fn fill_hw_entropy(buf: &mut [u8]) -> Result<(), CapError>` signature preserved; body now delegates `QuorumEntropy::collect_with_retry(buf, 60_000)`. Callers `init_prng()` / `reseed_drbg()` unchanged. 4-cfg builds GREEN (closed / degraded / tls-external / both=expected compile_error). |
| ENTR-07 | 13 entropy markers MISS->PASS | **DEFERRED-CI** (wiring host-verified) | `qemu-test.sh`: 12+ markers flipped from `entropy`/`stall` to forced-PASS `"false"` class; 4 new markers recognized (timer, ENTROPY_QUORUM, ENTROPY_SOURCES, gated ENTROPY_DEGRADED). `Makefile::qemu-tcg` exports `K0_REQUIRE_DEGRADED=1` (L427). `main.rs` emits all markers. The boot RUN (markers actually appearing on boot serial) needs Linux+KVM — CI-deferred. |
| ENTR-08 | JitterRng `#[inline(never)]` + `black_box` LTO protection | **PASS-host** | `jitter.rs::jitter_fold_step` `#[inline(never)]`; `black_box` in `fold_one!` macro + `jitter_black_box` + `jitter_collect_byte`. `bash scripts/check-jitter-lto.sh` on real `--release` objdump -> **PASS (instructions=1819 >= 1024, black_box=273 >= 2)**. |

**Host-verifiable score: 8/8 ENTR gates GREEN.** No genuine gaps. Two items (ENTR-07 boot RUN, ENTR-03 min-entropy sub-criterion) are formally CI-deferred to the Linux+KVM lane per the approved Phase 08 deferral pattern — pending, not failed.

## ROADMAP Success Criteria (7) Achievement

| SC | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| SC #1 | 3-source quorum + strict 2-of-3 panic + fault-injection | ✓ host / RUN CI-deferred | quorum.rs code path + fault-inject 3/3 host mirror; boot-halt RUN = qemu-kvm leg |
| SC #2 | per-source RCT/APT + KVM 16384 min-entropy >= 0.5 | ✓ core host / min-entropy CI-deferred | health 6/6 host (793 binomial-locked); min-entropy needs boot serial |
| SC #3 | virtio 0xFE sentinel + verify-changed | ✓ host | check-virtio-sentinel PASS + sentinel 4/4 |
| SC #4 | entropy-degraded-ok ⊕ tls-external compile_error + no runtime policy syscall | ✓ host | dual-feature build FAILS with compile_error (re-run); QUORUM_MIN cfg-conditional, no runtime toggle |
| SC #5 | fill_hw_entropy single swap + 13 markers PASS | ✓ source / 13-marker RUN CI-deferred | capability.rs single-point delegate GREEN; qemu-test.sh flip + Makefile sealing wired |
| SC #6 | JitterRng LTO objdump >= 1024 instr + black_box + TCG self-disable | ✓ host | check-jitter-lto PASS 1819/273; `jitter_boot_self_test` sets `JITTER_DISABLED` on pass_count*2 < N |
| SC #7 | `arch::cpu::timer_frequency()` Option surface + boot serial N>0 | ✓ surface / boot line CI-deferred | Surface present (see note); `elapsed_since_boot_ms` None-safe (Pitfall 12); boot serial line RUN deferred |

**Note (SC #7 signature):** actual surface is `timer_frequency() -> Option<(u64, TimerKind)>`, a superset of the roadmap's `Option<u64>`. The `TimerKind` discriminant is exactly what SC #7 itself needs to emit `timer: invariant_tsc=true` vs `timer: jitter_calibration` on boot serial. The `Option` (divide-by-zero avoidance, the actual Pitfall-12 point) is preserved and correctly handled in `quorum.rs::elapsed_since_boot_ms`. This is a benign enhancement, not a defect.

## Independently Re-run Host Gates (actual output)

| Gate | Command | Result |
|------|---------|--------|
| Closed production build | `cargo build --target x86_64-unknown-none` | exit 0 (Finished dev) |
| entropy-degraded-ok build | `cargo build --target x86_64-unknown-none --features entropy-degraded-ok` | exit 0 |
| tls-external build | `cargo build --target x86_64-unknown-none --features tls-external` | exit 0 |
| **ENTR-05 mutex** | `cargo build --features tls-external,entropy-degraded-ok` | **FAILS: `error: entropy-degraded-ok cannot coexist with tls-external`** (expected) |
| Release build | `cargo build --release --target x86_64-unknown-none` | exit 0 |
| check-alloc-zero | `make check-alloc-zero` | PASS (alloc 심볼 0) |
| check-machete | `make check-machete` | PASS (no unused deps) |
| check-jitter-lto | `bash scripts/check-jitter-lto.sh` | PASS (instructions=1819 black_box=273) |
| check-virtio-sentinel | `bash scripts/check-virtio-sentinel.sh` | PASS (3 patterns) |
| entropy-host-test | `make entropy-host-test` | **18/18 PASS** (5+6+3+4; `--no-default-features` leg fix confirmed working) |

The `entropy-host-test` `--no-default-features` fix (HEAD commit 88ef454) is present and functional: 18/18 pass on this host, matching the SUMMARY claim.

## Behavioral Spot-Checks

| Behavior | Method | Result |
|----------|--------|--------|
| ENTR-05 mutex genuinely blocks | ran dual-feature build | ✓ compile_error emitted, build fails |
| JitterRng loop survives LTO | objdump on real release binary | ✓ 1819 instr, 273 black_box sites |
| Host test suites are substantive (not hollow) | read all 4 test files | ✓ real StreamHealth evaluator, in-host binomial recomputation locks 793, mock-injected sentinel core, EnrollEvent transmute layout assert |
| Fault-inject panic path exists in kernel | read quorum.rs collect/collect_with_retry | ✓ Err(QuorumFailed) + panic! present and wired via capability.rs |

## Artifacts / Wiring (Levels 1-3)

| Artifact | Exists | Substantive | Wired |
|----------|--------|-------------|-------|
| `src/arch/common/entropy/quorum.rs` | ✓ | ✓ (332 lines, strict quorum + BLAKE3 XOF + audit) | ✓ called by capability.rs + main.rs |
| `src/arch/common/entropy/health.rs` | ✓ | ✓ (RCT 41 / APT 793 evaluator) | ✓ used by quorum.rs + jitter.rs |
| `src/arch/common/entropy/jitter.rs` | ✓ | ✓ (Müller fold, inline(never), black_box) | ✓ used by quorum.rs + main.rs boot |
| `src/arch/common/entropy/virtio_rng.rs` | ✓ | ✓ (sentinel_collect_with + KernelHal) | ✓ used by quorum.rs + main.rs boot init |
| `src/arch/x86_64/entropy/hw.rs` | ✓ | ✓ (RDSEED/RDRAND lossless move) | ✓ used by quorum.rs hw branch |
| `src/arch/x86_64/entropy/virtio_transport.rs` | ✓ | ✓ (real PCI ECAM enumerate) | ✓ used by virtio_rng init |
| `src/arch/cpu.rs` | ✓ | ✓ (timer_frequency 3-tier chain + cycle_counter) | ✓ used by jitter + quorum + main.rs |
| `src/capability.rs::fill_hw_entropy` | ✓ | ✓ (single-point delegate) | ✓ init_prng + reseed_drbg |
| `src/main.rs` boot markers | ✓ | ✓ (7-step entropy boot sequence) | ✓ pub mod arch (main.rs:12) |
| `tests/entropy_*.rs` + `audit_entropy_schema.rs` | ✓ | ✓ (18 substantive cases) | ✓ link `iso_light_k0` lib surface |

## Anti-Pattern Scan

- `src/arch/` entropy subtree: **no** TODO/FIXME/XXX/TBD/unimplemented!/todo!/placeholder markers.
- Pre-existing debt markers in phase-touched files (`capability.rs:13,217` TODO about SMP spinlock; `main.rs` various TODO about MMU/scheduler) are **v1.0 code** — `git blame capability.rs:217` -> commit c5775ed4 (2026-05-07), well before Phase 08 (2026-07-19/20), and none sit in Phase 08 entropy regions.
- No TBD/FIXME/XXX (blocker-class markers) in any phase-modified file. Debt-marker blocker gate does **not** fire.
- No stub returns (`return null`/hardcoded empty) in entropy modules; all `Err(...)` paths carry audit_enqueue + zeroize.

## CI-Deferred Items (pending, NOT gaps — approved Phase 08 pattern)

| Item | Reason host cannot run | Deferred to |
|------|------------------------|-------------|
| ENTR-07: 13 markers MISS->PASS on real boot | macOS no /dev/kvm + QEMU 11 TCG RDRAND/RDSEED defect + post-TLS stall | Linux+KVM CI lane (`make qemu-kvm` + `make qemu-tcg`) |
| ENTR-03: 16384-sample jitter min-entropy >= 0.5 | needs JITTER_BOOT_DUMP boot-serial hex dump; no boot serial on this host | Linux+KVM CI lane (host-side ea_iid over dump) |
| SC #7: boot serial `timer:` line N>0 | needs real boot serial | Linux+KVM CI lane |
| `make ci-phase8` full 6-leg composite | includes the two QEMU legs above | Linux+KVM CI lane |

These are consistent with `deferred-items.md` and the CLAUDE.md host-vs-CI split. The code and script/Makefile wiring behind every deferred item is present and host-verified — only the QEMU boot RUN is pending.

## Gaps Summary

**No genuine gaps found.** Every host-verifiable ENTR requirement (ENTR-01/02/04/05/06/08 fully, ENTR-03 core) is implemented in real code (not stubs), independently re-verified via build + script + host-test execution, and correctly wired through `capability::fill_hw_entropy` into the boot path. The only outstanding work is the QEMU boot-serial verification of ENTR-07 (13 markers) and the ENTR-03 16384-sample min-entropy estimate — both structurally impossible to run on this macOS host (no KVM, QEMU 11 TCG defect) and formally deferred to the Linux+KVM CI lane under the approved, pre-agreed Phase 08 deferral pattern. Status is `human_needed` solely to route those two boot-dependent verifications to the CI environment; it does not reflect any code defect.

**Overall Phase-Goal Verdict: ACHIEVED-WITH-CI-DEFERRALS.**

---

_Verified: 2026-07-19T22:36:46Z_
_Verifier: Claude (gsd-verifier) — independent host re-run_
