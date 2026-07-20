---
phase: 09-architecture-hal-extraction
plan: 06
subsystem: infra
tags: [hal, no_std, aarch64-stub, cfg-conditional, surface-lock, ci-gate, phase10-handoff, rust]

# Dependency graph
requires:
  - phase: 09-architecture-hal-extraction
    plan: 05
    provides: HAL-06 최초 수렴 (check-arch-cfg-gate exit 0) + src/boot 4-어댑터 + _kernel_start(&BootInfo) 합류점 + x86_64 hub 5 ZST + Entropy 첫 구현체
  - phase: 09-architecture-hal-extraction
    plan: 01
    provides: 6 HAL trait 계약 표면 (Cpu Mmu Idt Console BootEntry Entropy) + ci-phase9 합성 타깃 + 게이트 스크립트 5종
provides:
  - src/arch/aarch64/mod.rs stub 허브 (6 trait 두 번째 구현체 진입 표면 잠금, unimplemented 골격 cfg aarch64 배제)
  - src/arch/mod.rs aarch64 cfg 분기 + pub use aarch64 as active (HAL-02 cfg-conditional re-export 양방향 완성)
  - Phase 10 인계 문서 deferred-items.md (A1 / OQ1 / ARM-01 / ARM-11 / iretq-eret / uefi LIVE-01 / qemu 이연 lane)
  - docs/dispatch-reachability.md 이동 파일 경로 갱신 (syscall/idt/vga -> arch/x86_64)
  - ci-phase9 host 9-leg 최종 실측 GREEN (qemu-smoke leg Linux+KVM lane 이연)
affects: [phase-10-arm-port, phase-11-live, phase-12-matrix]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "aarch64 stub 허브 = x86_64 hub 대칭 6 ZST + unimplemented 본문 골격 cfg(target_arch = aarch64) 게이트로 x86_64 산출물 완전 배제 (OQ4 텍스트 표면 잠금)"
    - "cfg-conditional re-export 양방향 = x86_64/aarch64 각각 pub mod + pub use as active 로 활성 아키텍처 단일 진입점 (HAL-02)"
    - "Phase 10 진입 anchor = trait 두 번째 구현체 작성이 단일 작업이 되도록 표면·가정(A1/OQ1/Pitfall8) 을 문서로 잠금"

key-files:
  created:
    - src/arch/aarch64/mod.rs
    - .planning/phases/09-architecture-hal-extraction/deferred-items.md
  modified:
    - src/arch/mod.rs
    - docs/dispatch-reachability.md

key-decisions:
  - "OQ4 채택 9-D 검증은 텍스트 표면 잠금 3종 (골격 파일 존재 + x86_64 빌드 무영향 + grep 게이트) cargo check aarch64-unknown-none-softfloat 는 Phase 10 ARM-01 이월 (타깃 미설치 실측 확인)"
  - "aarch64 hub 는 6 ZST (Aarch64Cpu/Mmu/Idt/Console/BootEntry/Entropy) 로 x86_64 hub 5 ZST + Entropy(QuorumEntropy 위임) 대비 Entropy 도 arch-특화 ZST 로 분리 잠금 (Phase 10 이 RNDR/RNDRRS 배선)"
  - "qemu-smoke leg 는 macOS KVM 부재 + TCG stall + ISO 빌드/ML-KEM keygen 이 wall-clock 창 초과로 Linux+KVM lane 이연 (Phase 8 및 9-A~9-C 선례 계승 honest 표기)"

patterns-established:
  - "봉인 wave = 표면 잠금(코드) + 가정 인계(문서) + 합성 게이트 최종 실측 3-축으로 phase 를 git bisectable 로 종료"

requirements-completed: [HAL-01, HAL-02, HAL-03, HAL-09]

# Metrics
duration: 14min
completed: 2026-07-20
---

# Phase 9 Plan 06: 9-D aarch64 stub 표면 잠금 + Phase 10 인계 + ci-phase9 최종 봉인 Summary

**x86_64 hub 와 대칭인 aarch64 stub 허브 (6 ZST unimplemented 골격) 를 신설해 6 HAL trait 두 번째 구현체 진입 표면을 잠그고 (arch/mod.rs cfg 분기 + active alias 양방향 완성), x86_64 산출물에 aarch64 심볼 유입 0 을 nm 으로 실측했으며, A1/OQ1/ARM-01/ARM-11/iretq-eret/uefi LIVE-01/qemu 이연 lane 을 Phase 10 인계 문서로 잠그고 dispatch-reachability 이동 경로를 갱신한 뒤 ci-phase9 host 9-leg 를 최종 GREEN 실측해 Phase 9 를 봉인했다 (qemu-smoke leg 는 Linux+KVM lane 이연 honest 표기).**

## Performance

- **Duration:** 14분
- **Started:** 2026-07-20T05:42Z
- **Completed:** 2026-07-20T05:56Z
- **Tasks:** 2 완료 (각 원자적 커밋)
- **Files:** 2 created + 2 modified

## Accomplishments
- aarch64 stub 허브 신설 (9-D 표면 잠금) — src/arch/aarch64/mod.rs 에 x86_64 hub 대칭 한국어 Docstring (# Features, Phase 10 이 6 trait 두 번째 구현체를 채울 자리 명시) + 6 ZST (Aarch64Cpu/Aarch64Mmu/Aarch64Idt/Aarch64Console/Aarch64BootEntry/Aarch64Entropy) + trait impl 시그니처 stub (본문 unimplemented! ARM-01 골격). Mmu typestate 는 Aarch64MmuUninit/Init/AddrSpace 3 placeholder ZST 로 연관 타입 잠금
- HAL-02 cfg-conditional re-export 양방향 완성 — src/arch/mod.rs 에 `#[cfg(target_arch = "aarch64")] pub mod aarch64;` + `pub use aarch64 as active;` 추가, x86_64 분기와 대칭. 활성 아키텍처가 `crate::arch::active` 단일 진입점으로 노출
- x86_64 빌드 무영향 실측 (T-09-06 완화) — cargo build --target x86_64-unknown-none GREEN (선존 dev trust-root 경고만) + make build-rel GREEN + `nm release ELF | grep -ci aarch64` == 0 (stub 미유입 확정) + check-arch-cfg-gate exit 0 유지 (aarch64 cfg 는 src/arch/ 내부)
- Phase 10 인계 문서 (deferred-items.md) 신설 — A1 abi_x86_interrupt aarch64 컴파일 무해성 가정 / OQ1 syscall ABI-중립 분할 (SyscallNum/SyscallError/SyscallContext/is_user_address, SyscallContext 의 rdi/rsi/rdx 를 hsm_registry·air_gap 이 직접 소비 Pitfall 8) / ARM-01 타깃·링커 / ARM-11 secure_zero str xzr 실검증 / iretq·eret Ring3 강하 실검증 / uefi.rs 본문 Phase 11 LIVE-01 / qemu 이연 lane 전 sub-step 취합
- docs 경로 갱신 + ci-phase9 최종 봉인 — dispatch-reachability.md 구 경로 (src/syscall.rs / src/idt.rs / src/vga.rs) 를 신 경로 (src/arch/x86_64/*) 로 정정 (라인 번호는 역사 기록물 성격 유지), ci-phase9 host 9-leg 전수 GREEN 실측

## ci-phase9 최종 게이트 실측 (Task 2)

| leg | 결과 | 실측값 |
|-----|------|--------|
| check-alloc-zero | PASS (exit 0) | alloc 심볼 0 (Phase 1 standing BSS 가산 회귀) |
| check-machete | PASS (exit 0) | unused dependency 0 + dead-pub-item 0 (Phase 7 standing) |
| check-entropy-mutex | PASS (exit 0) | ENTR-05 entropy-degraded-ok x tls-external compile_error mutex (Phase 8 standing) |
| check-jitter-lto | PASS (exit 0) | JitterRng LTO 보호 instructions=1819 black_box=273 (Phase 8 standing) |
| check-arch-cfg-gate | PASS (exit 0) | cfg(target_arch) 0 sites outside src/arch/ (HAL-06, aarch64 stub 추가 후 무회귀) |
| check-ct-branches | PASS (exit 0) | authenticate branch=0 · CtLess branch=0 · verify_attest branch=41 관측 전용 (SC #8) |
| check-secure-zero | PASS (exit 0) | secure_zero 심볼 존재 + memset U-entry 0 (HAL-05) |
| check-body-untouched | PASS (exit 0) | tier1=6/50 · tier2=85/150 (HAL-04 base=770ec68, aarch64/mod.rs·arch/mod.rs 는 본체·main.rs 아님 무영향) |
| check-mmu-typestate | PASS (exit 0) | activate 오호출 E0599 컴파일 거부 존속 (HAL-07) |
| **qemu-smoke (10th leg)** | **이연 (Linux+KVM lane)** | macOS Apple Silicon KVM 부재 + QEMU 11 TCG stall + ISO 빌드/ML-KEM-768 keygen 이 wall-clock 창(2분) 초과 -> 마커 평가 미도달. 부팅 경로 무결성은 host 9-leg + nm 링크 실측(전 wave) 로 확보, 마커 실검증은 Linux+KVM lane 이연 (silent skip 아님, deferred-items.md 등재) |
| host test (cargo test --no-default-features) | PASS | 17 pass + 1 ignored = 18 (aarch64 stub 추가 후 무회귀) |

## Decisions Made
- OQ4 이행 — 9-D 검증은 텍스트 표면 잠금 3종 (골격 파일 + arch/mod.rs cfg 분기 존재 / x86_64 빌드 무영향 / grep·nm 게이트). aarch64-unknown-none-softfloat 타깃이 미설치임을 실측 확인하고 첫 실컴파일은 Phase 10 ARM-01 이월
- Entropy 도 arch-특화 ZST (Aarch64Entropy) 로 분리 잠금 — x86_64 는 Entropy 를 arch-중립 QuorumEntropy 에 impl 하나 aarch64 는 RNDR/RNDRRS + jitter quorum 이 arch-특화이므로 두 번째 구현체 표면을 ZST 로 명시 잠금 (Phase 10 이 배선)
- qemu-smoke leg 이연 (아래 Deviations 1) — 환경 제약 계승, host 9-leg 실측으로 대체 확보

## Deviations from Plan

### 필연 이연 / 포맷 이행 Issues

**1. [환경 제약 이연] qemu-smoke leg Linux+KVM lane 이연**
- **Found during:** Task 2 (ci-phase9 최종 실측)
- **Issue:** 본 macOS Apple Silicon 호스트는 /dev/kvm 부재로 QEMU 11 TCG 폴백. `make qemu-smoke` 가 ISO 빌드 + ML-KEM-768 TCG keygen + post-TLS stall 로 2분 wall-clock 창 내 마커 평가에 미도달 (bounded gtimeout 실측, 09-02/03/04/05 및 Phase 8 확립된 환경 제약).
- **Fix:** silent skip 금지 원칙에 따라 SUMMARY 실측 표와 deferred-items.md 양쪽에 이연 honest 표기. ci-phase9 host-runnable 9-leg 전수 GREEN 실측으로 회귀 가드 확보 + 전 wave nm 링크 실측으로 부팅 경로 무결성 확보. QEMU 마커 실검증은 Linux+KVM lane 이연 (T-09-06).
- **Files modified:** 없음 (게이트 실측 이연 기록)
- **Committed in:** `e807f0e` (deferred-items.md)

---

**2. [경로 정정] read_first 의 src/cpu.rs 실경로 정정**
- **Found during:** Task 1 (read_first)
- **Issue:** plan Task 1 read_first 가 "src/cpu.rs L466-483 상당의 구 aarch64 스텁 관례" 를 참조하나 해당 파일은 9-A 이동 후 src/arch/x86_64/cpu.rs (L490-513) 에 존재. src/cpu.rs 는 부재.
- **Fix:** src/arch/x86_64/cpu.rs L490-513 의 기존 aarch64 스텁 관례 (`#[cfg(target_arch = "aarch64")]` enable_simd_fpu/finalize_simd_fpu) 와 common/mod.rs secure_zero aarch64 분기 (str xzr) 를 참조해 stub 스타일 정합. 코드 변경 무관 (읽기 경로 정정).
- **Files modified:** 없음

---

**3. [CLAUDE.md 이행] 커밋 메시지 포맷 오버라이드**
- **Issue:** executor 기본 conventional 포맷 (`type(phase-plan): ...`) 은 프로젝트/전역 CLAUDE.md (prefix·콜론·em-dash·middot·period 금지, 한국어 plain-text) 와 충돌.
- **Fix:** 전 커밋을 한국어 plain-text 로 작성 (9-A~9-C 선례 계승).
- **Files modified:** 없음 (커밋 규약)

---

**Total deviations:** 3 (1x 환경 제약 이연 · 1x 읽기 경로 정정 · 1x CLAUDE.md 포맷 이행)
**Impact on plan:** aarch64 stub 표면 잠금 + cfg 분기 + 인계 문서 + docs 갱신 + ci-phase9 host 9-leg 실측 전부 계획대로 완결. x86_64 nm aarch64 심볼 0 · check-arch-cfg-gate 무회귀 · host 18 test 무회귀. scope creep 없음, 본체 무변경 유지 (body-untouched tier1=6/50).

## Issues Encountered
- **qemu-smoke wall-clock 초과 이연:** bounded gtimeout 220s 로 honest 시도했으나 harness 2분 창 내 ISO 빌드/부팅 미완. 09-02~09-05 확립된 macOS TCG 환경 제약이며 본 wave (aarch64 stub 추가) 이 유발한 회귀 아님 — aarch64 stub 은 cfg(target_arch = aarch64) 로 x86_64 부팅 경로에서 완전 배제됨 (nm aarch64 == 0 실측). QEMU 마커 실검증은 Linux+KVM lane 이연.

## User Setup Required
None - 외부 서비스 구성 불필요. 신규 의존성 0 (cargo add 0건).

## Known Stubs
- `src/arch/aarch64/mod.rs` 전체 (6 ZST + trait impl 본문 unimplemented!) — 본 plan 의 명시 산출 정의 (9-D 표면 잠금 OQ4). aarch64 타깃 미설치로 컴파일 배제 상태이며 x86_64 부팅 경로에 진입 불가 (nm aarch64 == 0). Phase 10 ARM-01 이 DAIF/CPACR_EL1/TTBR0_EL1/PL011/eret/RNDR asm 로 본문 채움. 이 stub 은 소비자 구현이 아니라 "trait 두 번째 구현체 진입 표면 잠금" 이 목표이므로 plan 목표를 저해하지 않음
- `src/boot/uefi.rs::parse_uefi` (09-05 계승) — 시그니처-only stub, Phase 11 LIVE-01 이 본문 채움. deferred-items.md 에 인계 등재
- `secure_zero` aarch64 분기 (str xzr, 09-01 계승) — 골격만 존재, Phase 10 ARM-11 실검증. deferred-items.md 에 인계 등재

## Threat Flags
없음 — 신규 network endpoint / auth path / 파일 접근 / schema 변경 0. threat_model 3종 전부 게이트로 완화 확인:
- T-09-06 (aarch64 stub 의 x86_64 빌드 유입): cfg(target_arch = aarch64) 게이트 + nm aarch64 심볼 0 실측 + x86_64 dev/release 양 프로필 회귀 GREEN
- T-09-02 (최종 시점 CT 게이트 미실행): ci-phase9 check-ct-branches release branch=0/0 최종 실측 (standing gate 존속)
- T-09-04 (인계 문서 누락으로 Phase 10 가정 미인지): deferred-items.md acceptance grep (abi_x86_interrupt / SyscallContext / LIVE-01) 전수 통과

## Next Phase Readiness
- 9-D 표면 잠금 완결 — Phase 10 aarch64 포트는 (1) `rustup target add aarch64-unknown-none-softfloat` (2) linker-aarch64.ld 신설 (3) src/arch/aarch64/mod.rs 의 6 ZST unimplemented 본문 채움 (4) A1 abi_x86_interrupt aarch64 무해성 검증 (5) OQ1 syscall ABI-중립 분할 순으로 진입. cfg 폭증 없이 "trait 두 번째 구현체 작성" 단일 작업
- Phase 9 전 sub-step (9-A/9-B/9-C/9-D) 각각 git bisectable PASS 게이트로 봉인 (HAL-09) — ci-phase9 host 9-leg standing gate 성립
- QEMU 2-leg (부팅 마커 + iretq/eret 실검증) 은 Linux+KVM lane 이연 지속 — deferred-items.md 에 ci-phase9 + ci-phase{1..6} qemu leg 재실행 목록 등재
- STATE.md / ROADMAP.md 는 orchestrator 가 wave 종료 후 중앙 갱신 (worktree 모드 규약, 본 executor 미변경)

## Self-Check: PASSED

- 생성 파일 2종 FOUND (src/arch/aarch64/mod.rs + deferred-items.md) + 09-06-SUMMARY.md
- 수정 파일 2종 반영 (src/arch/mod.rs aarch64 분기 + docs/dispatch-reachability.md 경로 갱신)
- 커밋 2종 FOUND (fb98be2 Task1 aarch64 stub / e807f0e Task2 인계+docs+ci)
- 게이트 재현 GREEN (nm aarch64 == 0 · check-arch-cfg-gate exit 0 · host 17+1=18 · ci-phase9 host 9-leg 전수 PASS)

---
*Phase: 09-architecture-hal-extraction*
*Completed: 2026-07-20*
