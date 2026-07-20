---
phase: 09-architecture-hal-extraction
plan: 01
subsystem: infra
tags: [hal, no_std, inline-asm, ci-gate, objdump, typestate, secure-zero, rust]

# Dependency graph
requires:
  - phase: 08-entropy-source-diversification
    provides: QuorumEntropy associated fn collect + EntropyError + arch/common/entropy 서브트리 + ci-phase8 게이트 관례
provides:
  - 6 HAL trait 계약 (Cpu Mmu Idt Console BootEntry Entropy) src/arch/mod.rs 단일 파일 (HAL-01)
  - Entropy 첫 구현체 impl Entropy for QuorumEntropy thin wrapper
  - arch::common::secure_zero rep stosb black-box zeroization + nm 게이트 GREEN (HAL-05)
  - CI 게이트 스크립트 4종 (check-arch-cfg-gate / check-ct-branches / check-secure-zero / check-body-untouched)
  - mmu typestate 음성 probe (HAL-07) + Makefile ci-phase9 합성 타깃
  - scripts/phase9-base-commit (본체 diff 측정 base)
affects: [09-02, 09-03, 09-04, 09-05, 09-06, phase-10-arm-port, phase-12-matrix]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "6 HAL trait 전부 수신자 없는 associated fn -> dyn 구조적 차단 (HAL-02)"
    - "secure_zero #[inline(never)] + #[unsafe(no_mangle)] + #[used] fn-pointer 앵커로 --gc-sections 생존"
    - "CT 분기 게이트 fragment 쌍 심볼 anchor + awk 절단 + objdump/gobjdump fallback (Phase 12 prior art)"
    - "본체 무변경 2-tier diff-stat 게이트 (base commit 파일 + git diff -M)"

key-files:
  created:
    - scripts/phase9-base-commit
    - scripts/check-arch-cfg-gate.sh
    - scripts/check-ct-branches.sh
    - scripts/check-secure-zero.sh
    - scripts/check-body-untouched.sh
    - tests/compile-fail/mmu-typestate.rs
    - src/arch/mmu_typestate_probe.rs
  modified:
    - src/arch/mod.rs
    - src/arch/common/mod.rs
    - Cargo.toml
    - Makefile

key-decisions:
  - "CT 게이트 대상 심볼을 plan 명명(capability::authenticate / hsm_attest::verify_signature)이 아닌 실존 심볼(hsm_registry::authenticate / constant_time::CtLess)로 정정 — 실측 미실존 명명"
  - "verify_attest 는 D-12 설계상 입력 독립 분기 41건 보유 -> CT 분기 0 게이트 비대상, 관측 전용 보고로 분리"
  - "secure_zero 는 #[used] fn-pointer 앵커 없이는 --gc-sections 가 회수 -> no_mangle 단독 심볼 보존 가정 정정"
  - "host test 는 .cargo/config.toml 기본 타깃 고정으로 --target <host triple> 필수 (Makefile entropy-host-test 관례)"

patterns-established:
  - "interface-first HAL trait 계약 먼저, impl 이동은 Wave 2+"
  - "CI 게이트 baseline 실측이 이후 sub-step 회귀 기준점"

requirements-completed: [HAL-01, HAL-02, HAL-03, HAL-05, HAL-06, HAL-07]

# Metrics
duration: 132min
completed: 2026-07-20
---

# Phase 9 Plan 01: HAL 계약 + Wave 0 검증 인프라 Summary

**6 HAL trait 계약과 secure_zero rep stosb zeroization 을 정의하고, 파일 이동 전에 4종 CI 게이트 baseline 을 실측해 이후 5개 plan 의 회귀 기준점을 확정했다.**

## Performance

- **Duration:** 132분 (세션 리셋 걸침, 실작업 시간 기준)
- **Started:** 2026-07-20T02:05:39Z
- **Completed:** 2026-07-20T04:17:44Z
- **Tasks:** 3 완료
- **Files modified:** 11 (7 created + 4 modified)

## Accomplishments
- 6 HAL trait (Cpu Mmu Idt Console BootEntry Entropy) 단일 파일 정의 + Entropy 첫 구현체 연결, dyn/Box 0, 커널 빌드 GREEN (HAL-01/02/03)
- secure_zero rep stosb black-box zeroization 신설, release 바이너리 T secure_zero 심볼 실측 + memset U-entry 0 (HAL-05)
- CI 게이트 4종 + mmu typestate 음성 probe + ci-phase9 합성 타깃 배선, baseline 실측 (ct-branches PASS / body-untouched PASS / secure-zero PASS / mmu-typestate PASS / arch-cfg-gate 54건 FAIL 예상 상태)

## Task Commits

각 task 원자적 커밋:

1. **Task 1: CI 게이트 스크립트 4종 + mmu-typestate probe + Makefile ci-phase9** - `6dcc47d`
2. **Task 2: src/arch/mod.rs 6 HAL trait 정의 + Entropy 첫 구현체** - `0e93120`
3. **Task 3: arch::common::secure_zero inline-asm 구현 + nm 게이트 GREEN** - `6c0d8dd`

## Files Created/Modified
- `scripts/phase9-base-commit` - Phase 9 시작 base commit 해시 (본체 diff 측정 기준)
- `scripts/check-arch-cfg-gate.sh` - HAL-06 cfg(target_arch) src/arch/ 외부 0 수렴 게이트 (주석 라인 필터)
- `scripts/check-ct-branches.sh` - SC #8 CT 함수 je/jne/jz/jnz 0 objdump 게이트
- `scripts/check-secure-zero.sh` - HAL-05 nm memset U-entry 0 + secure_zero 심볼 존재 게이트
- `scripts/check-body-untouched.sh` - HAL-04 본체 무변경 2-tier diff-stat 게이트
- `tests/compile-fail/mmu-typestate.rs` - HAL-07 compile-fail 문서 파일
- `src/arch/mmu_typestate_probe.rs` - HAL-07 음성 probe (Mmu<Uninitialized> 에서 activate 오호출 -> E0599)
- `src/arch/mod.rs` - 6 HAL trait 정의 + impl Entropy for QuorumEntropy + probe mod 선언
- `src/arch/common/mod.rs` - secure_zero rep stosb + #[used] 앵커
- `Cargo.toml` - mmu-typestate-probe feature 추가
- `Makefile` - check-* 5 leg + ci-phase9 합성 타깃 + .PHONY 갱신

## Decisions Made
- CT 게이트 대상 심볼을 실존 심볼로 정정 (아래 Deviations 1 참조)
- secure_zero 심볼 보존 방식으로 #[used] fn-pointer 앵커 채택 (아래 Deviations 2 참조)
- HAL trait 은 전부 수신자 없는 associated fn — dyn 구조적 차단 + QuorumEntropy::collect 기존 associated fn 시그니처와 정합
- OQ5/OQ6 RESEARCH 권장안 채택 (arch/cpu.rs 무개명, 명시 목록 re-export 는 Wave 2+ 대상)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] CT 게이트 대상 심볼명이 실측 미실존**
- **Found during:** Task 1 (check-ct-branches.sh 작성)
- **Issue:** plan/ROADMAP SC #8 이 `capability::authenticate` 와 `hsm_attest::verify_signature` 를 CT 게이트 대상으로 명명하나, release 바이너리 nm 실측 결과 두 심볼 모두 미존재. 실제 capability CT 인증은 `hsm_registry::authenticate` (branch=0), CT 프리미티브는 `constant_time::CtLess` (branch=0) 이며, 실존 `hsm_attest::verify_attest` 는 D-12 설계상 입력 독립 분기 41건을 합법 보유하여 분기 0 게이트에 부적합.
- **Fix:** fragment 쌍을 `hsm_registry`+`authenticate`, `constant_time`+`CtLess` 로 지정하고 verify_attest 는 관측 전용(게이트 비대상) 보고로 분리. 심볼 미발견 시 blocker FAIL 로 표면화 (본체 수정 우회 금지).
- **Files modified:** scripts/check-ct-branches.sh
- **Verification:** bash scripts/check-ct-branches.sh exit 0, 두 대상 심볼 branch=0 확인, verify_attest branch=41 관측 보고
- **Committed in:** `6dcc47d`

**2. [Rule 1 - Bug] secure_zero 심볼이 --gc-sections 로 회수됨**
- **Found during:** Task 3 (nm 게이트 실측)
- **Issue:** plan 은 `#[unsafe(no_mangle)]` 단독으로 uncalled secure_zero 심볼이 release 바이너리에 보존된다고 가정했으나, 이 링커 설정(--gc-sections, linker.ld KEEP 는 multiboot2header/boot32 한정)에서 호출자 없는 no_mangle 함수는 GC 루트가 아니므로 회수됨. nm 게이트 (b) 항목 지속 FAIL.
- **Fix:** arch/common/mod.rs 내부에 `#[used] static SECURE_ZERO_ANCHOR: unsafe fn(*mut u8, usize) = secure_zero;` fn-pointer 앵커 추가. 본체 boot path 호출자 추가가 아닌 링커 보존 앵커로 본체 변경 0 원칙 유지.
- **Files modified:** src/arch/common/mod.rs
- **Verification:** nm 결과 `T secure_zero` 실측, objdump 로 rep stosb 본문 확인, memset U-entry 0, check-secure-zero.sh PASS
- **Committed in:** `6c0d8dd`

---

**Total deviations:** 2 auto-fixed (2x Rule 1)
**Impact on plan:** 두 정정 모두 검증 게이트의 정확성 확보에 필수. 심볼 정정은 실측 우선 원칙이고 앵커는 HAL-05 nm 게이트 실효성 요건. scope creep 없음, 본체 무변경 0 유지.

## Issues Encountered
- host test 최초 실행 시 `.cargo/config.toml` 이 기본 타깃을 x86_64-unknown-none 으로 고정하여 std/test 부재로 실패. Makefile entropy-host-test 레그와 동일하게 `--target $(rustc host triple)` 명시로 해결. 17 pass + 1 ignored (DudeCT 타이밍 test #[ignore]) = 18 host test, 회귀 0.

## User Setup Required
None - 외부 서비스 구성 불필요. 신규 의존성 0 (cargo add 0건).

## Known Stubs
interface-first 설계상 의도된 미소비 표면 (Wave 0/1 범위, plan 명시 허용):
- **6 HAL trait**: 구현체 impl 은 Wave 4 (09-04 이후) 에서 추가 예정. `#[allow(dead_code)]` 부착, Phase 10 aarch64 가 동일 표면 구현하도록 강제하는 컴파일 타임 계약. plan `<decisions>` 및 must_haves 에 명시.
- **secure_zero 호출자 0**: plan "호출자 추가 금지 — 본체 변경 0 원칙" 준수. #[used] 앵커로 심볼만 보존. 실사용 배선은 후속 phase 판단.
- **secure_zero aarch64 분기**: str xzr 골격만 존재, Phase 10 ARM-11 실검증 (본 phase 컴파일 대상 x86_64 아님).
- **src/arch/mmu_typestate_probe.rs**: feature `mmu-typestate-probe` 게이트, production 빌드 미포함. E0599 컴파일 거부가 정상 동작.

이 스텁들은 plan 의 목표(계약 정의 + 게이트 baseline)를 저해하지 않음 — 소비자 구현이 아니라 계약·인프라 확립이 본 plan 의 산출 정의.

## Threat Flags
없음 — 신규 network endpoint / auth path / 파일 접근 / schema 변경 0. secure_zero 는 plan threat_model T-09-03 (mitigate) 에 이미 등재된 정보 노출 완화 표면.

## Next Phase Readiness
- Wave 2+ (09-02 이후) 파일 이동의 회귀 기준점 확립 완료 — 매 sub-step 후 4종 게이트 재실행 가능
- arch-cfg-gate 54건은 9-C 종료 시 0 수렴 대상 (현재 예상 FAIL 상태, per-file 분포 실측 기록됨)
- ci-phase9 qemu-smoke leg 은 macOS 차단 시 Linux+KVM lane 이연 (Phase 8 선례)

## Self-Check: PASSED

- 생성 파일 10종 전부 FOUND (게이트 스크립트 4 + base-commit + probe 2 + mod.rs 2 + SUMMARY)
- 커밋 4종 전부 FOUND (6dcc47d Task1 / 0e93120 Task2 / 6c0d8dd Task3 / 6954011 SUMMARY)
- 워킹트리 clean

---
*Phase: 09-architecture-hal-extraction*
*Completed: 2026-07-20*
