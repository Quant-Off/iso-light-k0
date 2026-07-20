---
phase: 09-architecture-hal-extraction
plan: 02
subsystem: infra
tags: [hal, no_std, git-mv, lossless-move, re-export, smap, ct-gate, objdump, rust]

# Dependency graph
requires:
  - phase: 09-architecture-hal-extraction
    plan: 01
    provides: 6 HAL trait 계약 + arch/x86_64 as active 별칭 골격 + CI 게이트 4종 baseline (check-ct-branches / check-body-untouched) + scripts/phase9-base-commit
provides:
  - src/arch/x86_64/{cpu,gdt,tss,vga,boot_stub}.rs 5 ISA 파일 lossless 이동본 (HAL-04 전반부)
  - crate::cpu / crate::boot / crate::tss / crate::vga / crate::boot_stub 경로 명시 목록 re-export 보존 (OQ6)
  - gdt as boot 개명 별칭으로 KERNEL_CS/USER_CS/USER_DS/SYSCALL_CS_BASE/SYSRET_CS_BASE 참조 존속
  - 9-A 첫 bisectable 게이트 봉인 (이동 커밋 0ce5f50 + 배선 커밋 57878ec 분리)
affects: [09-03, 09-04, 09-05, 09-06, phase-10-arm-port]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "git mv 순수 이동 커밋 + 배선 커밋 2단 분리 -> rename detection 0/0 diff 보존 + bisectable (HAL-09)"
    - "명시 목록 re-export (glob 회피, OQ6) -> Pitfall 4 섀도잉 회피 + pub 표면 무변화"
    - "boot -> gdt 개명은 crate-root pub use ... as boot 별칭으로 기존 crate::boot 경로 존속"
    - "arch 내부는 re-export 우회 금지 직접 경로 사용 (Anti-Pattern 5)"

key-files:
  created:
    - src/arch/x86_64/cpu.rs
    - src/arch/x86_64/gdt.rs
    - src/arch/x86_64/tss.rs
    - src/arch/x86_64/vga.rs
    - src/arch/x86_64/boot_stub.rs
  modified:
    - src/arch/x86_64/mod.rs
    - src/main.rs
    - src/arch/cpu.rs

key-decisions:
  - "이동 커밋(0ce5f50)은 본문 바이트 무변경 순수 rename 만 담고 배선(57878ec)을 분리해 rename detection 오염 회피 (Pitfall 6)"
  - "boot.rs -> gdt.rs 개명은 crate::boot 을 gdt as boot 별칭으로 보존 (본체 idt/process/syscall use 문 무변경)"
  - "arch/cpu.rs L37/L41 crate::cpu::cpuid -> crate::arch::x86_64::cpu::cpuid 직접 경로 정리 (plan 언급 crate::cpu::features 는 이 파일 미존재 실측 -> cpuid 2건만 정정)"
  - "arch/x86_64/entropy/hw.rs 의 crate::cpu::features() 는 files_modified 범위 밖 + re-export 로 해소되어 본문 무변경 (out of scope)"

patterns-established:
  - "ISA 의존 파일 이동은 순수 git mv 커밋 선행 후 crate-root 명시 re-export 배선 커밋 후행"
  - "이동 후 SMAP 창 실존은 objdump stac/clac 잔존 카운트로 실측 증명"

requirements-completed: [HAL-02, HAL-04, HAL-09]

# Metrics
duration: 8min
completed: 2026-07-20
---

# Phase 9 Plan 02: 9-A ISA 의존 5 파일 lossless 이동 Summary

**최고 위험 경로인 crate::cpu::stac/clac 30 call site 를 담은 5개 ISA 파일을 src/arch/x86_64/ 로 본문 바이트 무변경 이동하고 명시 목록 re-export 로 본체 경로를 보존해 9-A 첫 bisectable 게이트를 GREEN 으로 봉인했다.**

## Performance

- **Duration:** 8분
- **Started:** 2026-07-20T04:28:14Z
- **Completed:** 2026-07-20T04:36:32Z
- **Tasks:** 2 완료
- **Files modified:** 8 (5 renamed + 3 modified)

## Accomplishments
- src/{cpu,boot,tss,vga,boot_stub}.rs 5 파일을 src/arch/x86_64/{cpu,gdt,tss,vga,boot_stub}.rs 로 lossless 이동, base..HEAD rename detection 5건 전부 0 insertions/0 deletions 실측 (HAL-04 전반부)
- crate-root 명시 목록 re-export (boot_stub/cpu/tss/vga) + gdt as boot 개명 별칭으로 본체 30 stac/clac call site + idt/process/syscall 의 crate::boot 참조 전부 본문 무변경 컴파일 (HAL-02)
- 이동 커밋(0ce5f50) 과 배선 커밋(57878ec) 분리로 git bisectable 유지 (HAL-09), 9-A 종료 회귀 게이트 전부 GREEN 봉인

## Task Commits

각 task 원자적 커밋:

1. **Task 1 커밋 1: 9-A ISA 의존 5 파일 순수 이동** - `0ce5f50`
2. **Task 1 커밋 2: re-export 배선 + arch 내부 직접 경로 정리** - `57878ec`
3. **Task 2: 9-A 종료 회귀 게이트 (검증 전용, 파일 변경 0)** - 커밋 없음

## Files Created/Modified
- `src/arch/x86_64/cpu.rs` - 구 src/cpu.rs lossless 이동본 (stac/clac/cpuid/features/SIMD/보안비트/rdmsr/wrmsr)
- `src/arch/x86_64/gdt.rs` - 구 src/boot.rs lossless 이동본 (GDT/TSS 디스크립터 + init_gdt + KERNEL_CS/USER_CS/USER_DS/SYSCALL_CS_BASE/SYSRET_CS_BASE)
- `src/arch/x86_64/tss.rs` - 구 src/tss.rs lossless 이동본 (crate::stack 참조는 무변경 존속)
- `src/arch/x86_64/vga.rs` - 구 src/vga.rs lossless 이동본
- `src/arch/x86_64/boot_stub.rs` - 구 src/boot_stub.rs lossless 이동본 (multiboot2 헤더 + boot32 global_asm 스텁)
- `src/arch/x86_64/mod.rs` - boot_stub/cpu/gdt/tss/vga 5 모듈 선언 추가 (기존 entropy 포함 pub mod 6)
- `src/main.rs` - 5 모듈 선언 삭제 후 명시 목록 re-export + gdt as boot 별칭 (tier2 diff 8줄)
- `src/arch/cpu.rs` - crate::cpu::cpuid -> crate::arch::x86_64::cpu::cpuid 직접 경로 2건 (Anti-Pattern 5)

## 9-A 종료 회귀 게이트 실측

| 게이트 | 결과 | 실측값 |
|--------|------|--------|
| cargo build --target x86_64-unknown-none | PASS | dev + release 양 프로필 GREEN |
| objdump stac 잔존 (SMAP 창) | PASS | stac=16 (>= 1) |
| objdump clac 잔존 (SMAP 창) | PASS | clac=16 (>= 1) |
| check-ct-branches.sh | PASS (exit 0) | hsm_registry::authenticate branch=0 · constant_time::CtLess branch=0 · verify_attest branch=41 관측 전용 |
| check-body-untouched.sh | PASS (exit 0) | tier1=0/50 (본체 본문 diff 0) · tier2=8/150 (main.rs 모듈 선언 정리분) |
| host ci leg 5종 (alloc-zero/alloc-bus/no-dev-sk/no-network/machete) | PASS (exit 0) | cargo-machete unused dep 0 |
| host test (cargo test --no-default-features) | PASS | 17 pass + 1 ignored = 18 (Plan 01 baseline 정합, 회귀 0) |
| make qemu-smoke | 부팅 진입 PASS / 하류 마커 MISS | 아래 이연 참조 |

## Decisions Made
- 이동 커밋과 배선 커밋 분리 (Pitfall 6 rename detection 오염 회피) — 이동 단독 커밋은 빌드 불가지만 sub-step 게이트는 9-A 종료 시점만 요구 (HAL-09 문언)
- boot -> gdt 개명은 crate::boot 별칭 보존으로 본체(idt/process/syscall) use 문 무변경
- plan 언급 crate::cpu::features 정정 대상은 arch/cpu.rs 에 미존재 실측 -> cpuid 2건만 직접 경로화 (아래 Deviations 1 참조)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] plan 지정 arch/cpu.rs 의 crate::cpu::features 참조가 실측 미존재**
- **Found during:** Task 1 커밋 2 (arch/cpu.rs 직접 경로 정리)
- **Issue:** plan action 은 arch/cpu.rs L37/L41 의 `crate::cpu::cpuid` 와 `crate::cpu::features` 를 직접 경로화하라 지시하나, 실측 결과 arch/cpu.rs 에는 `crate::cpu::cpuid` 2건(L37/L41)만 존재하고 `crate::cpu::features` 는 부재. `crate::cpu::features()` 는 범위 밖 파일 arch/x86_64/entropy/hw.rs:77 에 존재하며 이는 plan frontmatter files_modified 목록에 없음.
- **Fix:** arch/cpu.rs 는 cpuid 2건만 `crate::arch::x86_64::cpu::cpuid` 로 정정. hw.rs 의 features() 는 out of scope 로 무변경 유지 (re-export 경유 crate::cpu::features 로 정상 해소, 빌드 GREEN 확인). acceptance criterion `grep -rn "crate::cpu::" src/arch/cpu.rs == 0` 충족.
- **Files modified:** src/arch/cpu.rs
- **Verification:** grep -c "crate::cpu::" src/arch/cpu.rs == 0, cargo build GREEN
- **Committed in:** `57878ec`

---

**Total deviations:** 1 auto-fixed (1x Rule 1)
**Impact on plan:** plan 텍스트의 심볼 위치 가정을 실측으로 정정한 scope 축소 (features 는 범위 밖 파일 소속). 본체 무변경 0 유지, scope creep 없음. acceptance criterion 및 body-untouched tier1=0 그대로 충족.

## Issues Encountered
- qemu-smoke 하류 마커 MISS: macOS Apple Silicon 은 KVM 부재로 TCG (ENTROPY_MODE=tcg-entropy, -cpu qemu64,+rdrand,+rdseed) 모드로 폴백. `[부팅 진입]` 은 PASS 이나 post-TLS stall (qemu-test.sh L59 문서화된 RIP=0x40B866ECEB4E TCG SSE/AVX 스톨) 로 메인 루프 진입 이후 전 마커 MISS. 이는 Phase 8 에서 확립된 macOS TCG 환경 제약이며 본 파일 이동이 유발한 회귀가 아님 — 오히려 `[부팅 진입] PASS` 가 multiboot2 헤더 + boot32 스텁 + GDT 로더 이동본이 부팅 경로에서 무결하게 동작함을 증명함. Phase 8 선례대로 QEMU 마커 검증은 Linux+KVM lane 으로 이연.

## User Setup Required
None - 외부 서비스 구성 불필요. 신규 의존성 0 (cargo add 0건).

## Known Stubs
없음 — 본 plan 은 파일 이동 + 배선만 수행, 신규 미소비 표면 도입 0. Plan 01 이 도입한 6 HAL trait interface-first 스텁은 본 plan 범위 밖이며 Wave 4 (09-04 이후) 구현 대상 유지.

## Threat Flags
없음 — 신규 network endpoint / auth path / 파일 접근 / schema 변경 0. threat_model T-09-01/02/04 (mitigate) 전부 게이트 GREEN 으로 완화 확인 (SMAP 창 stac/clac 잔존 · CT 분기 0 · 명시 목록 re-export 로 pub 표면 무변화).

## Next Phase Readiness
- 9-A 봉인 완료 — 최고 위험 경로 (SMAP 창 30 site) 이동·검증 선행 소진. 09-03 (9-B) 는 idt/serial/interrupt 등 후속 ISA 파일 이동에 동일 2-커밋 패턴 적용
- crate::boot / crate::tss 등 별칭은 9-B 이동 전 원위치 참조를 보존 (본체 use 문 무변경 유지)
- QEMU 2-leg (부팅 마커 실검증) 은 Linux+KVM lane 이연 지속 — 본 plan 도 host 게이트 + objdump SMAP 실측 + 부팅 진입 PASS 로 이동 무결성 확보
- STATE.md / ROADMAP.md 는 orchestrator 가 wave 종료 후 중앙 갱신 (worktree 모드 규약)

## Self-Check: PASSED

- 생성 파일 6종 전부 FOUND (arch/x86_64 5 이동본 + 09-02-SUMMARY)
- 이동 대상 구 경로 5종 전부 삭제 확인 (src/{cpu,boot,tss,vga,boot_stub}.rs)
- 커밋 3종 전부 FOUND (0ce5f50 이동 / 57878ec 배선 / e353dbb SUMMARY)
- 워킹트리 clean (선존 .DS_Store 무관 항목만 untracked)

---
*Phase: 09-architecture-hal-extraction*
*Completed: 2026-07-20*
