---
phase: 09-architecture-hal-extraction
plan: 03
subsystem: infra
tags: [hal, no_std, git-mv, lossless-move, re-export, syscall, mmu, ct-gate, arch-cfg-gate, rust]

# Dependency graph
requires:
  - phase: 09-architecture-hal-extraction
    plan: 02
    provides: src/arch/x86_64/{cpu,gdt,tss,vga,boot_stub}.rs 5 ISA 이동본 + crate-root 명시 목록 re-export + gdt as boot 별칭 + 9-A bisectable 게이트 봉인
provides:
  - src/arch/x86_64/{mmu,idt,syscall,memory_map}.rs 4 ISA 파일 lossless 이동본 (HAL-04 후반부, 9/9 완결)
  - crate::mmu / crate::idt / crate::syscall / crate::memory_map 경로 명시 목록 re-export 보존 (OQ6)
  - crate-root 잔존 ISA 파일 0 실측 (9개 ISA 의존 파일 전량 src/arch/x86_64/ 로 수렴)
  - 9-B 두 번째 bisectable 게이트 봉인 (이동 커밋 b32352f + 배선 커밋 9e29624 분리)
  - check-arch-cfg-gate 37 -> 28 감소 실측 (9-C main.rs cfg 제거 전제 성립)
affects: [09-04, 09-05, 09-06, phase-10-arm-port]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "git mv 순수 이동 커밋 + 배선 커밋 2단 분리 -> rename detection 100% 4/4 + bisectable (HAL-09)"
    - "명시 목록 re-export 확장 (glob 회피, OQ6) -> pub 표면 무변화 + Pitfall 4 섀도잉 회피"
    - "syscall.rs 는 ABI-중립 표면 (SyscallNum/SyscallError/SyscallContext/is_user_address) 혼재 상태 그대로 전체 이동 (OQ1 분할은 Phase 10 이월)"
    - "memory_map.rs 도 parse_multiboot2 혼재 상태 그대로 전체 이동 (OQ3 2단계 분할은 9-C 이월)"

key-files:
  created:
    - src/arch/x86_64/mmu.rs
    - src/arch/x86_64/idt.rs
    - src/arch/x86_64/syscall.rs
    - src/arch/x86_64/memory_map.rs
  modified:
    - src/arch/x86_64/mod.rs
    - src/main.rs

key-decisions:
  - "이동 커밋(b32352f)은 본문 바이트 무변경 순수 rename 4/4 만 담고 배선(9e29624)을 분리해 rename detection 오염 회피 (Pitfall 6)"
  - "syscall.rs 는 OQ1 채택대로 전체 lossless 이동, SyscallContext rdi/rsi/rdx 필드 개명 시도 0 (Pitfall 8 본체 diff 예산 방어)"
  - "이동 파일 4개 본문 불가침 유지 -> memory_map.rs 의 crate::mmu::SIZE_2MIB 는 re-export 로 해소되어 본문 무변경 (Anti-Pattern 5 직접 경로화는 body-untouched tier1=0 우선으로 미적용)"
  - "main.rs 의 #[cfg(target_arch=x86_64)] pub mod syscall 가드 삭제로 arch-cfg-gate 실측 28 (plan 추정 29 대비 -1, 삭제가 plan action 자체 지시분)"

patterns-established:
  - "9개 ISA 의존 파일 전량 이동 완결 -> crate-root ISA 파일 0, arch-cfg-gate 카운트가 파일 이동분(8) + syscall cfg 가드(1) = 9 site 자연 감소"
  - "syscall dispatcher 이동 회귀는 in-repo check-ct-branches (kernel 바이너리) + body-untouched tier1=0 으로 검증, cross-repo dudect 레그는 보조"

requirements-completed: [HAL-04, HAL-09]

# Metrics
duration: 9min
completed: 2026-07-20
---

# Phase 9 Plan 03: 9-B 잔여 4 ISA 파일 lossless 이동 (9/9 완결) Summary

**syscall dispatcher · mmu typestate · idt 핸들러 · memory_map 를 담은 잔여 4개 ISA 의존 파일을 src/arch/x86_64/ 로 본문 바이트 무변경 이동해 HAL-04 의 9개 파일 이동을 완결하고, crate-root ISA 파일 0 · arch-cfg-gate 37->28 감소를 실측하며 9-B 두 번째 bisectable 게이트를 GREEN 으로 봉인했다.**

## Performance

- **Duration:** 9분
- **Started:** 2026-07-20T04:44:09Z
- **Completed:** 2026-07-20T04:54:06Z
- **Tasks:** 2 완료 (Task 1 이동+배선, Task 2 검증 전용)
- **Files modified:** 6 (4 renamed + 2 modified)

## Accomplishments
- src/{mmu,idt,syscall,memory_map}.rs 4 파일을 src/arch/x86_64/ 로 lossless 이동, 이동 커밋 b32352f 은 4 files changed 0 insertions 0 deletions · base..HEAD rename detection 4건 전부 `src/{ => arch/x86_64}/*.rs | 0` 실측 (HAL-04 후반부, 9/9 완결)
- crate-root 명시 목록 re-export 를 {boot_stub, cpu, idt, memory_map, mmu, syscall, tss, vga} 로 확장해 hsm_registry/air_gap 의 crate::syscall::{SyscallContext, SyscallError, is_user_address} · elf 의 crate::mmu · allocator 의 crate::memory_map · memory_map 의 crate::mmu::SIZE_2MIB 참조를 전부 본문 무변경 컴파일 (HAL-02 존속)
- 이동 커밋(b32352f) 과 배선 커밋(9e29624) 분리로 git bisectable 유지 (HAL-09 두 번째 게이트), 9-B 종료 회귀 게이트 in-repo 전량 GREEN 봉인
- crate-root 잔존 ISA 파일 0 실측 (9개 ISA 의존 파일 전량 arch/x86_64 수렴) · check-arch-cfg-gate 37 -> 28 감소로 9-C main.rs cfg 제거 전제 성립

## Task Commits

각 task 원자적 커밋 (이동/배선 분리 bisectable):

1. **Task 1 커밋 1: 9-B ISA 의존 4 파일 순수 이동** - `b32352f`
2. **Task 1 커밋 2: 9-B re-export 배선 4 모듈** - `9e29624`
3. **Task 2: 9-B 종료 회귀 게이트 (검증 전용, 파일 변경 0)** - 커밋 없음

## Files Created/Modified
- `src/arch/x86_64/mmu.rs` - 구 src/mmu.rs lossless 이동본 (4-level 페이징 + Mmu typestate Uninitialized + AddressSpace, crate::allocator::alloc_frame 참조 무변경)
- `src/arch/x86_64/idt.rs` - 구 src/idt.rs lossless 이동본 (extern x86-interrupt 핸들러 + PIC/EOI, crate::boot/tss/vga 참조는 re-export 로 해소)
- `src/arch/x86_64/syscall.rs` - 구 src/syscall.rs lossless 이동본 (naked syscall_entry + dispatcher + ABI 타입 SyscallNum/SyscallError/SyscallContext/is_user_address, 본체 역호출 crate::hsm_registry::handle_*/crate::air_gap::* 무변경)
- `src/arch/x86_64/memory_map.rs` - 구 src/memory_map.rs lossless 이동본 (중립 타입 + parse_multiboot2 혼재 상태, OQ3 분할은 9-C)
- `src/arch/x86_64/mod.rs` - idt/memory_map/mmu/syscall 4 모듈 선언 추가 (pub mod 총 10종 = entropy + 9-A 5 + 9-B 4)
- `src/main.rs` - idt/memory_map/mmu 3 선언 + cfg 가드 동반 syscall 2줄 삭제 후 명시 목록 re-export 확장 (tier2 diff 13줄, gdt as boot 별칭 유지)

## 9-B 종료 회귀 게이트 실측

| 게이트 | 결과 | 실측값 |
|--------|------|--------|
| cargo build --target x86_64-unknown-none | PASS | dev + release(build-rel) 양 프로필 GREEN |
| make check-mmu-typestate | PASS (exit 0) | crate::mmu 경로 re-export 보존으로 activate 오호출 E0599 컴파일 거부 존속 |
| check-ct-branches.sh | PASS (exit 0) | authenticate branch=0 · CtLess branch=0 · verify_attest branch=41 관측 전용 (9-A 정합) |
| check-body-untouched.sh | PASS (exit 0) | tier1=0/50 (본체 본문 diff 0) · tier2=13/150 (main.rs 모듈 정리분) |
| check-arch-cfg-gate.sh | exit 1 (HAL-06 수렴 전 예상) | 28 sites (9-A 37 -> 9-B 28, -9 = 이동 파일 8 + syscall cfg 가드 1) · 감소 실측 충족 |
| check-alloc-zero | PASS | alloc 심볼 0 |
| check-alloc-bus | PASS | src/bus.rs alloc 의존 0 (BUS-01) |
| check-no-dev-sk | PASS | dev sk 파일 부재 (closed 프로필) |
| check-no-network | PASS | closed 프로필 Network 심볼 0 (GAP-03) |
| check-machete | PASS | cargo-machete unused dep 0 |
| host test (cargo test --no-default-features --target aarch64-apple-darwin) | PASS | 17 pass + 1 ignored = 18 (9-A baseline 정합, 회귀 0) |
| wire-attest-host-test (실 sibling 경로 실행) | PASS | 4 test 파일 x 3 = 12 pass (submit_dispatch/payload_layout/status_serialize/no_slot_mutation) |
| chan-dudect | BLOCKED 이연 | sibling elib-k0-nt worktree dudect 하네스 테스트 파일 비컴파일 (별도 repo, 아래 Deviations 1) |
| make qemu-smoke | 부팅 진입 (stage 2-3) / 하류 마커 MISS 이연 | TCG 모드 (ENTROPY_MODE=tcg-entropy, macOS KVM 부재) — Linux+KVM lane 이연 |

## Decisions Made
- 이동 커밋과 배선 커밋 분리 (Pitfall 6 rename detection 오염 회피) — 이동 단독 커밋 b32352f 는 4 files 0/0 diff 순수 rename, 배선 9e29624 후행
- syscall.rs OQ1 전체 이동 — SyscallContext 의 x86 레지스터 필드명(rdi/rsi/rdx) 개명 시도 0, ABI-중립 분할은 Phase 10 첫 plan 이월
- memory_map.rs OQ3 1단계 전체 이동 — parse_multiboot2 분할과 중립 타입 재배치는 9-C (Plan 05) 이월
- 이동 4파일 본문 불가침 우선 -> memory_map.rs 의 crate::mmu::SIZE_2MIB 는 Anti-Pattern 5 직접 경로화 대신 re-export 해소 채택 (body-untouched tier1=0 유지 목적)

## Deviations from Plan

### Auto-fixed / 실측 정정 Issues

**1. [Rule 3 - 환경 경로] chan-dudect / wire-attest-host-test Makefile 타깃이 stale 절대 경로 하드코딩**
- **Found during:** Task 2 (확장 레그 실행)
- **Issue:** 두 타깃 모두 `cd /Library/Quant/Repository/projects/elib-k0-nt` 를 하드코딩하나 본 머신 레이아웃에 미존재. 실제 sibling 은 Cargo.toml 의 `../elib-k0-nt` 가 가리키는 worktree 경로 (`/Library/Quant/code-projects/iso-light-k0/.claude/worktrees/elib-k0-nt`).
- **Fix:** Makefile 은 본문 불가침(범위 밖)으로 무변경 유지하고, 동등 명령을 실제 sibling 경로에 직접 실행. wire-attest-host-test 는 4 test 파일 12 pass 로 PASS 확인. chan-dudect 는 sibling 의 dudect 하네스 테스트 파일(chan_length_ct.rs/chan_nonce_overflow.rs)이 no_std prelude 결여(`Stats::default`/`sqrt`/`powi`/`Result`/`Vec` 미해소)로 비컴파일 — 이는 별도 repo(elib-k0-nt) worktree 체크아웃의 선존 상태이며 본 커널 내부 파일 이동과 무관 (phase 9 에서 elib 파일 touch 0 실측). SCOPE BOUNDARY 규칙상 out of scope.
- **CT 회귀 대체 검증:** syscall dispatcher 이동의 CT 회귀 가드는 in-repo check-ct-branches.sh (kernel 바이너리 je/jne/jz/jnz 0) GREEN + body-untouched tier1=0 (dispatcher 본문 바이트 무변경 rename 100%) 으로 충족. constant-time 라이브러리 자체는 빌드 GREEN (테스트 하네스만 비컴파일).
- **Files modified:** 없음 (Makefile 무변경, elib 파일 무변경)

---

**2. [실측 정정] check-arch-cfg-gate 카운트 plan 추정 29 대비 실측 28**
- **Found during:** Task 2 (arch-cfg-gate 실행)
- **Issue:** plan 은 약 29 기대(main.rs 26 + panic.rs 2 + ipc.rs 1)로 추정하나 실측 28 (main.rs 25 + panic.rs 2 + ipc.rs 1).
- **Fix:** plan action 자체가 지시한 `#[cfg(target_arch=x86_64)] pub mod syscall;` 2줄 삭제로 main.rs cfg site 가 26 -> 25 로 감소한 것이 원인. 삭제는 plan 지시분이므로 기능 이탈 아님. 9-A(37) 대비 28 로 감소한 사실은 acceptance criterion (9-A 시점보다 감소) 충족.
- **Files modified:** 없음 (측정값 기록만)

---

**Total deviations:** 2 (1x Rule 3 환경 경로 이연 · 1x 실측 정정)
**Impact on plan:** 본체·이동 파일 본문 무변경 0 유지, scope creep 없음. HAL-04 9개 파일 이동 완결 + body-untouched tier1=0 + in-repo 게이트 전량 GREEN 그대로 충족. cross-repo dudect 레그만 sibling 환경 사유로 이연.

## Issues Encountered
- **chan-dudect sibling 비컴파일:** elib-k0-nt worktree 의 dudect 통계 하네스(chan_*_ct 테스트 파일)가 `Stats::default`/`sqrt`/`powi` 등 std/libtest 심볼 미해소로 컴파일 실패. 최근 sibling 커밋(8fc8cb3 "constant-time 테스트 하네스 안정화 ... cargo config 타겟을 aarch64-apple-darwin 으로 정정") 이후 상태로 추정. 본 커널(iso-light-k0) 파일 이동과 완전 독립 — phase 9 base..HEAD 에서 elib 파일 변경 0 실측. constant-time 라이브러리 본체는 빌드 GREEN.
- **qemu-smoke 하류 마커 MISS:** macOS Apple Silicon 은 KVM 부재로 TCG (ENTROPY_MODE=tcg-entropy) 폴백. 부팅 진입(stage 2-3) 도달로 moved idt/mmu/syscall/memory_map/boot 경로가 부팅 시퀀스에서 무결 로드됨을 확인하나, post-TLS TCG 스톨(Phase 8/9-A 선례)로 하류 마커 평가 불가. Phase 8 선례대로 QEMU 마커 실검증은 Linux+KVM lane 이연.

## User Setup Required
None - 외부 서비스 구성 불필요. 신규 의존성 0 (cargo add 0건).

## Known Stubs
없음 — 본 plan 은 파일 이동 + 배선만 수행, 신규 미소비 표면 도입 0. Plan 01 이 도입한 6 HAL trait interface-first 스텁은 본 plan 범위 밖이며 Wave 4(09-04 이후) 구현 대상 유지.

## Threat Flags
없음 — 신규 network endpoint / auth path / 파일 접근 / schema 변경 0. threat_model T-09-01(is_user_address re-export 오배선)/T-09-02(LTO CT 재생성)/T-09-05(이동 본문 혼입) 전부 게이트 GREEN 으로 완화 확인 (명시 목록 re-export 라 silent 오배선 불가 = E0433 컴파일 실패 · check-ct-branches GREEN · rename 100% + body-untouched tier1=0).

## Next Phase Readiness
- 9-B 봉인 완료 — HAL-04 9개 ISA 의존 파일 이동 100% 완결, crate-root 잔존 ISA 파일 0 실측. 09-04 이후 Wave 4 는 HAL trait 구현 채우기로 진행
- crate::syscall / crate::mmu / crate::memory_map / crate::idt 별칭 re-export 는 9-C main.rs cfg 제거 전까지 본체 use 문 무변경 보존
- check-arch-cfg-gate 28 (37 -> 28 감소) 로 9-C 의 main.rs cfg 제거 전제 성립 — 남은 28 site 중 main.rs 25 가 9-C 주요 수렴 대상
- QEMU 2-leg (부팅 마커 실검증) 및 chan-dudect(sibling 하네스 복구 후) 는 Linux+KVM lane 이연 지속 — 본 plan 도 in-repo 게이트(build/ct-branches/body-untouched/arch-cfg-gate) + host 18 test + wire 12 test + 부팅 진입 PASS 로 이동 무결성 확보
- STATE.md / ROADMAP.md 는 orchestrator 가 wave 종료 후 중앙 갱신 (worktree 모드 규약, 본 executor 미변경)

## Self-Check: PASSED

- 생성 파일 5종 전부 FOUND (arch/x86_64 4 이동본 + 09-03-SUMMARY)
- 이동 대상 구 경로 4종 전부 삭제 확인 (src/{mmu,idt,syscall,memory_map}.rs ABSENT)
- 커밋 3종 전부 FOUND (b32352f 이동 / 9e29624 배선 / e4a9150 SUMMARY)
- 워킹트리 clean (선존 .DS_Store 무관 항목만 untracked)

---
*Phase: 09-architecture-hal-extraction*
*Completed: 2026-07-20*
