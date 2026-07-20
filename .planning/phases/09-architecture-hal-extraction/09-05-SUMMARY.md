---
phase: 09-architecture-hal-extraction
plan: 05
subsystem: infra
tags: [hal, no_std, bootinfo, firmware-neutral, adapter, arch-cfg-gate, memory-map-split, static-bss, rust]

# Dependency graph
requires:
  - phase: 09-architecture-hal-extraction
    plan: 04
    provides: 본체 외과수술 3건 완료 + 6 HAL trait x86_64 구현체 + src/arch/ 외부 cfg 위반이 main.rs 25 만 잔존
  - phase: 09-architecture-hal-extraction
    plan: 03
    provides: memory_map.rs 1차 이동 (arch/x86_64/memory_map.rs, parse_multiboot2 혼재 상태 — 2차 분할 출발점)
  - phase: 09-architecture-hal-extraction
    plan: 02
    provides: gdt as boot 별칭 배선 (재정의 대상) + crate-root 명시 목록 re-export
provides:
  - src/boot/ 4-파일 표면 (mod.rs BootInfo + memory_map.rs 중립 타입 + multiboot2.rs 실동작 어댑터 + uefi.rs 시그니처 stub)
  - 펌웨어-중립 BootInfo struct (6 필드 + command_line_len, const fn empty + static BSS, 동적 할당 0, HAL-08)
  - _boot_adapter_mb2 no_mangle 어댑터 + _kernel_start(&'static BootInfo) 합류점 (boot_stub .Lkernel_entry 경유)
  - check-arch-cfg-gate 최초 GREEN (exit 0) — src/arch/ 외부 cfg(target_arch) 0 (HAL-06 수렴)
  - memory_map 2차 분할 이동 완결 (OQ3 2단계) + boot 네임스페이스 gdt-별칭 -> 디렉토리 모듈 재정의
affects: [09-06, phase-10-arm-port, phase-11-live]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "펌웨어-중립 BootInfo = 고정 크기 배열만 소비 (MemoryMap + [u8;128] command_line) const fn empty static BSS -> 동적 할당 0 (HAL-08)"
    - "어댑터 진입점 = boot_stub .quad 간접 점프 대상 (_boot_adapter_mb2) 가 RDI 규약으로 파싱 후 static BOOT_INFO 채워 _kernel_start(&BootInfo) 로 tail-합류"
    - "memory_map 2차 분할 = 중립 타입(memory_map.rs) / mb2 파서(multiboot2.rs) 경계로 BootInfo 가 arch 경로 미참조 -> 펌웨어-중립성 실질화 (OQ3)"
    - "boot 네임스페이스 재정의 = gdt as boot 별칭 소거(idt/syscall/main 참조 직접경로화)와 pub mod boot 선언을 동일 커밋에서 수행 (E0255 회피)"
    - "cfg(target_arch) 소거 = x86_64 가드 라인만 제거 본문 유지 aarch64 wfi 분기는 블록째 삭제 (all(target_arch,debug_assertions) 변형은 게이트 대상 아니므로 존치)"

key-files:
  created:
    - src/boot/mod.rs
    - src/boot/memory_map.rs
    - src/boot/multiboot2.rs
    - src/boot/uefi.rs
  modified:
    - src/main.rs
    - src/arch/x86_64/mod.rs
    - src/arch/x86_64/idt.rs
    - src/arch/x86_64/syscall.rs
    - src/arch/x86_64/boot_stub.rs
  deleted:
    - src/arch/x86_64/memory_map.rs

key-decisions:
  - "OQ2 이행 uefi.rs 는 parse_uefi 시그니처-only stub (본문 unimplemented!) — 실동작 어댑터는 multiboot2 1개 + arch boot_stub 경유, Phase 11 LIVE-01 이 본문 채움"
  - "OQ3 2단계 이행 arch/x86_64/memory_map.rs 를 src/boot/memory_map.rs(중립 타입) + src/boot/multiboot2.rs(parse_multiboot2 + parse_kaslr_offset) 로 분할 후 원본 삭제"
  - "kaslr_offset 미배선 (decision 이행) 어댑터가 parse_kaslr_offset 를 호출하지 않고 kaslr_offset=0 유지 -> _kernel_start 가 None 주입 (GRUB KASR 태그 부재로 기존에도 None, 런타임 동등). 실사용 배선 Phase 11 LIVE-09"
  - "mb2 info 예약 블록 (c) 제거 mb2_addr 이 펌웨어-중립 _kernel_start 에서 소거 — 어댑터가 핸드오프 전량을 BOOT_INFO(.bss, (b)로 보호)로 복사 후 진입하므로 원본 mb2 영역은 죽은 상태, 별도 예약 불필요 (부팅 마커 무회귀)"
  - "커밋 메시지는 프로젝트/전역 CLAUDE.md 규칙 이행 — 한국어 plain-text, prefix/콜론/em-dash/middot/period 금지 (executor 기본 conventional 포맷 미사용)"

patterns-established:
  - "펌웨어-중립 합류점 = _kernel_start(&BootInfo) 는 Phase 10 aarch64 boot stub 과 Phase 11 limine/uefi 가 동일 struct 로 합류하는 유일 진입 표면"
  - "분할 이동 = 중립 타입과 펌웨어 파서를 별 파일로 가르면 BootInfo 가 arch 를 참조하지 않아 펌웨어-중립성이 컴파일 그래프로 강제됨"

requirements-completed: [HAL-06, HAL-08, HAL-09]

# Metrics
duration: 14min
completed: 2026-07-20
---

# Phase 9 Plan 05: 9-C 후반부 BootInfo 합류 + memory_map 2차 분할 + cfg 전량 제거 (HAL-06 수렴) Summary

**펌웨어-중립 BootInfo struct + src/boot/ 4-어댑터 표면 (multiboot2 실동작 / uefi 시그니처 stub / boot_stub 경유) 을 세우고 _boot_adapter_mb2 -> _kernel_start(&BootInfo) 합류점을 잠갔으며, memory_map.rs 를 중립 타입/mb2 파서로 2차 분할 이동하고 main.rs 잔여 cfg(target_arch) 19+aarch64 1 을 전량 제거해 check-arch-cfg-gate 를 최초 exit 0 (GREEN) 으로 수렴시켰다 (HAL-06).**

## Performance

- **Duration:** 14분
- **Started:** 2026-07-20T05:24:58Z
- **Completed:** 2026-07-20T05:38:42Z
- **Tasks:** 3 완료 (Task 1 분할+배선 2커밋, Task 2 합류 1커밋, Task 3 검증 전용)
- **Files:** 4 created + 5 modified + 1 deleted

## Accomplishments
- 펌웨어-중립 boot 계층 신설 — src/boot/mod.rs 에 `BootInfo { memory_map, kaslr_offset, command_line[128] + command_line_len, rsdp_ptr, dtb_ptr, framebuffer }` + `const fn empty()` 정의, 고정 크기 배열만 사용해 static BSS 배치 · 동적 할당 0 (grep Vec/Box/alloc 0줄, HAL-08)
- memory_map 2차 분할 이동 (OQ3 2단계) — arch/x86_64/memory_map.rs 를 src/boot/memory_map.rs(MemoryMap/MemoryRegion/MemoryKind/ParseError 중립 타입) + src/boot/multiboot2.rs(parse_multiboot2 + parse_kaslr_offset + Mb2* 원시 구조체) 로 본문 그대로 분할 후 원본 삭제, multiboot2 는 타입을 `super::memory_map` 경로로 소비
- boot 네임스페이스 재정의 (E0255 회피) — `pub use ... gdt as boot` 별칭 소거 + idt.rs/syscall.rs 의 crate::boot 참조를 `crate::arch::x86_64::gdt` 직접 경로화 + main.rs init_gdt 를 gdt 경로로 전환한 뒤 `pub mod boot` 를 신규 디렉토리 모듈로 재정의 (동일 커밋)
- BootInfo 합류점 성립 (HAL-08) — multiboot2.rs 에 `#[unsafe(no_mangle)] _boot_adapter_mb2(mb2_addr)` 어댑터 추가 (static BOOT_INFO 를 parse_multiboot2 결과로 채우고 fail-safe unwrap_or_else(empty) lossless 이식, 신규 파싱 0), boot_stub .Lkernel_entry `.quad` 를 `_kernel_start` -> `_boot_adapter_mb2` 로 변경 (RDI 규약 유지), _kernel_start 를 `&'static BootInfo` 시그니처로 전환하고 boot_info.memory_map 소비
- HAL-06 최초 수렴 — main.rs 의 bare `#[cfg(target_arch="x86_64")]` 19건 전량 제거 (본문 유지) + kernel_main_loop 의 aarch64 wfi 분기 블록째 삭제, `check-arch-cfg-gate.sh` 가 처음으로 exit 0 (PASS, src/arch/ 외부 cfg 0줄)

## Task Commits

각 task 원자적 커밋:

1. **Task 1 커밋 1: memory_map 2차 분할 이동 boot 계층 신설** - `7c8400d`
2. **Task 1 커밋 2: boot 네임스페이스 재정의 BootInfo 골격 배선** - `e1b347b`
3. **Task 2: BootInfo 합류 _kernel_start 전환 및 main cfg 전량 제거** - `f9f16e9`
4. **Task 3: 9-C 종료 회귀 게이트 (검증 전용, 파일 변경 0)** - 커밋 없음

## Files Created/Modified
- `src/boot/mod.rs` - 신설. BootInfo 6 필드 + command_line_len (미배선 5필드 #[allow(dead_code)]) + const fn empty + pub mod memory_map/multiboot2/uefi. 한국어 module Docstring (# Features)
- `src/boot/memory_map.rs` - 신설 (분할 이동본). 중립 타입 MemoryMap/MemoryRegion/MemoryKind/ParseError + MAX_REGIONS/DEFAULT_REGION. 파서 미포함 (펌웨어-중립)
- `src/boot/multiboot2.rs` - 신설 (분할 이동본 + 어댑터). Mb2* 원시 구조체 + parse_multiboot2 + parse_kaslr_offset(#[allow(dead_code)] Phase 11) + static BOOT_INFO + _boot_adapter_mb2 진입점
- `src/boot/uefi.rs` - 신설. parse_uefi 시그니처-only stub (unimplemented!, OQ2 Phase 11 LIVE-01 채움)
- `src/main.rs` - _kernel_start(&'static BootInfo) 전환 + boot_info.memory_map 소비 + gdt as boot 별칭 소거 + re-export 갱신(gdt 추가/memory_map 별칭) + pub mod boot + cfg(target_arch) 19+aarch64 제거 + mb2 예약 블록 제거
- `src/arch/x86_64/mod.rs` - pub mod memory_map 선언 제거
- `src/arch/x86_64/idt.rs` - crate::boot::KERNEL_CS -> crate::arch::x86_64::gdt::KERNEL_CS
- `src/arch/x86_64/syscall.rs` - crate::boot::{SYSCALL_CS_BASE,SYSRET_CS_BASE} -> crate::arch::x86_64::gdt::{...}
- `src/arch/x86_64/boot_stub.rs` - .Lkernel_entry .quad _kernel_start -> _boot_adapter_mb2 + 관련 주석 갱신 (.boot32/_start/linker.ld 심볼 계약 무변경)

## 9-C 종료 회귀 게이트 실측 (Task 3)

| 게이트 | 결과 | 실측값 |
|--------|------|--------|
| make build-rel (release) | PASS | dev + release 양 프로필 GREEN (unused/error 경고 0, 선존 dev trust-root 경고만) |
| nm _boot_adapter_mb2 / _kernel_start (release ELF) | PASS | `_boot_adapter_mb2` T @ ffffffff8014df43 · `_kernel_start` T @ ffffffff8014e0fd — 링크 수준 합류 실측 (T-09-06) |
| check-ct-branches.sh | PASS (exit 0) | authenticate branch=0 · CtLess branch=0 · verify_attest branch=41 관측 전용 (9-A~9-C 정합, LTO CT 재생성 0) |
| check-secure-zero.sh | PASS (exit 0) | secure_zero 심볼 존재 + memset U-entry 0 (HAL-05) |
| check-body-untouched.sh | PASS (exit 0) | tier1=6/50 (ipc.rs 선존분) · tier2=85/150 main.rs (cfg 제거+re-export+BootInfo 전환+블록c 제거 합계, cap 150 준수) |
| **check-arch-cfg-gate.sh** | **PASS (exit 0)** | **cfg(target_arch) 0 sites outside src/arch/ — HAL-06 최초 수렴 GREEN** |
| make check-mmu-typestate | PASS (exit 0) | activate 오호출 E0599 컴파일 거부 존속 (HAL-07 무약화) |
| check-alloc-zero / alloc-bus / no-dev-sk / no-network / machete | PASS (5/5 exit 0) | alloc 심볼 0 · bus alloc 0 · dev sk 부재 · Network 심볼 0 · unused dep 0 |
| wire-attest-host-test (실 sibling 경로) | PASS | 4 test 파일 x 3 = 12 pass (submit_dispatch/payload_layout/status_serialize/no_slot_mutation) |
| chan-dudect | 이연 (sibling 상태) | 명시 host target 시 컴파일 GREEN 이나 chan_ 필터 매치 0 (sibling 체크아웃에 dudect 하네스 부재) · phase 9 elib 파일 touch 0 · CT 회귀는 in-repo check-ct-branches GREEN 로 대체 확보 |
| host test (cargo test --no-default-features --target aarch64-apple-darwin) | PASS | 17 pass + 1 ignored = 18 (9-A~9-C baseline 정합, 회귀 0) |
| make qemu-smoke | 이연 (Linux+KVM lane) | macOS Apple Silicon KVM 부재 TCG 폴백 · ISO 빌드+부팅이 wall-clock 창(2분) 내 미완 (ML-KEM-768 TCG 지연 + post-TLS 스톨, 09-02/03/04 선례) — 부팅 경로 무결성은 nm 링크 실측 + linker.ld 계약 무변경 + in-repo 게이트로 확보, 마커 실검증은 Linux+KVM lane 이연 (silent skip 아님) |

## Decisions Made
- OQ2 이행 — uefi.rs 는 parse_uefi 시그니처만 잠근 stub (본문 unimplemented!), 발급 경로 0. multiboot2 1개가 유일 실동작 어댑터이며 Phase 11 LIVE-01 이 uefi 본문 채움
- OQ3 2단계 이행 — 중립 타입과 mb2 파서를 별 파일로 분할해 BootInfo 가 arch 경로를 미참조하게 만들어 펌웨어-중립성을 컴파일 그래프로 강제
- kaslr_offset 미배선 (decision 이행) — 어댑터가 parse_kaslr_offset 를 호출하지 않고 kaslr_offset=0 유지, _kernel_start 가 `if kaslr==0 { None }` 로 주입. GRUB 이 KASR 커스텀 태그를 넣지 않으므로 기존에도 parse 결과가 None 이라 런타임 동등. 실사용 배선 Phase 11 LIVE-09
- mb2 info 예약 블록 (c) 제거 (아래 Deviations 2) — mb2_addr 이 펌웨어-중립 진입점에서 소거됨에 따른 필연적 정리, 어댑터 소비 후 죽은 영역이므로 무회귀
- 커밋 메시지 포맷 (아래 Deviations 3) — 프로젝트/전역 CLAUDE.md 가 executor 기본 conventional 포맷을 오버라이드

## Deviations from Plan

### Auto-fixed / 필연 정리 Issues

**1. [Rule 3 - 배선] main.rs parse 호출 경로 정정 (분할 이동 필연)**
- **Found during:** Task 1 커밋 2 (배선)
- **Issue:** parse_multiboot2/parse_kaslr_offset 가 memory_map -> multiboot2 로 이동하므로 main.rs 의 `memory_map::parse_multiboot2` 가 미해소. plan Task 1 action 은 이 2 call site 정정을 명시하지 않았으나 빌드 GREEN 위해 필수.
- **Fix:** commit 2 에서 `crate::boot::multiboot2::parse_multiboot2/parse_kaslr_offset` 로 정정 (MemoryMap::empty 은 memory_map 유지). Task 2 가 _kernel_start 전면 재작성으로 두 call 을 어댑터 소비로 완전 대체하여 잔존 0 (grep parse_multiboot2 in main == 0).
- **Files modified:** src/main.rs
- **Verification:** cargo build GREEN (commit 2), grep parse_multiboot2 src/main.rs == 0 (commit 3)
- **Committed in:** `e1b347b` -> `f9f16e9`

---

**2. [Rule 3 - 블로킹] mb2 info 예약 블록 (c) 제거 (mb2_addr 소거 대응)**
- **Found during:** Task 2 (_kernel_start &BootInfo 전환)
- **Issue:** 기존 _kernel_start 의 allocator 초기화 (c) 단계가 `allocator::mark_used(mb2_addr, ...)` 로 mb2 info 구조체 물리 영역을 예약하나, 펌웨어-중립 `_kernel_start(&BootInfo)` 는 mb2_addr 을 보유하지 않음.
- **Fix:** 블록 (c) 제거. 보안 분석 — 어댑터가 parse_multiboot2 로 mb2 핸드오프 전량을 static BOOT_INFO(커널 .bss, allocator (b) 단계로 이미 예약 보호)로 복사한 뒤 진입하므로, 원본 mb2 info 영역은 _kernel_start 진입 시점에 더 이상 참조되지 않는 죽은 데이터. 해당 프레임이 재사용 가능해져도 살아있는 데이터 손상 0 -> 부팅 마커 무회귀. (a) 하위 1 MiB · (b) 커널 물리 범위 예약은 무변경 존치.
- **Files modified:** src/main.rs
- **Verification:** cargo build/build-rel GREEN, nm _boot_adapter_mb2 링크 존재, in-repo 게이트 전량 GREEN
- **Committed in:** `f9f16e9`

---

**3. [CLAUDE.md 이행] 커밋 메시지 포맷 오버라이드**
- **Found during:** 전 task 커밋
- **Issue:** executor 기본 `type(phase-plan): ...` conventional 포맷은 프로젝트 CLAUDE.md ("prefix chore/feat 금지", "커밋 메시지에 콜론 금지") 및 전역 CLAUDE.md (한국어 plain-text, ":"/"—"/"·"/"." 금지) 와 충돌.
- **Fix:** CLAUDE.md 가 executor 기본을 오버라이드 — 전 커밋을 한국어 plain-text (prefix/콜론/em-dash/middot/period 없음) 로 작성.
- **Files modified:** 없음 (커밋 메시지 규약)

---

**Total deviations:** 3 (1x 배선 필연 정정 · 1x 블로킹 정리 · 1x CLAUDE.md 포맷 이행)
**Impact on plan:** BootInfo + 4-어댑터 + 합류점 + memory_map 2차 분할 + cfg 전량 제거 전부 계획대로 완결. 신규 파싱 로직 0 (Security V5) · 동적 할당 0 · body-untouched tier1=6/50 · HAL-06 최초 GREEN 달성. scope creep 없음.

## Issues Encountered
- **qemu-smoke Linux+KVM 이연:** macOS Apple Silicon KVM 부재 -> TCG 폴백. ISO 빌드 + ML-KEM-768 TCG keygen + post-TLS 스톨 로 2분 wall-clock 창 내 마커 평가 미도달 (09-02/03/04 확립된 환경 제약, 본 부팅 경로 변경이 유발한 회귀 아님). 부팅 진입 경로 (_start -> _boot_adapter_mb2 -> _kernel_start) 무결성은 (1) release ELF nm 심볼 실측 (2) linker.ld .boot32/_start/ENTRY 계약 무변경 (오직 .quad 대상만 변경) (3) in-repo 게이트 6종 GREEN (4) host 18 test 로 확보. QEMU 마커 실검증은 Linux+KVM lane 이연 (T-09-06).
- **chan-dudect sibling 상태:** Makefile 하드코딩 경로 (/Library/Quant/Repository/projects/elib-k0-nt) 는 본 머신 부재 (09-03 실측 정합). 실 sibling worktree 에서 명시 host target 실행 시 constant-time 테스트는 컴파일 GREEN 이나 `chan_` 필터가 0 매치 (dudect 하네스 테스트가 해당 체크아웃에 부재). phase 9 base..HEAD elib 파일 변경 0 실측 -> SCOPE BOUNDARY out of scope. syscall/chan CT 회귀 가드는 in-repo check-ct-branches (kernel 바이너리 je/jne/jz/jnz 0) GREEN 로 대체 확보.

## User Setup Required
None - 외부 서비스 구성 불필요. 신규 의존성 0 (cargo add 0건).

## Known Stubs
- `src/boot/uefi.rs::parse_uefi` — 시그니처-only stub (본문 unimplemented!). plan 의도된 OQ2 표면 잠금이며 실동작 발급 경로 0. Phase 11 LIVE-01 이 본문 채움. 현 부팅 경로는 multiboot2 실동작 어댑터만 소비하므로 plan 목표 (BootInfo 합류점 잠금) 저해 없음.
- `BootInfo` 미배선 필드 (command_line/command_line_len/rsdp_ptr/dtb_ptr/framebuffer) + `parse_kaslr_offset` — 모두 #[allow(dead_code)] 로 보존, decision 명문에 따라 0/None 초기값 유지. kaslr/framebuffer/rsdp 는 Phase 11, dtb 는 Phase 10 이 실사용 배선. 신규 파싱 로직 0 (Security V5) 준수를 위한 의도적 미배선이며 목표 저해 없음.

## Threat Flags
없음 — 신규 network endpoint / auth path / 파일 접근 / schema 변경 0. threat_model 4종 전부 게이트로 완화 확인:
- T-09-05 (검증 없는 신규 파싱 유입): parse_multiboot2 lossless 재배치만, 미사용 필드 0/None, grep 신규 파싱 0 (Security V5)
- T-09-01 (mb2_addr 검증 전 BOOT_INFO 전역 노출): 기존 unwrap_or_else(empty) fail-safe lossless 이식 + BOOT_INFO 는 부팅 단일 스레드 어댑터 진입에서만 기록 (# Safety 명문)
- T-09-02 (진입 경로 변경 LTO CT 재생성): check-ct-branches release branch=0/0 존속
- T-09-06 (boot_stub .quad 오배선 부팅 불능): nm 심볼 실측 (_boot_adapter_mb2 T 존재) + linker.ld .boot32/_start 계약 무변경 + qemu 마커 Linux+KVM lane 이연

## Next Phase Readiness
- 9-C 완결 — HAL-06 최초 수렴 (check-arch-cfg-gate exit 0). src/arch/ 외부 cfg(target_arch) 0 standing gate 성립, 09-06 (9-D aarch64 stub surface lock + trait 잠금) 진입 가능
- 펌웨어-중립 합류점 _kernel_start(&BootInfo) 확정 — Phase 10 aarch64 boot stub 은 동일 BootInfo 를 채우는 arch 어댑터를 제공하면 자동 합류, Phase 11 limine/uefi 는 uefi.rs stub 본문을 채워 대칭 합류
- src/boot/ 4-파일 표면 잠금 (동적 할당 0) — memory_map 중립 타입은 arch 무의존, multiboot2 파서는 유일 펌웨어-format-aware 컴포넌트로 격리
- QEMU 2-leg (부팅 마커 실검증) + chan-dudect (sibling 하네스 복구 후) 는 Linux+KVM lane 이연 지속 — 본 plan 도 in-repo 게이트 6종 + host 18 test + wire 12 test + nm 링크 실측으로 무결성 확보
- STATE.md / ROADMAP.md 는 orchestrator 가 wave 종료 후 중앙 갱신 (worktree 모드 규약, 본 executor 미변경)

## Self-Check: PASSED

- 생성 파일 4종 FOUND (src/boot/{mod,memory_map,multiboot2,uefi}.rs) + 09-05-SUMMARY.md
- 삭제 대상 원본 FOUND 제거 (src/arch/x86_64/memory_map.rs ABSENT)
- 커밋 3종 FOUND (7c8400d 분할이동 / e1b347b 배선 / f9f16e9 합류+cfg제거)
- HAL-06 게이트 재현 GREEN (check-arch-cfg-gate exit 0) + nm _boot_adapter_mb2 링크 실측 + host 17+1=18 무회귀

---
*Phase: 09-architecture-hal-extraction*
*Completed: 2026-07-20*
