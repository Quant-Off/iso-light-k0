---
phase: 09-architecture-hal-extraction
plan: 04
subsystem: infra
tags: [hal, no_std, inline-asm, zst, typestate, inline-always, vtable-zero, ct-gate, arch-cfg-gate, rust]

# Dependency graph
requires:
  - phase: 09-architecture-hal-extraction
    plan: 03
    provides: src/arch/x86_64/{mmu,idt,syscall,memory_map}.rs 이동 완결 + crate-root ISA 파일 0 + arch-cfg-gate 28 상태
  - phase: 09-architecture-hal-extraction
    plan: 01
    provides: 6 HAL trait 계약 (Cpu Mmu Idt Console BootEntry Entropy) + mmu typestate 음성 probe + CI 게이트 4종
provides:
  - src/arch/x86_64/process_entry.rs enter_user(cr3, rip, rsp) -> ! (구 process.rs enter_ring3 iretq asm lossless 추출본)
  - src/arch/x86_64/cpu.rs halt_loop() -> ! + wait_for_interrupt() free fn (panic/ipc 소비 표면)
  - 6 HAL trait x86_64 첫 구현체 전량 (X86Cpu/X86Mmu/X86Idt/X86Console/X86BootEntry ZST 5종 + 기 QuorumEntropy Entropy)
  - 본체 외과수술 3건 완료 (panic/ipc/process cfg·asm -> arch 표면 위임) 로 src/arch/ 외부 cfg 위반이 main.rs 25 만 잔존
  - X86Mmu 3 단계 typestate 위임 매핑 (HAL-07) + check-mmu-typestate GREEN 존속
affects: [09-05, 09-06, phase-10-arm-port]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "6 HAL trait 구현체 전부 ZST + 메서드 전수 #[inline(always)] -> 위임 후 잔여 호출 오버헤드 0 + vtable 미생성 (HAL-02/03)"
    - "본체 잔여 asm 은 arch/x86_64 free fn (halt_loop/wait_for_interrupt) + process_entry::enter_user 로 추출 후 arch::active 경로 단일 호출 위임"
    - "trait 선언 무변경 실현 -> 6 trait 시그니처가 실물 API (stac/clac/cli/sti/initialize/activate/init_idt/pic_eoi/print/update_base) 와 정합, 조정 0건"
    - "Mmu::phys_to_virt 는 AddressSpace::virt_to_phys 의 역 (phys + KERNEL_VMA_BASE) 로 수신자 없는 associated fn 유지"

key-files:
  created:
    - src/arch/x86_64/process_entry.rs
  modified:
    - src/arch/x86_64/cpu.rs
    - src/arch/x86_64/mod.rs
    - src/panic.rs
    - src/ipc.rs
    - src/process.rs

key-decisions:
  - "6 trait 시그니처 전부 실물 API 와 정합하여 arch/mod.rs 무변경 (plan 의 trait 조정 허용은 미행사 — 조정 불필요)"
  - "Mmu::phys_to_virt 는 mmu 의 &self+generic 메서드 대신 커널 세그먼트 관계식 (phys + KERNEL_VMA_BASE) 로 구현 -> 수신자 없는 associated fn 계약 (HAL-02) 유지"
  - "Idt::eoi(irq) 는 IRQ >= 8 (Slave PIC) 분기로 pic_eoi_slave / pic_eoi_master 위임 (단일 eoi 표면 부재 실물 대응)"
  - "post_mmu_enable 은 vga::update_base 인자를 (KERNEL_VMA_BASE + 0xB8000) 으로 명시 (plan 의 KERNEL_VMA_BASE 지시에 VGA 버퍼 오프셋 보정)"
  - "panic.rs aarch64 wfe 분기는 halt_loop 위임 시 소거 (aarch64 halt_loop 은 Phase 10 aarch64 hub 가 arch::active 로 제공)"

patterns-established:
  - "본체 외과수술 = 이동이 아닌 최소 편집 -> tier1 (ipc.rs) diff 6/50 로 예산 준수, process/panic 은 tier 목록 밖"
  - "trait 구현체 첫 실증 = Phase 10 aarch64 가 동일 표면 구현하도록 강제하는 컴파일 타임 계약의 x86_64 앵커"

requirements-completed: [HAL-03, HAL-06, HAL-07]

# Metrics
duration: 7min
completed: 2026-07-20
---

# Phase 9 Plan 04: 9-C 전반부 본체 외과수술 3건 + 6 HAL trait x86_64 구현체 Summary

**panic/ipc/process 의 잔여 cfg·asm 을 arch 표면 (halt_loop / wait_for_interrupt / process_entry::enter_user) 위임으로 교체해 src/arch/ 외부 cfg 위반을 main.rs 25 만 남기고, 6 HAL trait 의 x86_64 첫 구현체 (ZST 5종 + 기 Entropy) 를 inline(always) 21 메서드 전수 · vtable 0 · dyn 0 으로 완결하며 Mmu 3 단계 typestate 위임 매핑을 실증했다.**

## Performance

- **Duration:** 7분
- **Started:** 2026-07-20T05:05:08Z
- **Completed:** 2026-07-20T05:12:38Z
- **Tasks:** 3 완료
- **Files modified:** 6 (1 created + 5 modified)

## Accomplishments
- arch 표면 3종 신설 — cpu.rs 에 `halt_loop() -> !` (cli+hlt 무한 루프) + `wait_for_interrupt()` (hlt) free fn 이식, process_entry.rs 에 `enter_user(cr3, rip, rsp) -> !` 로 구 enter_ring3 의 cr3->swapgs->iretq atomic asm 블록을 오퍼랜드·순서 lossless 추출 (USER_CS/USER_DS 는 `crate::arch::x86_64::gdt` 직접 경로)
- 본체 외과수술 3건 — panic.rs cfg 2 분기 -> `arch::active::cpu::halt_loop()` 단일 호출, ipc.rs hlt asm 4줄 -> `wait_for_interrupt()` 1줄, process.rs iretq asm + None-분기 cli/hlt -> `process_entry::enter_user` + `halt_loop()` 위임 및 `crate::boot` 참조 제거. src/arch/ 외부 cfg 위반이 28 -> 25 (main.rs 전량) 로 수렴
- 6 HAL trait x86_64 첫 구현체 완결 — X86Cpu(11)/X86Mmu(4)/X86Idt(3)/X86Console(2)/X86BootEntry(1) 5 ZST + 기 QuorumEntropy(1) = 22 메서드, x86_64/mod.rs 신규 21 메서드 전수 `#[inline(always)]`, release 바이너리 vtable 심볼 0 · src/arch/ dyn/Box 0 실측 (HAL-03)
- X86Mmu 가 `Mmu<Uninitialized>::initialize` / `Mmu<Initialized>::activate` / `vga::update_base` 를 pre/enable/post 3 단계로 위임 매핑, mmu.rs 본문 무변경 · check-mmu-typestate E0599 음성 probe 존속 (HAL-07)

## Task Commits

각 task 원자적 커밋:

1. **Task 1: arch 표면 3종 추가 (halt_loop/wait_for_interrupt/process_entry)** - `8c1cf2b`
2. **Task 2: 본체 외과수술 3건 (panic/ipc/process)** - `cc048f1`
3. **Task 3: 6 HAL trait x86_64 ZST 구현체 5종 + HAL-03 검증** - `55d42f1`

## Files Created/Modified
- `src/arch/x86_64/process_entry.rs` - 신설. `enter_user(cr3, rip, rsp) -> !` cr3 적재 -> swapgs -> iretq 단일 atomic asm (options(noreturn) 유지), gdt 직접 경로 import
- `src/arch/x86_64/cpu.rs` - clac() 하단에 `halt_loop() -> !` + `wait_for_interrupt()` free fn 추가 (기존 본문 무변경, x86 asm 이식)
- `src/arch/x86_64/mod.rs` - `pub mod process_entry;` + ZST 5종 + 5 trait impl (21 메서드 inline(always)) 추가
- `src/panic.rs` - loop cfg 2 분기 제거 -> halt_loop() 위임 (본문 1 호출), cfg 2 site 소거
- `src/ipc.rs` - hlt asm 4줄 + stale SAFETY 주석 -> wait_for_interrupt() 1줄, cfg 1 site 소거 (tier1)
- `src/process.rs` - enter_ring3 iretq asm 추출 + None-분기 halt_loop() + `use crate::boot::{USER_CS, USER_DS}` 제거, asm! 0 site

## 9-C 전반부 종료 게이트 실측

| 게이트 | 결과 | 실측값 |
|--------|------|--------|
| cargo build --target x86_64-unknown-none | PASS | dev + release(make build-rel) 양 프로필 GREEN |
| check-ct-branches.sh (release) | PASS (exit 0) | HsmRegistry::authenticate branch=0 · constant_time::CtLess branch=0 · verify_attest branch=41 관측 전용 (9-A/9-B 정합, LTO CT 재생성 0) |
| check-mmu-typestate | PASS (exit 0) | Mmu<Uninitialized>::activate 오호출 E0599 컴파일 거부 존속 (위임 wrapper 추가 후에도 typestate 무약화, HAL-07) |
| check-body-untouched.sh | PASS (exit 0) | tier1=6/50 (ipc.rs 1 add + 5 del) · tier2=13/150 (main.rs 무변경) |
| check-arch-cfg-gate.sh | exit 1 (HAL-06 수렴 전 예상) | 25 sites 전량 src/main.rs (28 -> 25, -3 = panic 2 + ipc 1) · src/arch/ 외부 본체 잔여 0 |
| impl crate::arch:: (x86_64/mod.rs) | PASS | 5 (Cpu/Mmu/Idt/Console/BootEntry) |
| #[inline(always)] (x86_64/mod.rs) | PASS | 21 == 신규 impl 메서드 총수 (Entropy 1 은 arch/mod.rs 기존분 별도) |
| nm vtable (release) | PASS | 0 심볼 (dyn/Box 미사용 정적 디스패치) |
| dyn/Box grep (src/arch/) | PASS | 0 lines |
| host test (cargo test --no-default-features --target aarch64-apple-darwin) | PASS | 17 pass + 1 ignored = 18 (9-A/9-B baseline 정합, 회귀 0) |

## Decisions Made
- 6 trait 시그니처가 실물 API 와 전부 정합하여 `src/arch/mod.rs` 무변경 — plan 이 허용한 "trait 선언 측 조정" 은 조정 불필요로 미행사 (trait 은 여전히 9-D 종료 시 잠금 예정)
- `Mmu::phys_to_virt(pa) -> u64` 는 mmu.rs 의 `&self`+generic 메서드 대신 커널 세그먼트 관계식 `pa + KERNEL_VMA_BASE` (AddressSpace::virt_to_phys 의 역) 로 구현해 수신자 없는 associated fn (HAL-02 dyn 차단) 유지
- `Idt::eoi(irq)` 는 단일 eoi 표면 부재 실물에 맞춰 IRQ >= 8 (Slave PIC 경유) 분기로 pic_eoi_slave / pic_eoi_master 위임
- `X86Mmu::post_mmu_enable` 은 vga::update_base 인자를 `(KERNEL_VMA_BASE + 0xB8000)` 으로 명시 — plan 의 KERNEL_VMA_BASE 지시에 VGA 버퍼 phys 오프셋 보정 (아래 Deviations 1)
- panic.rs aarch64 wfe 분기는 halt_loop 위임으로 소거 — aarch64 halt_loop 은 Phase 10 aarch64 hub 가 arch::active 로 제공하는 구조 유지

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] post_mmu_enable 의 vga::update_base 인자 타입·오프셋 보정**
- **Found during:** Task 3 (X86Mmu impl 작성)
- **Issue:** plan 은 `post_mmu_enable -> vga::update_base(KERNEL_VMA_BASE)` 를 지시하나 (a) `vga::update_base` 는 `*mut u16` 인자를 받아 `u64` const 를 직접 전달 시 타입 불일치, (b) KERNEL_VMA_BASE 단독은 커널 세그먼트 기저 (0xFFFFFFFF80000000) 를 가리켜 VGA 버퍼(phys 0xB8000) 가 아님.
- **Fix:** `vga::update_base((mmu::KERNEL_VMA_BASE + 0xB8000) as *mut u16)` 로 VGA 버퍼의 커널 선형 매핑 가상 주소를 명시. 본 표면은 데모 구현체이며 boot path 는 자체 (주석 처리된) PHYS_MAP_OFFSET+0xB8000 경로를 유지하므로 실제 부팅 배선과 무충돌.
- **Files modified:** src/arch/x86_64/mod.rs
- **Verification:** cargo build GREEN (타입 정합), nm vtable 0
- **Committed in:** `55d42f1`

---

**2. [실측 정정] check-arch-cfg-gate 28 -> 25 감소, exit 1 은 수렴 전 예상 상태**
- **Found during:** Task 2 (arch-cfg-gate 실행)
- **Issue:** plan acceptance 는 "카운트 == main.rs 잔여분만" 을 요구하나 게이트 자체는 비-0 이면 exit 1 (HAL-06 수렴 미완).
- **Fix:** 실측 25 sites 전량이 src/main.rs (28 = main 25 + panic 2 + ipc 1 -> 25 = main 25) 임을 확인. src/arch/ 외부 본체 (panic/ipc/process) cfg 잔여 0 달성으로 acceptance (main.rs 잔여분만) 충족. main.rs cfg 소거는 Plan 05 대상이므로 exit 1 은 정상 (9-B 선례와 동일).
- **Files modified:** 없음 (측정값 기록만)

---

**Total deviations:** 2 (1x Rule 1 타입·오프셋 보정 · 1x 실측 정정)
**Impact on plan:** 본체 외과수술 3건 · 6 trait 구현체 · Mmu typestate 매핑 전부 계획대로 완결. trait 선언 조정 0 · mmu.rs 본문 무변경 · body-untouched tier1 6/50 로 예산 준수. scope creep 없음.

## Issues Encountered
- **check-arch-cfg-gate exit 1 존속:** 25 main.rs cfg site 는 Plan 05 (9-C 후반 main.rs cfg 소거) 대상. 본 plan 은 본체 (arch 외부 비-main) cfg 를 0 으로 만드는 것이 범위이며 이를 달성 (panic/ipc/process 전량 소거). HAL-06 완전 수렴 (0 sites) 은 Plan 05 이후.
- **qemu boot 마커 실검증 미수행:** T-09-01 (enter_user asm 추출 시 오퍼랜드·순서 변형) 완화는 asm 블록 lossless 추출 (오퍼랜드 목록 cr3/ss/cs/rsp/rip + options(noreturn) 무변경) + host 18 test + in-repo 게이트로 확보하나, iretq 권한 강하의 런타임 실검증은 macOS KVM 부재로 Phase 8/9 선례대로 Wave 5 게이트 (Linux+KVM lane) 이연.

## User Setup Required
None - 외부 서비스 구성 불필요. 신규 의존성 0 (cargo add 0건).

## Known Stubs
6 HAL trait x86_64 구현체 (X86Cpu/X86Mmu/X86Idt/X86Console/X86BootEntry) 는 `#[allow(dead_code)]` ZST 로 현재 boot path 미소비 상태 — 이는 plan 의도된 "첫 구현체 실증" 표면이며 Phase 10 aarch64 가 동일 trait 을 구현하도록 강제하는 컴파일 타임 계약의 x86_64 앵커임. 실제 boot path 배선 (free fn 경로 -> trait 경로 전환) 은 trait 잠금 (9-D) 이후 후속 phase 판단. plan must_haves 및 decisions 에 명시된 설계이므로 목표 저해 없음.

## Threat Flags
없음 — 신규 network endpoint / auth path / 파일 접근 / schema 변경 0. threat_model 4종 전부 게이트로 완화 확인:
- T-09-01 (enter_user asm 오퍼랜드 변형): asm 블록 lossless 추출 (오퍼랜드·순서·options 무변경) + host 18 test GREEN, qemu 런타임 검증 Wave 5 이연
- T-09-02 (ZST inline(always) LTO CT 재생성): check-ct-branches release 실측 branch=0/0 존속
- T-09-06 (panic halt_loop 무한 재귀): halt_loop 시그니처 `-> !` 컴파일 타임 divergence + grep 게이트 GREEN
- T-09-04 (typestate 약화): check-mmu-typestate E0599 존속 + Self::Uninit -> Self::Init 타입 전이 강제

## Next Phase Readiness
- 본체 외과수술 완결 — src/arch/ 외부 cfg 위반이 main.rs 25 만 잔존, Plan 05 (main.rs cfg 소거 + memory_map/syscall 분할) 로 HAL-06 완전 수렴 (0 sites) 진입 가능
- 6 HAL trait 전량 x86_64 첫 구현체 보유 — Phase 10 aarch64 hub 가 동일 표면 (Cpu/Mmu/Idt/Console/BootEntry/Entropy) 을 대칭 구현하면 arch::active 위임이 자동 성립
- process_entry::enter_user 는 Phase 10 SC #7 BootEntry::enter_user 합류 표면으로 확정 (X86BootEntry impl 이 이미 연결)
- QEMU 2-leg (iretq 권한 강하 실검증) 은 Linux+KVM lane 이연 지속 — 본 plan 은 in-repo 게이트 (build/ct-branches/mmu-typestate/body-untouched) + host 18 test + vtable 0 실측으로 무결성 확보
- STATE.md / ROADMAP.md 는 orchestrator 가 wave 종료 후 중앙 갱신 (worktree 모드 규약, 본 executor 미변경)

## Self-Check: PASSED

- 생성 파일 2종 FOUND (src/arch/x86_64/process_entry.rs + 09-04-SUMMARY.md)
- 수정 파일 5종 FOUND (cpu.rs/mod.rs/panic.rs/ipc.rs/process.rs)
- 커밋 3종 FOUND (8c1cf2b Task1 / cc048f1 Task2 / 55d42f1 Task3)
- 게이트 실측 재현 (impl=5, inline=21, vtable=0, dyn=0, tier1=6/50, cfg 25=main.rs)

---
*Phase: 09-architecture-hal-extraction*
*Completed: 2026-07-20*
