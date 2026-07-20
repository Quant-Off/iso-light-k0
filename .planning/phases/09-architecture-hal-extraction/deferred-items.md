# Phase 09 Deferred Items

## 2026-07-20 Plan 06 (Wave 6 9-D 봉인) Phase 10 인계

9-D 표면 잠금 (aarch64 stub 허브 + arch/mod.rs cfg 분기) 완료 시점에 Phase 10 aarch64 포트가 "trait 의 두 번째 구현체 작성" 단일 작업으로 진입하도록 아래 가정·검증분을 인계한다. 각 항목은 Phase 9 에서 텍스트/링크 수준으로만 잠갔고 aarch64 타깃 실컴파일·런타임 검증은 Phase 10/11 로 이월된다.

### A1 crate-root abi_x86_interrupt attr 의 aarch64 컴파일 무해성 (미검증 가정)

- `src/main.rs:4` 의 `#![feature(abi_x86_interrupt)]` 는 x86_64 IDT 핸들러 ABI 를 위한 crate-root attr 이며 현재 aarch64 빌드에서의 거동이 미검증
- Phase 10 최초 `cargo check --target aarch64-unknown-none-softfloat` 시 본 attr 이 aarch64 에서 무해하게 통과하는지 (또는 cfg 게이트로 x86_64 한정해야 하는지) 검증 필수
- 만약 aarch64 에서 거부되면 `#[cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]` 형태 게이트가 필요 (단 feature attr 은 cfg_attr 로 못 감싸는 제약 있음 -> 대안은 별 crate 분리 또는 x86 전용 모듈 격리)

### OQ1 syscall ABI-중립 표면 분할 (Phase 10 첫 plan)

- `src/arch/x86_64/syscall.rs` 의 아래 4 표면은 ABI-중립부와 x86 전용부가 혼재하며 Phase 10 첫 plan 에서 중립부를 arch/common 으로 분할해야 함
  - `SyscallNum` enum (L129) ABI-중립 (syscall 번호 카탈로그)
  - `SyscallError` enum (L177) ABI-중립 (반환 코드)
  - `SyscallContext` struct (L110) **x86 레지스터 필드명 rdi/rsi/rdx 보유 -> 분할 시 주의**
  - `is_user_address` fn (L486) 주소 공간 경계 판정 (KERNEL_VMA_BASE 의존 -> aarch64 는 TTBR split 로 재정의)
- **Pitfall 8** `SyscallContext` 의 x86 레지스터 필드명 (rdi = arg0, rsi = arg1, rdx = arg2) 이 본체 `src/hsm_registry.rs` 와 `src/air_gap.rs` 에서 `ctx.rdi` 등으로 직접 소비됨 -> 필드명을 arg0/arg1/arg2 로 중립화하려면 이 두 소비처의 call site 도 동시 갱신 필요 (본체 diff 유발 -> body-untouched 게이트는 Phase 9 종료로 해제되므로 Phase 10 은 자유)
- 분할 시 aarch64 는 x0/x1/x2 (AAPCS64) 를 SyscallContext 의 동일 arg 슬롯에 매핑

### ARM-01 aarch64 타깃/링커 (Phase 10 범위)

- `aarch64-unknown-none-softfloat` rustup 타깃이 현재 미설치 (본 wave 실측 확인) -> Phase 10 최초 게이트에서 `rustup target add aarch64-unknown-none-softfloat` 선행
- `linker-aarch64.ld` (현재 부재) 신설 필요 x86 의 `linker.ld` .boot32/_start/ENTRY 계약 대응부를 aarch64 EL1 진입 규약으로 재작성
- 첫 `cargo check --target aarch64-unknown-none-softfloat` 통과가 9-D stub 허브 (`src/arch/aarch64/mod.rs`) 의 첫 실컴파일 게이트 (현재는 텍스트 표면 잠금 상태 OQ4)

### ARM-11 secure_zero aarch64 asm 실검증

- `src/arch/common/mod.rs` 의 `secure_zero` aarch64 분기 (`str xzr, [{p}], #8` 8 바이트 루프 + `strb wzr` 잔여) 는 골격만 존재하고 실행 검증 미수행
- Phase 10 ARM-11 에서 aarch64 빌드 후 objdump 로 `str xzr`/`strb wzr` 본문 확인 + memset U-entry 0 (compiler elide 부재) 실측 필요 (x86 rep stosb 게이트 대응부)

### iretq/eret 런타임 권한 강하 실검증 (QEMU 이연 하류)

- Plan 04 에서 추출한 x86 `enter_user` (`src/arch/x86_64/process_entry.rs`) 의 iretq 권한 강하는 asm lossless 추출 + host 18 test + in-repo 게이트로만 확보, iretq 실런타임 검증은 macOS KVM 부재로 Linux+KVM lane 이연
- Phase 10 aarch64 `Aarch64BootEntry::enter_user` (현재 stub) 는 대응하는 eret 강하 (`msr elr_el1` + `msr sp_el0` + `eret`) 를 채우며, x86 iretq + aarch64 eret 양쪽의 Ring 3 최초 진입 실검증은 QEMU Linux+KVM lane 에서 수행

### src/boot/uefi.rs 본문 채움 -> Phase 11 LIVE-01

- `src/boot/uefi.rs::parse_uefi` 는 시그니처-only stub (본문 `unimplemented!`, OQ2 표면 잠금) 이며 실동작 발급 경로 0
- HAL-08 "4 어댑터" 문언 (mod.rs BootInfo + memory_map 중립 타입 + multiboot2 실동작 + uefi stub) 의 사후 verifier 대조 시 uefi 는 의도된 stub 임을 본 인계로 명시
- Phase 11 LIVE-01 이 uefi.rs 본문을 채워 limine/uefi 부트로더가 `_kernel_start(&BootInfo)` 합류점에 대칭 진입 (multiboot2 어댑터와 동일 struct 소비)

### docs/dispatch-reachability.md 경로 갱신 (본 plan 완료)

- Phase 7 산출물의 구 경로 인용 (src/syscall.rs / src/idt.rs / src/vga.rs) 을 9-A/9-B 이동 후 신 경로 (src/arch/x86_64/syscall.rs / idt.rs / vga.rs) 로 정정 완료 (Runtime State Inventory 항목 4)
- 라인 번호는 역사 기록물 성격 유지 위해 재검증하지 않고 경로만 정정 -> Phase 10 이 syscall 분할 시 해당 문서의 SyscallNum 축 경로가 다시 이동될 수 있음 (그때 재갱신)

### QEMU 이연 lane 목록 (Linux+KVM lane 재실행 필요)

본 macOS Apple Silicon 호스트는 /dev/kvm 부재 + QEMU 11 TCG RDRAND/RDSEED 결함 + post-TLS stall + ML-KEM-768 TCG keygen 지연 (2분 wall-clock 창 초과) 로 아래 qemu leg 를 전 sub-step 에서 이연했다 (각 plan SUMMARY 실측 취합, silent skip 아님). Linux+KVM lane 에서 재실행 필요하다.

- 9-A (Plan 02) qemu-smoke 부팅 진입 PASS 하류 마커 MISS -> multiboot2 헤더 + boot32 스텁 + GDT 로더 이동본 부팅 무결성은 부팅 진입 PASS + objdump SMAP 로 확보, 마커 실검증 이연
- 9-B (Plan 03) qemu-smoke 부팅 진입 (stage 2-3) 도달 -> moved idt/mmu/syscall/memory_map/boot 부팅 시퀀스 무결 로드 확인, 하류 마커 이연
- 9-C 전반 (Plan 04) iretq 권한 강하 런타임 실검증 이연 (enter_user asm lossless 추출 + host 18 test 로 확보)
- 9-C 후반 (Plan 05) qemu-smoke 이연 -> _start -> _boot_adapter_mb2 -> _kernel_start 합류점 무결성은 release ELF nm 심볼 실측 + linker.ld .boot32/_start/ENTRY 계약 무변경 + in-repo 게이트 6종으로 확보
- 9-D (Plan 06) ci-phase9 합성 게이트의 qemu-smoke leg -> host 9 leg 전수 GREEN 실측, qemu leg 만 Linux+KVM lane 이연 (아래 ci-phase9 실측 참조)
- Linux+KVM lane 재실행 대상
  - `make ci-phase9` 10-leg composite 최종 GREEN (host 9 leg 는 본 wave 확보, qemu-smoke leg 추가)
  - ci-phase{1..6} qemu-smoke/qemu-smoke-smoke/qemu-smoke-tls-external leg (Phase 1~6 마커 회귀)
  - x86 iretq + aarch64 eret Ring 3 최초 진입 실검증

### ci-phase9 최종 실측 (본 wave 봉인)

- host-runnable 9 leg 전수 PASS 실측 (Plan 06 SUMMARY 실측 표 참조)
  - check-alloc-zero / check-machete / check-entropy-mutex / check-jitter-lto (standing 4 leg)
  - check-arch-cfg-gate / check-ct-branches / check-secure-zero / check-body-untouched / check-mmu-typestate (Phase 9 신규 5 leg)
- qemu-smoke (10th leg) 는 위 QEMU 이연 lane 사유로 Linux+KVM lane 이연 (honest 표기, silent skip 아님)
