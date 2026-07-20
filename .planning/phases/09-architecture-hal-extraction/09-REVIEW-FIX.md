---
phase: 09-architecture-hal-extraction
fixed_at: 2026-07-20T11:54:50Z
review_path: .planning/phases/09-architecture-hal-extraction/09-REVIEW.md
iteration: 1
findings_in_scope: 7
fixed: 7
skipped: 0
status: all_fixed
---

# Phase 9: Code Review Fix Report

**Fixed at:** 2026-07-20T11:54:50Z
**Source review:** .planning/phases/09-architecture-hal-extraction/09-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 7 (Critical 0 + Warning 7, scope=critical_warning)
- Fixed: 7
- Skipped: 0

**최종 검증 (전 수정 적용 후):**
- `cargo build --target x86_64-unknown-none` (debug + release) GREEN
- `cargo test --target aarch64-apple-darwin --no-default-features` 17 passed + 1 ignored + 0 failed (회귀 0)
- 게이트 5종 전부 exit 0
  - check-arch-cfg-gate PASS (production cfg 0 + raw asm 0 debug 스캐폴딩 16 관측)
  - check-ct-branches PASS (CT 심볼 secret-dependent jCC 0)
  - check-secure-zero PASS (k0_secure_zero 심볼 존재 + memset U-entry 0)
  - check-body-untouched PASS (tier1 6/50 tier2 main.rs 94/150)
  - check-mmu-typestate PASS (E0599 음성 probe)

## Fixed Issues

### WR-01: mb2 KASLR 오프셋 파싱 경로 무언 제거 (보안 완화 경로 사멸)

**Files modified:** `src/boot/multiboot2.rs`, `src/main.rs`
**Commit:** 4e0fa7a
**Applied fix:** `_boot_adapter_mb2` 가 memory_map 파싱 직후 `parse_kaslr_offset(mb2_addr).unwrap_or(0)` 로 `BootInfo.kaslr_offset` 를 채우도록 배선 복원. 어댑터는 `_kernel_start` 의 allocator init 이전에 실행되므로 mb2 info 영역이 온전하여 IN-01(예약 제거)이 태그 접근을 막지 않음 -> 예약 복원 불필요. `parse_kaslr_offset` 의 `#[allow(dead_code)]` 제거(이제 호출자 존재), stale 문서 정정. main.rs 소비부(`boot_info.kaslr_offset == 0 ? None : Some`)는 이미 올바르므로 주석만 정정. nm 실측 `_boot_adapter_mb2`/`_kernel_start` 체인 T 심볼 존치 확인.
**비고 (human verification 권고):** 이는 보안 완화 경로 재활성이다. 컴파일·링크·소비 로직·심볼 체인은 실측 확인했으나 KASLR 태그가 실제로 흐르는 end-to-end 런타임 확인은 태그를 방출하는 부트로더 + QEMU 부팅이 필요하다. 표준 grub-mkrescue ISO 는 커스텀 태그를 방출하지 않아 런타임 값은 통상 None(0) 이며 무회귀다. 태그 실제 흐름 런타임 검증은 QEMU Linux+KVM lane 이연 대상(Phase 8 선례 macOS QEMU 제약).

### WR-02: main.rs 게이트 미포착 raw x86 asm 3건 (HAL-06 수렴 표면적)

**Files modified:** `src/arch/x86_64/cpu.rs`, `src/arch/x86_64/mod.rs`, `src/main.rs`, `scripts/check-arch-cfg-gate.sh`
**Commit:** 2ad0632
**Applied fix:** x86_64/cpu.rs 에 free fn `interrupts_disable()`(cli) / `interrupts_enable()`(sti) 신설(`#[cfg(target_arch = "x86_64")]`, `unsafe fn`, 기존 `wait_for_interrupt`/`halt_loop` 패턴 답습). X86Cpu trait impl 을 이 free fn 위임으로 갱신(asm 단일 소재화). main.rs L230 cli -> `crate::arch::active::cpu::interrupts_disable()`, L790 sti -> `interrupts_enable()`, `kernel_main_loop` 의 hlt -> `wait_for_interrupt()` 위임. check-arch-cfg-gate.sh 에 src/arch/ 외부 raw `asm!` 검출 레그 추가(게이트가 표면적 PASS 를 준 근본 원인 봉쇄). 실측 src/arch/ 외부 raw asm 0 확인.

### WR-03: check-ct-branches.sh 가 je/jne/jz/jnz 만 검출 (CT 분기 클래스 다수 누락)

**Files modified:** `scripts/check-ct-branches.sh`
**Commit:** d166409
**Applied fix:** 하드 게이트 카운터를 secret-dependent 조건부 점프 jCC 전수(`j(e|ne|z|nz|b|nb|be|nbe|a|na|ae|l|nl|le|nle|g|ng|ge|s|ns|c|nc|o|no|p|np)`)로 확장, cmov/setCC 는 branchless CT 목표 수단이므로 별도 관측 카운터로 분리(하드 게이트 아님). 실측 결과 대상 심볼은 정확히 게이트 정밀도 문제였음을 확인 -> hsm_registry::authenticate jCC=0(cmov/set=8 관측), constant_time::CtLess jCC=0(cmov/set=2 관측). verify_attest 는 관측 전용 jCC=62(D-12 입력 독립 분기 합법). 게이트 확장 후에도 CT 심볼 jCC 0 통과(진짜 CT 회귀 아님).

### WR-04: secure_zero x86 DF=0 가정 + 미지원 타깃 무언 no-op

**Files modified:** `src/arch/common/mod.rs`
**Commit:** fb8a62b
**Applied fix:** x86 `rep stosb` 앞에 `"cld"` 를 추가하여 DF=0(전진)을 명시 보장(DF=1 진입 시 역방향 버퍼 밖 손상 차단). asm 블록이 `preserves_flags` 를 주장하지 않으므로 DF 변경 안전. 함수 하단에 `#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))] compile_error!(...)` 를 두어 미지원 타깃의 조용한 no-op 소거 실패를 컴파일 타임 차단. release objdump 실측 본체 `movq; xorl; cld; rep stosb; retq` 직선 코드 확인(조건 분기 0).

### WR-05: HAL Console safe 메서드가 내부 unsafe MMIO 은폐

**Files modified:** `src/arch/mod.rs`, `src/arch/x86_64/mod.rs`
**Commit:** ea8ee45
**Applied fix:** Console trait 의 `write_str`/`clear` 를 `unsafe fn` 으로 승격하고 `# Safety` 에 콘솔 백엔드(VGA base) 초기화 계약을 명문화(HAL 의 여타 unsafe-wrapping trait 메서드 규약과 정합). X86Console impl 시그니처 동기. 미초기화 상태 호출 UB 를 safe 표면으로 노출하던 soundness 함정 제거. 외부 호출자 부재 실측(ZST dead-code) -> 회귀 0.
**비고:** trait 시그니처 계약 변경이므로 Phase 10 aarch64 Console 구현체가 동일 `unsafe fn` 표면을 소비하게 됨(의도된 계약 강화).

### WR-06: `#[unsafe(no_mangle)] secure_zero` 전역 심볼이 zeroize::secure_zero 와 충돌 위험

**Files modified:** `src/arch/common/mod.rs`, `scripts/check-secure-zero.sh`, `Makefile`
**Commit:** d48c580
**Applied fix:** 커널 raw buffer 소거 심볼 `secure_zero` -> `k0_secure_zero` 개명(프로젝트 접두어로 zeroize 표면과 명확 분리). 앵커 static `SECURE_ZERO_ANCHOR` -> `K0_SECURE_ZERO_ANCHOR` 및 참조 갱신, compile_error/docstring 동기. check-secure-zero.sh nm 정규식 ` [Tt] secure_zero` -> ` [Tt] k0_secure_zero` 갱신. 실측 확인: 모든 `secure_zero(...)` 호출부(ipc/keystore/sign_service/crypto_service/tls/syscall 등)는 `zeroize::volatile::secure_zero` import 사용, 커널 `arch::common::secure_zero` 는 앵커 전용 0-호출자 -> 개명 안전. release nm `T k0_secure_zero` 존치 + 게이트 PASS.

### WR-07: check-arch-cfg-gate.sh substring grep 이 cfg(all/any(target_arch)) 및 인라인 주석 회피 허용

**Files modified:** `scripts/check-arch-cfg-gate.sh`
**Commit:** 48bfab3
**Applied fix:** substring grep 을 강화하여 라인별 `//` 주석 선제거(awk `sub(/\/\/.*/, "", code)`) 후 `cfg(` + `target_arch` 동시 포함으로 판정 -> `cfg(all(...))`/`cfg(any(...))`/`cfg(not(...))` 중첩 형태와 인라인 주석 회피를 정확 포착(BSD/macOS awk 호환 위해 선택적 괄호 정규식 대신 2-조건 조합 사용, `\(?` 정규식은 BSD awk 에서 illegal primary 로 vacuous PASS 를 유발하여 회피). production(비-debug) arch cfg 는 하드 FAIL, `debug_assertions` 게이트 스캐폴딩은 관측 전용 분리. 실측 결과 src/arch/ 외부 production arch cfg 0(WR-02 raw asm 제거 후 main.rs production 코드는 ISA 독립), debug 스캐폴딩 16 sites(모두 debug_assertions 게이트) 관측 보고.
**설계 판단 (게이트 약화 아님):** 16 debug 스캐폴딩 site 는 x86 부팅 경로를 실행하는 테스트 전용 함수로 arch-gating 이 정당하며(가드 제거는 aarch64 하드 브레이크 유발 -> WR-02 회귀 패턴 재현), HAL-06 의 실질 목표인 production ISA 독립성은 하드 게이트로 유지된다. 미래의 production arch cfg 유입은 강화된 정규식으로 하드 FAIL 되며 스캐폴딩은 은닉 없이 투명 관측 보고된다.

## Skipped Issues

없음 (in-scope 7건 전부 fixed).

## 참고: Info findings (범위 외, 미대응)

fix_scope=critical_warning 이므로 IN-01 ~ IN-05 는 미대응. WR-01 대응 중 IN-01(mb2 info 예약 제거) 이 KASLR 태그 파싱을 막는지 실측 확인했으나 어댑터가 allocator init 이전에 파싱하므로 무관함을 확정. IN-01 의 RSDP/cmdline/framebuffer 소급 파싱 불가 이슈는 Phase 11 인계 문서 사안으로 잔존.

---

_Fixed: 2026-07-20T11:54:50Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
