---
phase: 08-entropy-source-diversification
plan: 04
subsystem: entropy
tags: [quorum, entropy, boot, capability, audit-ring, blake3]
wave: 3
requires: [08-02, 08-03]
provides:
  - "QuorumEntropy::collect strict 2-of-3 fail-close boot path"
  - "QuorumEntropy::collect_with_retry runtime 60sec 폴링 재시드"
  - "capability::fill_hw_entropy 최종 quorum 단일점 (ENTR-06)"
  - "main.rs boot entropy marker 5종 + boot self-test 배선"
affects:
  - src/arch/common/entropy/quorum.rs
  - src/arch/common/entropy/mod.rs
  - src/capability.rs
  - src/main.rs
tech-stack:
  added: []
  patterns: ["BLAKE3 XOF 3-source mixing", "cfg-conditional QUORUM_MIN", "AUDIT_RING result 9..=12 lifecycle"]
key-files:
  created: []
  modified:
    - src/arch/common/entropy/quorum.rs
    - src/arch/common/entropy/mod.rs
    - src/capability.rs
    - src/main.rs
decisions:
  - "elib-k0-nt 실 crate 이름은 blake (path dep) 로 blake::Blake3 + blake::ct_eq_slice 사용"
  - "cpu.rs TimerKind + timer_frequency 확장은 Wave 2 산출물로 이미 존재 재사용"
  - "quorum.rs 수집 machinery 는 target_os none 게이트 host lib 은 struct+EntropyError+const 만 컴파일"
  - "timer 부재 fail-open-to-hang 차단 위해 RETRY_SPIN_CEILING 상한 추가 (fail-closed 보증)"
metrics:
  duration_min: 55
  completed: 2026-07-19
  tasks: 3
  files_modified: 4
---

# Phase 8 Plan 04: Wave 3 정책+통합 Summary

**QuorumEntropy production strict 2-of-3 fail-close 정책 본문 + BLAKE3 XOF 3-source mixing 을 채우고 capability::fill_hw_entropy 단일점을 quorum 호출로 최종 교체 + main.rs boot 시퀀스에 entropy marker 5종 + boot self-test 배선 완료 host test 18/18 회귀 PASS**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-07-19
- **Tasks:** 3/3
- **Files modified:** 4

## Accomplishments

- quorum.rs 에 QuorumEntropy collect (boot strict 2-of-3 fail-close) + collect_with_retry (runtime 60sec 폴링) + collect_from_source (per-source StreamHealth) 본문 채움. AUDIT_RING result 9..=12 (D-05 4 events 잠금) + slot_idx 0xFE/0xF0..0xF7 source-specific sub-encoding + BLAKE3 XOF mixing (blake::Blake3 신규 암호 0)
- capability::fill_hw_entropy 를 Wave 1 bridge stub (hw 직접 호출) 에서 QuorumEntropy::collect_with_retry(buf, 60_000) 단일 호출로 최종 교체. 양 cfg 분기 arch-중립 단일 본체로 통합. 호출자 init_prng / reseed_drbg 시그니처 변경 0 (ENTR-06 완전 충족)
- main.rs boot 시퀀스에 init_virtio_rng_instance + jitter_boot_self_test + timer line + ENTROPY_DEGRADED_OK_ACTIVE + ENTROPY_SOURCES_AVAILABLE=N + ENTROPY_QUORUM_2_OF_3_OK(또는 1_OF_3) 5종 marker emit. FATAL 메시지 entropy quorum failure 로 갱신 fail-closed 유지. format_timer_line / format_sources_line helper 신설 (alloc 0)
- mod.rs pub use quorum::{QuorumEntropy, EntropyError} 확정
- 4 cfg 분기 (closed / degraded / tls-external / smoke) 전수 컴파일 GREEN + mutex 조합 compile_error 차단 + release LTO 빌드 PASS + host test 4종 18/18 PASS 실측

## Task Commits

1. **Task 1: quorum.rs QuorumEntropy 본문 + mod.rs 재export** - `ee5fab1`
2. **Task 2: capability.rs fill_hw_entropy quorum 최종 교체** - `6019222`
3. **Task 3: main.rs boot entropy marker 5종 + boot self-test 배선** - `d44416a`

## Files Created/Modified

- `src/arch/common/entropy/quorum.rs` - QuorumEntropy struct + collect / collect_with_retry / collect_from_source / sources_available_at_boot + 3 StreamHealth BSS singleton + SOURCES_AVAILABLE_AT_BOOT latch + result 9..=12 const + sub-code 0..=3 + cfg-conditional QUORUM_MIN + BLAKE3 XOF mixing + elapsed_since_boot_ms helper (수집 machinery 는 target_os none 게이트)
- `src/arch/common/entropy/mod.rs` - pub use quorum::{QuorumEntropy, EntropyError}
- `src/capability.rs` - fill_hw_entropy 본문 QuorumEntropy::collect_with_retry 단일 호출로 교체 (bridge stub 제거)
- `src/main.rs` - boot 시퀀스 entropy init + marker emit + format_timer_line / format_sources_line helper 신설

## Decisions Made

- **blake crate 실 이름 채택** - Cargo.toml path dep 이름이 `blake` 이므로 plan 의 `elib_k0_nt::blake::Blake3` 대신 `blake::Blake3` + `blake::ct_eq_slice` 사용. finalize_xof(out_len) 은 SecureBuffer (고정 크기 stack 배열 MAX_OUTPUT_LEN 1024 Drop zeroize) 반환으로 alloc 0 보증
- **cpu.rs 미변경** - plan Task 3(d) 의 timer_frequency -> Option<(u64, TimerKind)> 확장 + TimerKind enum 은 Wave 2 (08-03) 산출물로 이미 존재. 본 wave 는 재사용만 (grep gate 정합)
- **수집 machinery target_os none 게이트** - src/lib.rs 의 host 전용 inline entropy 모듈이 quorum 을 포함하나 jitter / arch::cpu / hw / virtio_collect 는 host 부재. 수집 본체 + 3 StreamHealth static 을 `#[cfg(target_os = "none")]` 로 게이트하고 EntropyError + QuorumEntropy struct + const 만 cross-target 노출 (host lib 컴파일 보존)
- **RETRY_SPIN_CEILING 상한 추가 (Rule 2)** - timer_frequency None 시 elapsed 가 항상 0 이라 quorum 미복구 시 무한 spin 위험. spin 카운트 상한 (10_000_000) 을 두어 fail-open-to-hang 을 fail-closed panic 으로 종료 보증

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - 누락 안전기능] timer 부재 시 collect_with_retry 무한 spin 차단**
- **Found during:** Task 1
- **Issue:** plan 의 elapsed_since_boot_ms 는 timer_frequency None 시 0 반환. collect_with_retry 가 elapsed 만 의존하면 quorum 미복구 + timer 부재 조합에서 무한 loop (fail-open-to-hang) 발생 가능
- **Fix:** spins 카운터 + RETRY_SPIN_CEILING 상한 추가. `elapsed > max_wait_ms || spins > RETRY_SPIN_CEILING` 로 timer 부재에서도 fail-closed panic 종료 보증 (security_reminder fail-closed 정신 정합)
- **Files modified:** src/arch/common/entropy/quorum.rs
- **Commit:** `ee5fab1`

### 기록 사항 (비수정)

- **cpu.rs TimerKind / timer_frequency 확장 불필요** - plan Task 3(d) 는 timer_frequency 시그니처 확장을 지시하나 Wave 2 (08-03) 가 이미 `Option<(u64, TimerKind)>` + TimerKind enum 을 채움. 본 wave 는 재사용만 하여 cpu.rs 변경 0 (grep gate 는 그대로 PASS)
- **AUDIT_RING sub-code SUB_APT_FAIL(2) 예약** - StreamHealth::check 가 RCT 와 APT 실패를 HealthVerdict::Fail 단일 값으로 병합해 quorum 계층에서 두 test 구분 불가. health fail audit 는 SUB_RCT_FAIL(1) 로 통합 emit 하고 SUB_APT_FAIL(2) const 는 정의만 유지 예약. health.rs verdict 세분화는 Task 1 <files> scope 밖이라 미변경 (deferred-items 기록). fail 검출/차단 자체는 정상 동작 audit 정밀도만 한정
- **blake crate 실 이름** - plan 의 `elib_k0_nt::blake` 는 워크스페이스 표기 실 dep 이름은 `blake`

---

**Total deviations:** 1 auto-fixed (Rule 2 안전기능 1) + 기록 2
**Impact on plan:** fail-closed 강화 1건 외 plan 정합 실행. 호출자 시그니처 변경 0 커널 산출물 경로 변경 0

## Verification Results (실측)

| 항목 | 결과 |
|------|------|
| `cargo build --target x86_64-unknown-none` (closed) | PASS |
| entropy-degraded-ok 단독 / tls-external 단독 | PASS / PASS |
| smoke 단독 | PASS (gitignored dev sk 임시 provisioning 후 실측 커밋 0) |
| mutex 조합 (`tls-external,entropy-degraded-ok`) | compile_error 차단 확인 |
| `cargo build --release` (closed LTO) | PASS |
| `tests/entropy_health_rct_apt.rs` (host) | **6/6 PASS** |
| `tests/entropy_quorum_fault_inject.rs` `--include-ignored` | **3/3 PASS** |
| `tests/entropy_virtio_sentinel.rs` (host) | **4/4 PASS** |
| `tests/audit_entropy_schema.rs` (host) | **5/5 PASS** |
| EnrollEvent 12 옥텟 ABI compile assert (hsm_attest.rs L83) | 4 cfg 빌드 전수 compile 통과 |
| Task 1 grep gate (RESULT 4 / QUORUM_MIN / mod reexport / 0xF slot clean) | 전수 PASS |
| Task 2 grep gate (collect_with_retry / no collect_hw_into / no Timeout / sig 보존) | 전수 PASS |
| Task 3 grep gate (marker 6 / self-test / TimerKind / 2-source prefix 2) | 전수 PASS |
| QEMU 13 marker boot 회귀 | **본 host 이연** (Mac QEMU 11 TCG pre-existing 결함 deferred-items 기존 기록) 정본 검증은 Wave 4 Linux+KVM lane |

## Known Stubs

전부 Wave 4 진행 anchor 로 plan 이 명시

| Stub | File | 해소 시점 |
|------|------|-----------|
| audit schema test 의 result 9..=12 const 가 test-local 정의 (quorum.rs 정의 import 미전환) | tests/audit_entropy_schema.rs | Wave 4 (quorum const import 전환 가능) |
| fault-inject test 의 host 거울 harness (kernel collect_with_retry 는 hw/virtio/jitter 커널 전용이라 host 직접 호출 불가) | tests/entropy_quorum_fault_inject.rs | 구조상 host 재배선 불가 kernel qemu lane 위임 |
| SUB_APT_FAIL(2) const 정의만 유지 (health.rs verdict 세분화 대기) | src/arch/common/entropy/quorum.rs | health.rs verdict 확장 후속 (deferred-items) |
| 13 entropy 의존 marker 의 PASS 전환 (ENTR-07) | qemu-test.sh | Wave 4 boot smoke + check_marker flip |

## Threat Flags

없음. 본 wave 의 신규 surface (QuorumEntropy 정책 + AUDIT_RING result 9..=12) 는 전부 plan threat_model (T-08-02/04/06/08/12) 의 mitigate 대상 그대로 구현. capability.rs::fill_hw_entropy 단일점 교체로 호출자 시그니처 변경 0 boot marker 는 init_prng Ok 분기 안에서만 emit (honest gating)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Wave 4 진입 anchor 완비: quorum 정책 + capability 단일점 + main.rs marker 배선 완료. Wave 4 는 qemu-test.sh check_marker flip + check-jitter-lto.sh body PASS 재확인 + 13 entropy marker PASS 전환 검증 + ci-phase8 composite 실행 + Makefile entropy-host-test leg (deviation 5 형태) 작성
- smoke 빌드는 CI lane 에서 keys/dev_trust_root.sk44 provisioning 전제 (deferred-items 기록)
- ENTR-01 (3 sources) / ENTR-02 (strict 2-of-3 fail-stop) / ENTR-06 (단일점 교체) 핵심 surface 완성 ENTR-07 marker flip 만 Wave 4 잔존

---
*Phase: 08-entropy-source-diversification*
*Completed: 2026-07-19*

## Self-Check: PASSED

- modified files 4/4 FOUND (quorum.rs / mod.rs / capability.rs / main.rs)
- task commits 3/3 FOUND (ee5fab1, 6019222, d44416a)
- host test 18/18 PASS + 4 cfg 빌드 GREEN + mutex compile_error + release LTO PASS 실측
