# Air-Gap Dual Enforcement ABI v1

본 문서는 iso-light-k0 커널의 Phase 6 air-gap 이중 게이트 (build-time `tls-external` feature + runtime `NETWORK_ATTACH` capability) 의 *Ring 3 측 syscall ABI* 명세이다. Ring 3 클라이언트 작성자 (`iso-user-lumen` / 운영자) 와 감사 자료 분석자가 본 문서만 읽고 (a) 신규 3 syscall 의 정확한 호출 + (b) `EnrollEvent.result` 7 코드의 의미 + (c) Pitfall 3 (`bus_kind` octet 도용) 해석 + (d) Pitfall 5 (`NotImplemented` vs `AttestFailed` 의미 분리) 를 모두 명료히 이해할 수 있어야 한다.

본 명세는 v1 이며 본 마일스톤 (v1.0 Multi-HSM Connector) 종료 시점 잠금 자료이다. kernel 측 정의 위치는 `src/air_gap.rs` 의 `StatusEntry` / `NetCapState` / `init_audit_read_cap` / `init_network_cap` / `gap_self_check` / `take_network_cap` / `take_audit_read_cap` / `handle_status` 와 `src/syscall.rs::SyscallNum` 의 `NetworkCapTake = 14` / `AuditCapTake = 15` / `HsmStatus = 16` 3 신규 변종이다.

본 문서는 Phase 5.1 `docs/wire-protocol.md` 의 wire ABI 명세 패턴을 mirror 한 결과물이다 (PATTERNS §11, 75% role-match).

## 1. Overview

본 문서의 책임 경계

- **본 문서가 잠금:** `sys_hsm_status` / `sys_network_cap_take` / `sys_audit_cap_take` 3 syscall 의 register snapshot + 응답 layout + audit 의미, `EnrollEvent.result` 7 코드 통합 표, Pitfall 3 (`bus_kind` octet 도용) 해석 가이드, Pitfall 5 (`BusInstance::Network` arm `NotImplemented` stub) 의 운영자 해석.
- **본 문서가 잠금 X:** Zero-Trust / Air-Gapped Ready 의 *정책 선언* 과 본 마일스톤의 *위협 모델* — top-level `/AIR-GAP.md` 책임.
- **본 문서의 독자:** Ring 3 클라이언트 작성자 (`iso-user-lumen` / 후속 어플라이언스), 감사 자료 분석자, Ring 3 보안 감사자.

본 문서의 진리값 자료 위치

- `src/air_gap.rs` (Plan 06-02 잠금) — `StatusEntry` 8 옥텟 / `GAP_STATUS_LEN = 456` 옥텟 / `NetCapState` FSM / `init_*_cap` BSS bootstrap / `gap_self_check` 2-layer self-check
- `src/syscall.rs` (Plan 06-03 잠금) — `SyscallNum::NetworkCapTake = 14` (`cfg(feature = "tls-external")`) / `AuditCapTake = 15` (양 프로필 공통) / `HsmStatus = 16` (양 프로필 공통)
- `src/hsm_attest.rs` (Phase 5 D-13 잠금) — `EnrollEvent` 12 옥텟 ABI + `audit_enqueue` / `audit_snapshot` 헬퍼

본 문서가 명시하지 않는 항목 (Out of Scope)

- v2 phase 7+ — NETWORK_ATTACH cap 회전 / 재발급, `HSM_CAP_MINTER` 별도 bootstrap cap, audit log 영구 저장, 실 TLS 스택 (`rustls` / `mbedtls` 베어메탈), `sys_hsm_status` incremental 모드, `WireCmd` 표면의 `sys_hsm_status` 추가 mirror.
- `BusInstance::Network` arm body 의 실 TLS 구현은 v2 HW-04 위임 — 본 마일스톤에서는 `BusError::NotImplemented` stub 만 (§5 Pitfall 5 참조).

## 2. sys_hsm_status ABI

본 syscall 은 kernel 의 8 슬롯 HSM 등록부 + 32 엔트리 AUDIT_RING 을 단일 atomic 호출로 스냅샷 한다. AUDIT_READ capability 보유자만 진입 가능. Phase 5 의 sys_hsm_enumerate 와는 별개 — enumerate 는 slot 만 / status 는 slot + audit 양쪽.

### Register snapshot

| 레지스터 | 의미 |
|---------|------|
| `rax` | `SyscallNum::HsmStatus = 16` |
| `rdi` | `out_ptr` — Ring 3 user space 정적 버퍼 (456 옥텟 이상) |
| `rsi` | `out_len` — `out_ptr` 가 지시하는 버퍼 크기 (옥텟). `< 456` 시 `Denied` |
| `rdx` | `cap_token` — 호출자가 `sys_audit_cap_take` 로 회수한 `HsmCapability.token` (u64) |
| `RAX` 결과 | `0` = success / `-3` = `BadAddress` (`out_ptr` 범위 오류) / `-4` = `Denied` (cap 불일치 또는 `out_len < 456` 의 `BufferTooSmall` 콜럐스) |

`out_len < 456` 의 `BufferTooSmall` 케이스는 `Denied` 와 단일 collapse 된다 (Pitfall 7 — variant 노출 최소화). 운영자가 `Denied` 를 받았을 때 (a) cap 검증 실패 (b) 버퍼 크기 부족 두 경우를 구분하려면 본 ABI 본문을 참조하여 호출 측에서 미리 `out_len ≥ 456` 가드를 두어야 한다.

### 응답 layout (456 옥텟)

```
offset 0..2    : status_entries_written u16 LE   (0..=8 — 실제 채워진 slot 개수)
offset 2..4    : audit_events_written u16 LE     (0..=32 — 실제 채워진 audit 개수)
offset 4..8    : audit_total_counter u32 LE      (AUDIT_RING 누적 enqueue 수, ring wrap 감지 hint)
offset 8..72   : [StatusEntry; 8]                (64 옥텟 = 8 × 8 B)
offset 72..456 : [EnrollEvent; 32]               (384 옥텟 = 32 × 12 B)
```

| offset | length | content |
|--------|--------|---------|
| 0..2 | 2 | `status_entries_written` u16 LE (0..=8) |
| 2..4 | 2 | `audit_events_written` u16 LE (0..=32) |
| 4..8 | 4 | `audit_total_counter` u32 LE — ring wrap 감지용 누적 카운터 |
| 8..72 | 64 | `[StatusEntry; 8]` (8 × 8 B) |
| 72..456 | 384 | `[EnrollEvent; 32]` (32 × 12 B) |

총 456 옥텟. 호출자 버퍼의 `[456..out_len]` 잔여 영역은 미접촉 (kernel 이 단일 SMAP write window 안 1 회 복사로 처음 456 옥텟만 기록).

### StatusEntry layout (8 옥텟)

`#[repr(C)] StatusEntry`, `align_of == 1`, padding 옥텟 부재.

| offset | length | field | encoding |
|--------|--------|-------|----------|
| 0 | 1 | `slot_idx` | `u8` — 슬롯 인덱스 `0..=7` 또는 `0xFF` (미할당) |
| 1 | 1 | `bus_kind` | `u8` — `BusKind` octet (Phase 2 D-19) |
| 2 | 1 | `attest_result` | `u8` — `verify_result_code` (Phase 5 D-14) |
| 3 | 1 | `_pad` | `u8` — 항상 `0` 잠금 (Pitfall 6) |
| 4..8 | 4 | `pk_hash_prefix` | `[u8; 4]` — `BLAKE3(pk)[0..4]` 4 옥텟 (Phase 5 D-14) |

빈 슬롯의 entry 는 `slot_idx = 0xFF`, 나머지 필드는 0 잠금. `bus_kind` octet 값은 `BusKind` enum 의 discriminant 와 정확히 일치 — `0=Software / 1=Ring3Process / 2=Usb / 3=Spi / 4=Serial / 5=SmartCard / 6=Network` (Phase 2 D-19, `#[non_exhaustive]`).

### EnrollEvent layout (12 옥텟)

Phase 5.1 `docs/wire-protocol.md` §WireCmd::Status 의 12 옥텟 layout 과 동일 (Phase 5 D-13 잠금). 본 문서는 mirror 명시만 — 변경 시 양 문서 동시 정정 필요.

| offset | length | field |
|--------|--------|-------|
| 0..4 | 4 | `seq` u32 LE — ring 내 순서 카운터 |
| 4..5 | 1 | `slot_idx` u8 |
| 5..6 | 1 | `result` u8 (§5 코드 표) |
| 6..7 | 1 | `bus_kind` u8 |
| 7..8 | 1 | `_pad` u8 (0 잠금) |
| 8..12 | 4 | `pk_hash_prefix` `[u8; 4]` |

`slot_idx` 값 영역 (Phase 5 + 5.1 + 6 통합)

- `0..=7` — 실제 부착 슬롯 인덱스 (Phase 5 attach 게이트)
- `0xFD` — `sys_audit_cap_take` audit marker (Phase 6 D-06, §4 참조)
- `0xFE` — `sys_network_cap_take` audit marker (Phase 6 D-03) 또는 wire-side re-attestation marker (Phase 5.1 `WireCmd::AttestSubmit`)
- `0xFF` — 부재 슬롯 sentinel (Phase 5 attach 실패 / Phase 6 cap-less 또는 closed-build NetworkDenied)

### Audit 의미

- 본 syscall 호출 *자체* 는 `AUDIT_RING` 에 기록되지 않음 — audit-of-audit 무한 재귀 회피 (D-05 + T-06-06 mitigation).
- `cap_token` 검증 실패만 audit 기록 — `audit_enqueue(slot=0xFF, result=2, bus_kind=Software=0, pk_hash_prefix=[0;4])` (NetworkDenied 콜럐스 5 카테고리 중 5번 — §3 참조).
- `out_len < 456` 의 `BufferTooSmall` 케이스는 audit 미기록 — 정상 호출이지만 ABI 미숙지로 분류 (Pitfall 2 + T-06-07 mitigation). 운영자는 `RAX = -4` (Denied) 를 받았을 때 audit 기록 부재 여부로 cap-fail vs buffer-fail 을 분리할 수 있다.

## 3. sys_network_cap_take ABI

본 syscall 은 부팅 시 1 회 mint 된 `NETWORK_ATTACH_CAP` (16 옥텟 `HsmCapability`) 을 Ring 3 first caller 에게 인도한다. first-caller-wins 시맨틱 — `NetCapState::Provisioned → Taken` 단방향 전이, 부팅 1 회 mint 후 회전 없음 (v2 deferred). `cfg(feature = "tls-external")` 게이트 — closed 빌드는 본 syscall 자체가 컴파일에서 제외된다.

### Register snapshot

| 레지스터 | 의미 |
|---------|------|
| `rax` | `SyscallNum::NetworkCapTake = 14` (`#[cfg(feature = "tls-external")]` — closed 빌드 변종 부재) |
| `rdi` | `out_ptr` — Ring 3 user space 정적 버퍼 (16 옥텟 이상) |
| `RAX` 결과 | `0` = success / `-3` = `BadAddress` (out_ptr 범위 오류) / `-4` = `Denied` (state == `Taken` 재호출 collapse) / `-1` = `Unknown` (closed 빌드 변종 부재 — dispatcher 가 미지정 syscall 로 분류) |

`Unknown` 변종은 closed 빌드의 Ring 3 호출자가 본 syscall 을 시도했을 때 일관 collapse 된다 — closed 빌드에는 `SyscallNum::NetworkCapTake` enum variant 자체가 부재이므로 dispatcher `match` arm 의 `_ => SyscallError::Unknown.as_rax()` 폴백이 매칭된다.

### 응답 layout (16 옥텟)

`#[repr(C, align(8))] HsmCapability` — Phase 1 D-02 ABI 그대로 mirror.

| offset | length | field | encoding |
|--------|--------|-------|----------|
| 0..8 | 8 | `token` | `u64` LE — `CAP_DRBG` 가 부팅 시 1 회 합성한 unforgeable token |
| 8..9 | 1 | `slot` | `HsmSlotIdx` u8 — `0xFE` (cap-take marker, 실 슬롯 아님) |
| 9..10 | 1 | `_pad0` | `u8` — 0 잠금 |
| 10..12 | 2 | `rights` | `u16` LE — `HsmRights` 비트 (`NETWORK_ATTACH` 비트 set) |
| 12..13 | 1 | `_pad` | `u8` — 0 잠금 |
| 13..16 | 3 | `_pad1` | `[u8; 3]` — 0 잠금 |

### FSM (first-caller-wins)

`NetCapState` `#[repr(u8)]` — `Provisioned = 0` / `Taken = 1`. BSS default 가 `Provisioned`, take 호출 성공 시 `Taken` 단방향 전이. `Taken → Provisioned` 역전이 부재 (v2 회전 도입 시 `Revoked` / `Reprovisioned` variant 추가 예정).

### NetworkDenied 5 카테고리 (CONTEXT.md D-04)

`result = 2 (NetworkDenied)` 의 enqueue 시점은 다음 5 카테고리로 콜럐스된다. audit 자료 분석자는 `(slot_idx, bus_kind)` 튜플로 카테고리를 추정한다.

1. closed-build 에서 `BusKind::Network` 부착 시도 — `handle_attach` 의 matchless `_` arm 도달 시 `audit_enqueue(slot=0xFF, result=2, bus_kind=Network=6)` (Plan 06-04 D-01)
2. tls-external build 에서 `NETWORK_ATTACH` cap 미보유 부착 시도 — `audit_enqueue(slot=0xFF, result=2, bus_kind=Network=6)` (Plan 06-04)
3. tls-external build 에서 `sys_network_cap_take` state == `Taken` 시 재호출 — `audit_enqueue(slot=0xFE, result=2, bus_kind=Network=6)` (Plan 06-04 D-03)
4. tls-external build 에서 `sys_audit_cap_take` state == `Taken` 시 재호출 — `audit_enqueue(slot=0xFD, result=2, bus_kind=Software=0)` (Plan 06-04 D-06)
5. `sys_hsm_status` AUDIT_READ cap 미보유 호출 — `audit_enqueue(slot=0xFF, result=2, bus_kind=Software=0)` (§2 Audit 의미)

`bus_kind = Network=6` vs `Software=0` 의 분기는 `NETWORK_ATTACH` 계열 (1/2/3) 과 `AUDIT_READ` 계열 (4/5) 의 단일 식별자.

### Audit 의미 (양방향 기록)

- 성공: `audit_enqueue(slot=0xFE, result=3 (NetworkCapTaken), bus_kind=Network=6, pk_hash_prefix=[0;4])`
- 실패 (state == `Taken` 재호출): 위 카테고리 3.

## 4. sys_audit_cap_take ABI

본 syscall 은 부팅 시 1 회 mint 된 `AUDIT_READ_CAP` (16 옥텟 `HsmCapability`) 을 Ring 3 first caller 에게 인도한다. `sys_network_cap_take` 와 동일 형태 + first-caller-wins FSM. 차이점은 (a) cfg 게이트 부재 (양 프로필 공통 — audit 는 외부망과 무관한 운영 기능) (b) `slot_idx = 0xFD` (c) `bus_kind = Software = 0` (도용 — Pitfall 3).

### Register snapshot

| 레지스터 | 의미 |
|---------|------|
| `rax` | `SyscallNum::AuditCapTake = 15` (양 프로필 공통) |
| `rdi` | `out_ptr` — Ring 3 user space 정적 버퍼 (16 옥텟 이상) |
| `RAX` 결과 | `0` = success / `-3` = `BadAddress` / `-4` = `Denied` (state == `Taken` 재호출 collapse) |

### 응답 layout

`sys_network_cap_take` 와 동일 (16 옥텟 `HsmCapability`), 차이는 `slot` 옥텟이 `0xFD` (cap-take marker), `rights` 가 `AUDIT_READ` 비트 set.

### Pitfall 3 — `bus_kind` octet 도용 해석 가이드

본 syscall 의 audit enqueue 는 `bus_kind = Software = 0` 으로 기록된다 (실제 audit cap 자체는 외부망과 무관한 운영 기능이므로 `BusKind::Software` 도용). 운영자는 audit 자료 분석 시 `(result, slot_idx)` 튜플로 케이스를 분리한다.

| `result` | `slot_idx` | `bus_kind` | 의미 |
|---------|-----------|-----------|------|
| `3` (NetworkCapTaken) | `0xFE` | `Network = 6` | `sys_network_cap_take` 성공 (NETWORK_ATTACH cap 인도, Phase 6 D-03) |
| `3` (NetworkCapTaken) | `0xFD` | `Software = 0` | `sys_audit_cap_take` 성공 (AUDIT_READ cap 인도, Phase 6 D-06) |
| `3` (NetworkCapTaken) | `<8` | (slot 의 실 bus_kind) | 실 Software HSM attach 성공 (Phase 5 D-13) — 본 케이스는 코드 `0=Ok` 사용 가능성 더 높음, `3` 은 Phase 6 cap-take 표면 한정 권장 |
| `2` (NetworkDenied) | `0xFF` | `Software = 0` | `sys_hsm_status` cap-fail 또는 `NETWORK_ATTACH` cap-less attach 시도 (§3 카테고리 2 또는 5) |
| `2` (NetworkDenied) | `0xFE` | `Network = 6` | `sys_network_cap_take` state == Taken 재호출 (§3 카테고리 3) |
| `2` (NetworkDenied) | `0xFD` | `Software = 0` | `sys_audit_cap_take` state == Taken 재호출 (§3 카테고리 4) |

`BusKind` enum 의 `0 = Software` 변경 시 본 표도 함께 정정 필요 (BUS-02 와 결합 — Phase 2 D-19 잠금이 본 도용의 안전성 보증).

## 5. EnrollEvent.result 통합 코드 표 + Pitfall 5

본 절은 본 마일스톤 종료 시점 `EnrollEvent.result` octet 의 7 코드 진리값 자료이다. Phase 5 + Phase 5.1 + Phase 6 누적 + 7..=255 v2 예약.

### EnrollEvent.result 코드 표

| code | name | phase | enqueue 시점 | 의미 |
|------|------|-------|--------------|------|
| `0` | `Ok` | Phase 5 (D-13) | `handle_attach` attach + `verify_attest` 성공 | 실 슬롯 attach 성공 (`slot_idx ∈ 0..=7`) |
| `1` | `AttestFailed` | Phase 5 (D-13) | `verify_attest` 실패 | `mldsa::Error` 4 variant collapse — `(slot=0xFF, result=1)` |
| `2` | `NetworkDenied` | Phase 6 (D-04) | §3 5 카테고리 콜럐스 | closed-build attach / cap-less attach / cap-take state==Taken / status cap-fail |
| `3` | `NetworkCapTaken` | Phase 6 (D-04) | `sys_network_cap_take` 또는 `sys_audit_cap_take` 성공 | `slot_idx` 로 NETWORK vs AUDIT 분리 (§4 Pitfall 3) |
| `4` | `GapSelfCheckFail` | Phase 6 (D-04) | `gap_self_check` Layer 2 misconfig 감지 | enqueue 직후 `panic = abort` — 사실상 tls-external 빌드에서만 도달 (closed 빌드는 panic 으로 AUDIT_RING 접근 전에 정지) |
| `5` | `WireReattestOk` | Phase 5.1 (D-03) | `WireCmd::AttestSubmit` 성공 (epoch-rollover re-attest) | `(slot=0xFE, result=5)` (`docs/wire-protocol.md` §AttestSubmit Audit Trail) |
| `6` | `WireReattestFail` | Phase 5.1 (D-03) | `WireCmd::AttestSubmit` 실패 | `(slot=0xFE, result=6)` |
| `7..=255` | (v2 예약) | — | — | v2 phase 7+ 신규 사용 (detach event / cap revoke event / boot event 등) |

본 코드 표는 본 마일스톤 종료 시점 `0..=6 used + 7..=255 v2 예약` 잠금 — `06-CONTEXT.md` L68 의 stale 문구 `5..=255 v2 예약` 은 Phase 5.1 도입 *이전* 작성되었으며 본 plan (06-08 Task 2) 가 `7..=255 v2 예약` 으로 정정한다 (Open Question Q1 in-plan 해결).

### Pitfall 5 — `BusInstance::Network` arm `NotImplemented` vs `AttestFailed` 의미 혼동

본 마일스톤은 `BusInstance::Network` arm body 가 `BusError::NotImplemented` stub 만 — 실 TLS 스택은 v2 HW-04 위임 (CONTEXT.md D-07 함의). 본 stub 의 운영자 해석 가이드는 본 docs 가 *유일 방어* (T-06-10 mitigation).

**시나리오:**

1. tls-external 빌드의 정당한 호출자가 `NETWORK_ATTACH` cap 보유 + 정당한 `attest_payload` 로 `BusKind::Network` attach 시도.
2. `handle_attach` 의 BusKind::Network arm 도달 — cap 검증 통과 + payload 통과.
3. `BusInstance::new(BusKind::Network)` 생성 후 `open(init)` 호출 — `BusInstance::Network` arm body 가 `Err(BusError::NotImplemented)` 반환.
4. `handle_attach` 가 본 `BusError::NotImplemented` 를 `HsmCapError::Internal` 로 collapse → `SyscallError::Internal.as_rax() = -6` 반환 (Phase 1 Pitfall 7 variant 노출 최소화 일관).

**의미 분리** — 운영자가 다음 3 케이스를 명확히 구분해야 한다.

| 시나리오 | RAX | AUDIT_RING 기록 | 의미 |
|---------|-----|----------------|------|
| 실 attach 성공 | `0` | `(slot=N, result=0, bus_kind=BusKind octet)` | Phase 5 정상 경로 |
| 실 `AttestFailed` | `-4` (Denied) | `(slot=0xFF, result=1, bus_kind=BusKind octet)` | `verify_attest` 실패 — `mldsa::Error` collapse |
| `NotImplemented` stub | `-6` (Internal) | (audit 미기록) | `BusInstance::Network` arm 의 v2 위임 — 실 TLS 스택 부재. 본 마일스톤에서는 정당한 호출자도 본 상태 도달 |

**핵심 분리 기준:**

- `RAX = -4` + audit `(slot=0xFF, result=1)` → 실 `AttestFailed` (mldsa 검증 실패) — 운영자는 attestation 자료 자체를 의심.
- `RAX = -6` + audit 미기록 → `NotImplemented` stub — 운영자는 본 마일스톤이 v1 임을 인식하고 false alarm 분류 X. v2 HW-04 의 실 TLS 구현 후 본 상태 해소.

본 분리가 docs 없이 코드 본문만으로 명확하지 않은 이유는 `handle_attach` 의 collapse 가 Phase 1 Pitfall 7 (variant 노출 최소화) 정신을 따라 `BusError` 의 8 variant 를 `SyscallError` 3 variant 로 단방향 압축하기 때문이다. 운영자는 본 docs 의 §5 Pitfall 5 가 *유일한* 의미 분리 자료임을 인지해야 한다 (T-06-10 mitigation).

## 6. Open Question Q1 결정 — CONTEXT.md L68 stale 문구 정정

본 절은 `.planning/phases/06-air-gap-dual-enforcement/06-RESEARCH.md` §Open Questions Q1 의 in-plan 결정 잠금 자료이다.

**문제:** `06-CONTEXT.md` L68 의 "`result: u8` 의 `5..=255` 는 v2 phase 7+ 예약" 문구는 Phase 5.1 도입 *이전* 작성되어 stale 이다. Phase 5.1 D-03 가 `5 = WireReattestOk` / `6 = WireReattestFail` 을 이미 사용 중 (`05.1-PHASE-SUMMARY.md` L150 잠금) 이며, Phase 6 D-04 가 `2 / 3 / 4` 추가로 본 마일스톤 종료 시점 코드 `0..=6` 사용 + `7..=255` 가 진짜 v2 예약이다.

**결정 (Open Question Q1 in-plan 해소):** 본 docs (`docs/AIR-GAP.md`) 가 통합 코드 표 (§5) 의 *정정된 진리값 자료* 이다. `0..=6 used + 7..=255 v2 예약` 이 본 마일스톤 종료 시점 최종 잠금. `06-CONTEXT.md` L68 도 본 plan (06-08 Task 2) 가 동일 정정 — 양 문서 동시 보정.

**왜 양 문서 정정인가:** docs/AIR-GAP.md 는 Ring 3 호출자 ABI 진리값 자료, `06-CONTEXT.md` 는 본 마일스톤 planning 자료. 두 자료 모두 v2 예약 범위를 정확히 명시해야 후속 phase planner 가 `EnrollEvent.result` 의 다음 사용 가능 코드를 `7` 부터 시작할 수 있다.

**결정 단언 인용:**

- `# Decision: D-04` — `EnrollEvent.result` 4 코드 추가 (`2=NetworkDenied` 콜럐스 / `3=NetworkCapTaken` / `4=GapSelfCheckFail`) + 5 NetworkDenied 콜럐스 카테고리 (§3) — CONTEXT.md D-04 본문 잠금
- `# Decision: D-05` — `sys_hsm_status` ABI (rdi=out_ptr / rsi=out_len / rdx=cap_token / 456 옥텟 응답 / 호출 AUDIT 미기록) — CONTEXT.md D-05 본문 잠금
- `# Decision: D-06` — `sys_audit_cap_take` ABI + `bus_kind` octet 도용 (Pitfall 3 해석) — CONTEXT.md D-06 본문 잠금
- `# Decision (Open Q1 in-plan)` — CONTEXT.md L68 "5..=255" → "7..=255" 정정. 본 docs §5 표 가 통합 진리값 자료
- `# Decision: T-06-10 mitigation` — Pitfall 5 `NotImplemented` vs `AttestFailed` 의미 분리 (§5) — 운영자가 RAX=-6 (Internal/NotImplemented) vs RAX=-4 (Denied/AttestFailed) 의 audit 기록 유무로 분리 학습. 본 docs 가 유일 방어 자료
