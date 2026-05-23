---
phase: 07
plan: 01
requirements: [AUDIT-01, AUDIT-04]
generated_at_commit: 39d4c72
generated_at: 2026-05-23
scope: src/*.rs (30 파일, 14,583 lines)
---

# Phase 7 Integration Gap Audit — 4-Bucket Triage Report

본 보고서는 v1.0 Multi-HSM Connector 마일스톤 종료 직후 13K LOC 본체에 산재한 placeholder / dead_code / 와일드카드 흡수 site 를 전수 grep 으로 enumerate 한 후, `07-CONTEXT.md` §decisions 의 D-01..D-04 결정 규칙을 1:1 적용하여 G1/G2/G3/G4 4-bucket 으로 분류한 triaged 보고서이다. Pitfall 13 ("flat grep dump → triaged report") 회피가 본 보고서의 핵심 가치이며, 모든 triaged 항목은 raw evidence 행 id (E-NN) 를 인용하고, 모든 verdict 는 D-01..D-04 중 어느 규칙이 적용됐는지 명시한다.

## Scope

**Audit input:** `src/*.rs` 30 개 파일 14,583 lines (`find src -name '*.rs' -exec wc -l \; | tail -1` 기준).

**Out of scope:**
- `tests/` — 본 페이즈는 본체 audit 만, 테스트 코드의 placeholder 는 별도 작업
- `crates/iso-user-*/` — lumen reference client (Ring 3 user-space) 는 커널 본체 audit 대상 외
- `scripts/` — 빌드 / CI 스크립트의 placeholder 는 패턴이 다름
- `build.rs` — 빌드 시점 코드, 런타임 dispatch 표면 부재
- `cfg(test)` gated 블록 — 본 페이즈는 production path 본문 audit

**Enumeration patterns** (`<interfaces>` 명세 5종):

```
grep -rn 'unimplemented!\|todo!\|panic!.*not implemented' src --include='*.rs'
grep -rn '#\[cfg(any())\]' src --include='*.rs'
grep -rn '#\[allow(dead_code)\]' src --include='*.rs'
grep -rn 'Err(BusError::NotImplemented)\|BusError::NotImplemented' src --include='*.rs'
grep -n '_ => Err(BusError::NotImplemented)' src/bus.rs
```

**Additional patterns observed during enumeration:**
- `panic!()` in `src/air_gap.rs:178/191` — Phase 6 D-07 fail-stop 의도, "not implemented" 문구는 없지만 CONTEXT.md L92 가 명시적으로 audit 대상으로 지정 (BusError::NotImplemented 변종이 아니라 air-gap 자체 fail-stop)

## Bucket Definitions

D-01..D-04 정본은 `.planning/phases/07-integration-gap-audit/07-CONTEXT.md` §decisions 에 있으며, 본 보고서는 future reader 를 위해 verbatim 으로 재게재한다.

### D-01: "문서화된 future-purpose stub" → G2 (architectural placeholder)

- 결정 규칙: "현재 REQ 또는 ROADMAP / REQUIREMENTS Out-of-Scope 에 목적이 명시된 stub" → G2.
- 적용 예 (이미 확정): `src/bus.rs` 의 `BusVariant::Usb / Spi / Serial / SmartCard` 4 zero-sized stub variant — `#[non_exhaustive]` enum + REQUIREMENTS.md "Out of Scope" 의 "BUS / HSM trait stub 5종(USB/SPI/Serial/SmartCard/Network)도 v1.0 정의 그대로" 명시 + v2/v2.1 HW 드라이버 진입 슬롯 → G2 확정.
- 적용 예 (보류 — D-04 와 함께 해석): `BusVariant::Network` 는 Phase 6 `tls-external` cfg-gate 로 closed 빌드에서 심볼 부재, tls-external 빌드에서는 dispatch entry 본문 stub 가능. 두 프로필을 별개 audit entry 로 기록 — closed 프로필에서는 (심볼 부재로) audit 대상 미진입, tls-external 프로필에서는 D-04 narrow 정의로 G3 (전용 dispatch entry + 본문 stub). Claude's Discretion 으로 audit-report.md 의 정확한 표기 형식 결정.
- 부정 사례: 문서화된 future-purpose 매핑이 없으면 G2 자격 없음 (G4 또는 G3).

### D-02: `#[allow(dead_code)]` 7+ 사이트 — item-by-item triage + REQ 교차검증

- 자동 일괄 분류 거부. Audit 수행 중 각 dead_code 항목을 수동으로 트리아지:
  1. 주변 주석 / docstring 에서 REQ-id 인용 (예: `// HAL-04 lossless move 대비`) 여부 확인
  2. ROADMAP / REQUIREMENTS Out-of-Scope 매핑 가능성 조사 (D-01 규칙 적용 가능 여부)
  3. 호출 사이트 + 모듈 컨텍스트로 의도 추론 (예: `tls/handshake.rs:77` 의 dead_code 는 Phase 8 ENTR 또는 Phase 10 ARM TLS 표면 진입용 hook 일 가능성)
- 증거 충분 → G2 (D-01 규칙 만족). 그 외 → G4.
- 적용 대상 (현재 발견): `src/idt.rs:233/247/265`, `src/keystore.rs:38`, `src/vga.rs:20`, `src/main.rs:50/51/53`, `src/hsm_registry.rs:55`, `src/tls/handshake.rs:77` — 총 7+ 사이트. Audit 단계에서 추가 발견 가능.
- 부담 평가: 항목 수 < 20 이므로 부담 수용 가능. annotation 일괄 마이그레이션 (G2/G4 sibling 주석 부착 강제) 은 채택하지 않음 — 의도가 명시적이지 않은 항목까지 작성자가 추정 주석 부착하는 위양성 위험.

### D-03: Bucket 우선순위 (multi-match 해소) — G1 (키보드 우선) > G3 > G2 > G4

- G1 의 정의: "REQ 부재 알려진 결함" — 현 13K LOC 에 있어야 하는데 부재한 표면. 보안/정합성 결함 (예: BLAKE3 64-byte output buffer truncation 방탄 부재, syscall handler 누락, dispatch table 엔트리 부재). v2.0 REQ 가 아직 구현하지 않은 것은 G1 아님 (Phase 8~12 가 정상 장착 예정).
- G1 은 키보드 우선순위 — audit 수행 중 G1 후보가 발견되면 다른 bucket 자격 평가 이전에 G1 으로 즉시 장착 + 보안 검토 trigger. G1 은 본 페이즈의 가장 중요한 산출물 (양적으로는 적을 가능성 높음 — 양이 많으면 v1.0 완료성에 의문).
- G3 > G2 > G4: 한 항목이 G3 자격 + G2 자격 모두 만족 시 G3 로 분류 (dispatch-reachable 이라는 보안 표면 사실이 architectural intent 보다 우선 — Pitfall 13 의 "flat grep dump → triaged report" 정신 일관).
- G1 의 예상 카운트: 0~소수 (v1.0 종료 직후이므로 알려진 결함이 다수 있다면 v1.0 종료 자체 의문). audit-report.md 의 G1 섹션이 비어 있더라도 명시적 "G1: 적용 항목 없음" 포맷 유지.

### D-04: G3 의 정확한 작용 범위 — Narrow (전용 dispatch entry + 본문 unimplemented 만)

- G3 = dispatch table / match arm 에 **이름별로 명시 등록**되어 있고 해당 entry 의 본문이 `unimplemented!() / todo!() / panic!("not implemented") / Err(NotImplemented)` 인 경우만 해당.
- 와일드카드 `_ => Err(BusError::NotImplemented)` 형태의 흡수는 G3 아님 — 와일드카드는 dispatch table 의 entry 가 아니라 fallback. 결과: `BusVariant::Usb/Spi/Serial/SmartCard` 는 와일드카드 흡수로 G3 자격 없음 → D-01 의 G2 분류 유지.
- D-01 + D-03 + D-04 의 조합 결과: BusVariant 4 stub 은 (a) 와일드카드 흡수로 G3 아님 (D-04) (b) 문서화된 future-purpose (D-01) → G2 (D-03 의 G3 > G2 우선순위는 G3 자격이 없으므로 영향 없음).
- G3 의 표면 범위 (어떤 dispatch table 이 G3 후보 인가) 는 Claude's Discretion 으로 plan-phase 에서 추가 결정 — 후보: (i) `src/syscall.rs` 의 `SyscallNum` match arm (ii) lumen wire 의 `WireCmd` opcode dispatch (iii) `src/ipc.rs` 의 IPC channel dispatch (iv) `src/idt.rs` 의 IDT handler vector. 다중 dispatch 축의 교집합 / 합집합 정의는 audit 수행 중 발견 데이터로 보강.

## G1 — Genuinely Missing (REQ 부재 알려진 결함)

**G1 키보드 우선순위 enforcement (D-03)** — Task 2 가 16 raw evidence rows 전체에 대해 G1 자격을 G2/G3/G4 평가 *이전* 에 우선 평가하였다. G1 정의 "REQ 부재 알려진 결함" — 현 13K LOC 에 있어야 하는데 부재한 표면 (보안/정합성 결함, BLAKE3 64-byte output truncation 방탄 부재, syscall handler 누락, dispatch table 엔트리 부재) 를 기준으로 각 site 를 검토하였다:

- E-01..E-03 (idt PIC EOI/IRQ helpers) — IRQ handling 은 v1.0 + v2.0 REQ 모두 없음 (PIC 마스크 0xFF 전체 차단, polling-based 커널). 보안 결함 없음.
- E-04 (keystore TRUST_ROOT_PSK_SLOT) — 슬롯 예약, 보안 결함 없음.
- E-05 (vga Color) — 색상 enum 완전성, cosmetic.
- E-06/E-07 (main USER_*_ELF) — Phase E hook 문서화됨.
- E-08 (hsm_registry NETWORK_ATTACH right bit) — Phase 6 reserved, 보안 결함 없음.
- E-09 (tls parse_handshake_header) — write_handshake_header 와 페어 hook, 활성 reader 부재이나 보안 표면 누락 아님 (모든 TLS handshake parsing 은 v1.0 별도 경로).
- E-10..E-14 (bus.rs 5 wildcards) — documented future-purpose (REQUIREMENTS Out of Scope).
- E-15/E-16 (air_gap panic) — Phase 6 D-07 fail-stop *의도된 동작*, missing defense 가 아님 (오히려 *추가된* defense).

**Verdict**: 0 G1 sites.

**G1: 적용 항목 없음 (v1.0 종료 직후, 알려진 결함 부재 = v1.0 완료성 확인)**

(만약 후속 Plan 02 의 dispatch-reachability 분석이 새로운 G1 후보를 발견하면 본 보고서가 amended — `Authority Exercised` 또는 별도 G1 supplement section 으로 표기.)

## G2 — Architectural Placeholder

D-01 + (D-02 가 D-01 규칙 만족) 적용 결과. 모든 entry 의 evidence 컬럼이 REQ-id / OoS 행 / docstring 인용을 포함.

| E-NN | file | lines | pattern | bucket | rule | evidence |
|------|------|-------|---------|--------|------|----------|
| E-04 | src/keystore.rs | 38 | `#[allow(dead_code)] pub const TRUST_ROOT_PSK_SLOT: u8 = 0xFE` | G2 | D-02 → D-01 | docstring L36-37 "Phase 5 D-Discretion 신뢰 루트 PSK slot 네임스페이스 예약 / RESEARCH §14.2 Option (iii) stub 본 const 는 본 페이즈에서 사용되지 않으며 향후 keystore provisioning 의 자리만 잡음" — documented future-purpose for keystore provisioning |
| E-06 | src/main.rs | 51 | `#[allow(dead_code)] const USER_HELLO_ELF` | G2 | D-02 → D-01 | docstring L48-50 "Phase E 통합 단계에서 _kernel_start 가 spawn_elf + enter_ring3 를 호출하면 dead_code 경고가 자동으로 해소됨. 그 전까지 일시 허용" — documented Phase E hook |
| E-07 | src/main.rs | 53 | `#[allow(dead_code)] const USER_LUMEN_ELF` | G2 | D-02 → D-01 | docstring L48-50 "Phase E hook" 와 동일 cluster (USER_HELLO_ELF + USER_LUMEN_ELF 동일 docstring) |
| E-08 | src/hsm_registry.rs | 55 | `#[allow(dead_code)] pub const NETWORK_ATTACH: Self = Self(1 << 5)` | G2 | D-02 → D-01 | line comment "Phase 6 reserved" — Phase 6 가 NETWORK_CAP_STATE FSM (air_gap.rs:71/75) + NETWORK_ATTACH_CAP BSS singleton 의 대안 mechanism 을 채택했으나, HsmRights bitmask 슬롯 자체는 v2/v2.1 향후 right-bit 기반 fallback / cross-check 용도로 보존. 명시적 "reserved" 주석 = documented future-purpose |
| E-10 | src/bus.rs | 856 | `_ => Err(BusError::NotImplemented)` (BusInstance::open 와일드카드 — Usb/Spi/Serial/SmartCard/Network 흡수) | G2 | D-01 + D-04 | REQUIREMENTS.md §Out of Scope: "신규 암호 알고리즘 / 신규 HSM 드라이버 \| `elib-k0-nt` 기존 표면만. BUS / HSM trait stub 5종(USB/SPI/Serial/SmartCard/Network)도 v1.0 정의 그대로" + D-04: 와일드카드 흡수는 G3 아님 |
| E-11 | src/bus.rs | 865 | `_ => Err(BusError::NotImplemented)` (BusInstance::close 와일드카드) | G2 | D-01 + D-04 | REQUIREMENTS.md §Out of Scope "BUS / HSM trait stub 5종" + D-04 와일드카드 G3 배제 |
| E-12 | src/bus.rs | 874 | `_ => Err(BusError::NotImplemented)` (BusInstance::read 와일드카드) | G2 | D-01 + D-04 | REQUIREMENTS.md §Out of Scope "BUS / HSM trait stub 5종" + D-04 와일드카드 G3 배제 |
| E-13 | src/bus.rs | 883 | `_ => Err(BusError::NotImplemented)` (BusInstance::write 와일드카드) | G2 | D-01 + D-04 | REQUIREMENTS.md §Out of Scope "BUS / HSM trait stub 5종" + D-04 와일드카드 G3 배제 |
| E-14 | src/bus.rs | 892 | `_ => Err(BusError::NotImplemented)` (BusInstance::poll 와일드카드) | G2 | D-01 + D-04 | REQUIREMENTS.md §Out of Scope "BUS / HSM trait stub 5종" + D-04 와일드카드 G3 배제 |
| E-15 | src/air_gap.rs | 178 | `panic!("gap_self_check NETWORK_ATTACH_CAP not initialized in tls-external build")` | G2 | D-01 (Phase 6 D-07) | `.planning/phases/06-air-gap-dual-enforcement/06-CONTEXT.md` D-07 "2 층 self-check (Layer 1 `scripts/check-no-network.sh` + Layer 2 boot-time `gap_self_check()`)" — fail-stop 가 의도된 동작 (placeholder 아님). 본 line 자체가 Layer 2-a sanity check 의 정상 실행 경로 |
| E-16 | src/air_gap.rs | 191 | `panic!("gap_self_check AUDIT_READ_CAP not initialized")` | G2 | D-01 (Phase 6 D-07) | 06-CONTEXT.md D-07 Layer 2-c sanity check (양 프로필 공통 AUDIT_READ_CAP 검증). fail-stop 의도 동작 — placeholder 아님 |

**G2 cluster note (main.rs:50/51/53)** — Warning 10 resolution: main.rs:50 은 L48-50 docstring 의 닫는 줄 (Phase E hook 명시 텍스트). grep 은 #[allow(dead_code)] attribute line (51, 53) 만 캡처하므로 본 보고서는 L50 을 별도 row 로 분리하지 않고 E-06/E-07 의 evidence 컬럼에서 L48-50 docstring 으로 인용 — 동일 G2 cluster 의 동일 justification source.

## G3 — Dispatch-Reachable (Narrow per D-04)

D-04 narrow 정의 적용 — 이름별 명시 dispatch entry + stub-equivalent body. v1.0 종료 시점 본체에는 named dispatch entry + stub body 패턴이 BusKind::Network (tls-external profile) 1 건만 식별. 모든 wildcard `_ => Err(BusError::NotImplemented)` 는 D-04 explicit 배제 → G2 로 분류됨 (위 G2 섹션 E-10..E-14).

**Plan 02 의 dispatch-reachability 분석이 syscall.rs SyscallNum / WireCmd / IPC handler / IDT vector 의 4 dispatch 축을 전수 매핑하면 추가 G3 후보가 발견될 수 있다 — 본 Task 2 verdict 는 visible-proximity 기반 preliminary 이며 Plan 02 가 G2/G4 entry 를 G3 로 upgrade 할 수 있다.**

| E-NN | file | lines | pattern | bucket | rule | evidence | profile |
|------|------|-------|---------|--------|------|----------|---------|
| E-17 | src/bus.rs | 845 | `BusKind::Network => Self::Network` (BusInstance::new 명시 named arm, Self::Network zero-sized variant 의 dispatch method bodies (open/close/read/write/poll) 는 wildcard `_ => Err(BusError::NotImplemented)` 로 흡수됨) | G3 | D-04 narrow (named entry + stub body via wildcard absorption reachability) | REQUIREMENTS.md §Out of Scope "BUS / HSM trait stub 5종 (USB/SPI/Serial/SmartCard/Network) v1.0 정의 그대로" + CONTEXT.md D-01 "tls-external 빌드에서는 dispatch entry 본문 stub 가능 ... 두 프로필을 별개 audit entry 로 기록" + CONTEXT.md L55-56 "단일 row entry + 프로필 컬럼" Claude's Discretion | tls-external |

**Closed profile footnote (BusKind::Network — Plan 03 air-gap re-proof 대상):**

`BusKind::Network` 변종 자체는 `src/bus.rs:341` 의 enum 정의 + L845 의 named arm 양쪽에 unconditionally 등재 (`#[cfg(feature = "tls-external")]` 게이트 없음). closed 빌드에서도 enum variant 심볼은 존재. closed-vs-tls-external 분기는 (a) `src/hsm_registry.rs:557-587` 의 `handle_attach` Network arm 의 `#[cfg]` split (closed 빌드는 즉시 `SyscallError::Denied` collapse) (b) `src/air_gap.rs:172-185` 의 `gap_self_check` Layer 2-a / 2-b 분기에서 일어남. **closed 프로필에서는 BusKind::Network 가 dispatch entry 까지 도달은 가능하나 (handle_attach 의 closed arm 이 즉시 Denied), 본 closed-path Denied 도달 자체는 보안적 표면이 아니다 — Plan 03 의 air-gap dual-gate zero-bypass proof 가 closed 산출 바이너리의 nm/objdump 로 `BusKind::Network` 구현체 심볼 부재 + `NETWORK_ATTACH` capability 발급 경로 부재를 재증명할 때, 본 E-17 entry 의 tls-external G3 verdict 와는 별도로 closed proof 결과를 audit-report.md 에 amendment 또는 Plan 03 산출물에 기록.** 본 footnote 는 dual-treatment 의 closed 측을 명시한다.

## G4 — Truly Dead

D-02 default — `#[allow(dead_code)]` 사이트 중 D-01 (REQ / OoS 매핑) + 모듈 컨텍스트 추론 모두 fail 한 항목.

| E-NN | file | lines | pattern | bucket | rule | evidence |
|------|------|-------|---------|--------|------|----------|
| E-01 | src/idt.rs | 233 | `#[allow(dead_code)] pub unsafe fn pic_eoi_master` (Master PIC EOI signal helper) | G4 | D-02 (no REQ/OoS mapping) | v1.0 ENROLL/MUX/CAP/CHAN/BUS/WIRE/ATTEST/GAP 8 카테고리 + v2.0 AUDIT/ENTR/HAL/ARM/LIVE/MTRX 6 카테고리 모두 IRQ 직접 핸들러 등록 REQ 부재. PIC 마스크 0xFF 전체 차단 (idt.rs:222-224, polling-based 커널). 함수 본문 정상 작동 가능 (PIC1_CMD/PIC_EOI OUT 명령) 이나 호출자 0. **Plan 02 dispatch-reachability 가 IRQ handler vector 축에서 추가 evidence 발견 시 upgrade 가능** |
| E-02 | src/idt.rs | 247 | `#[allow(dead_code)] pub unsafe fn pic_eoi_slave` (Master + Slave PIC EOI helper) | G4 | D-02 (no REQ/OoS mapping) | E-01 와 동일 PIC scaffolding cluster. IRQ 8..15 handler 부재. **Plan 02 가 추가 evidence 발견 시 upgrade 가능** |
| E-03 | src/idt.rs | 265 | `#[allow(dead_code)] pub unsafe fn enable_irq` (IRQ 라인 마스크 해제 helper) | G4 | D-02 (no REQ/OoS mapping) | E-01/E-02 와 동일 PIC scaffolding cluster. 어느 IRQ 도 enable 되지 않음 (kernel_main 에 enable_irq 호출 0). **Plan 02 upgrade 가능** |
| E-05 | src/vga.rs | 20 | `#[allow(dead_code)] pub enum Color` (16-색 BIOS palette) | G4 | D-02 (no REQ/OoS mapping) | boot marker / diagnostic line 출력은 Green / Red / Blue 3 색만 사용 (variant Black/Brown/LightGray/DarkGray/LightRed/Magenta/Yellow/White 7 종 + remaining 미사용). 16-색 palette 완전성 보존이 design intent 인 정황은 있으나 REQ / OoS 명시적 mapping 부재. cosmetic-only. **단순 제거 가능 — 또는 v2.0 도중 framebuffer 기반 콘솔 도입 시 재사용 가능성** |
| E-09 | src/tls/handshake.rs | 77 | `#[allow(dead_code)] fn parse_handshake_header` (write_handshake_header 의 reader pair) | G4 | D-02 (borderline — Task 3 reviewer may upgrade to G2) | write_handshake_header (L63) 와 짝을 이루는 reader. 활성 호출자 0 (in-kernel handshake 는 별도 `tls::handshake::run_*` 경로). Phase 8 ENTR (entropy) 와 Phase 10 ARM (aarch64 port wire-compat) 모두 본 함수 직접 의존하지 않음. **Borderline verdict — write/parse pair 완전성 design intent 가 있다면 G2 upgrade 가능. Task 3 human review 가 최종 결정** |

## Raw Evidence Appendix

## Raw Evidence Appendix

본 부록은 Task 1 의 enumeration grep 5종 + 추가 발견 패턴 (air_gap.rs panic!) 의 전체 원시 hit 을 canonical Markdown table row 형식 (Warning 9 unified schema) 으로 기록한다. Sequential id `E-01..E-NN` — Task 2 가 bucket / rule / evidence 컬럼을 in-place 채운 후 `## Raw Evidence Appendix` 의 `triage_status` 컬럼에 verdict 결과를 사후 표기한다.

**Enumeration grep 결과:**

- `unimplemented! / todo! / panic!.*not implemented`: 0 hits (v1.0 종료 시점 본체에 이 3 패턴 부재 — v1.0 완료성 일차 지표)
- `#[cfg(any())]`: 0 hits (본체에 이 패턴 부재)
- `#[allow(dead_code)]`: 9 hits (idt.rs ×3, keystore.rs ×1, vga.rs ×1, main.rs ×2, hsm_registry.rs ×1, tls/handshake.rs ×1)
- `Err(BusError::NotImplemented)` (와일드카드 흡수): 5 hits (bus.rs:856/865/874/883/892)
- `BusError::NotImplemented` 변종 정의: 1 hit (bus.rs:351 — variant 정의 자체; 5 wildcard 흡수가 사용처. meta-note 만 기록, 별도 evidence row 생성 안 함)
- `air_gap.rs` panic! 2 사이트 (CONTEXT.md L92 가 명시적으로 audit 대상으로 지정 — Phase 6 D-07 fail-stop 의도): 2 hits

**총 raw evidence rows: 17** (Task 1 = 16 + Task 2 synthetic E-17 for BusKind::Network tls-external G3 dispatch entry; ≥ 15 acceptance threshold 충족).

Task 2 가 본 appendix 의 bucket / rule / evidence 컬럼을 in-place 갱신하고 우측에 `triage_status` 컬럼을 append 하였다. 모든 rows 는 `^\| E-[0-9]+` canonical regex 충족.

| E-NN | file | lines | pattern | bucket | rule | evidence | triage_status |
|------|------|-------|---------|--------|------|----------|---------------|
| E-01 | src/idt.rs | 233 | `#[allow(dead_code)]` on `pub unsafe fn pic_eoi_master` (Master PIC EOI hook) | G4 | D-02 | no REQ/OoS mapping; PIC 마스크 0xFF 전체 차단; polling-based 커널 | triaged → G4 |
| E-02 | src/idt.rs | 247 | `#[allow(dead_code)]` on `pub unsafe fn pic_eoi_slave` (Slave PIC EOI hook) | G4 | D-02 | E-01 cluster (IRQ 8..15 handler 부재) | triaged → G4 |
| E-03 | src/idt.rs | 265 | `#[allow(dead_code)]` on `pub unsafe fn enable_irq` (IRQ 마스크 해제 helper) | G4 | D-02 | E-01 cluster (enable_irq 호출 0) | triaged → G4 |
| E-04 | src/keystore.rs | 38 | `#[allow(dead_code)] pub const TRUST_ROOT_PSK_SLOT: u8 = 0xFE` | G2 | D-02 → D-01 | docstring L36-37 "Phase 5 D-Discretion 신뢰 루트 PSK slot 네임스페이스 예약 / RESEARCH §14.2 Option (iii) stub" | triaged → G2 |
| E-05 | src/vga.rs | 20 | `#[allow(dead_code)]` on `pub enum Color` (16-color BIOS palette) | G4 | D-02 | Green/Red/Blue 3 색만 사용 (boot marker); 나머지 cosmetic; REQ/OoS 매핑 부재 | triaged → G4 |
| E-06 | src/main.rs | 51 | `#[allow(dead_code)] const USER_HELLO_ELF` | G2 | D-02 → D-01 | docstring L48-50 "Phase E 통합 단계에서 _kernel_start 가 spawn_elf + enter_ring3 를 호출하면 dead_code 자동 해소" | triaged → G2 |
| E-07 | src/main.rs | 53 | `#[allow(dead_code)] const USER_LUMEN_ELF` | G2 | D-02 → D-01 | L48-50 docstring 동일 Phase E hook cluster (E-06 와 동일 justification) | triaged → G2 |
| E-08 | src/hsm_registry.rs | 55 | `#[allow(dead_code)] pub const NETWORK_ATTACH: Self = Self(1 << 5)` (Phase 6 reserved right bit) | G2 | D-02 → D-01 | line comment "Phase 6 reserved" — Phase 6 가 NETWORK_CAP_STATE FSM 대안 mechanism 채택했으나 right-bit 슬롯은 v2.x reservation 으로 보존 | triaged → G2 |
| E-09 | src/tls/handshake.rs | 77 | `#[allow(dead_code)] fn parse_handshake_header` | G4 | D-02 (borderline) | write_handshake_header 의 reader pair, 활성 호출자 0, Phase 8/10 REQ 매핑 부재 — borderline G4. **Task 3 reviewer 가 G2 upgrade 여부 결정** | triaged → G4 (Task 3 review pending) |
| E-10 | src/bus.rs | 856 | `_ => Err(BusError::NotImplemented)` (BusInstance::open 와일드카드 — Usb/Spi/Serial/SmartCard/Network 흡수) | G2 | D-01 + D-04 | REQUIREMENTS.md §Out of Scope "BUS/HSM trait stub 5종 v1.0 정의 그대로" + D-04 와일드카드 G3 배제 | triaged → G2 |
| E-11 | src/bus.rs | 865 | `_ => Err(BusError::NotImplemented)` (BusInstance::close 와일드카드) | G2 | D-01 + D-04 | E-10 와 동일 5-method cluster | triaged → G2 |
| E-12 | src/bus.rs | 874 | `_ => Err(BusError::NotImplemented)` (BusInstance::read 와일드카드) | G2 | D-01 + D-04 | E-10 와 동일 5-method cluster | triaged → G2 |
| E-13 | src/bus.rs | 883 | `_ => Err(BusError::NotImplemented)` (BusInstance::write 와일드카드) | G2 | D-01 + D-04 | E-10 와 동일 5-method cluster | triaged → G2 |
| E-14 | src/bus.rs | 892 | `_ => Err(BusError::NotImplemented)` (BusInstance::poll 와일드카드) | G2 | D-01 + D-04 | E-10 와 동일 5-method cluster | triaged → G2 |
| E-15 | src/air_gap.rs | 178 | `panic!("gap_self_check NETWORK_ATTACH_CAP not initialized in tls-external build")` | G2 | D-01 (Phase 6 D-07) | 06-CONTEXT.md D-07 Layer 2-a sanity check; fail-stop 의도 동작 (placeholder 아님) | triaged → G2 |
| E-16 | src/air_gap.rs | 191 | `panic!("gap_self_check AUDIT_READ_CAP not initialized")` | G2 | D-01 (Phase 6 D-07) | 06-CONTEXT.md D-07 Layer 2-c sanity check (양 프로필 공통 AUDIT_READ_CAP 검증) | triaged → G2 |
| E-17 | src/bus.rs | 845 | `BusKind::Network => Self::Network` named arm + Self::Network zero-sized variant dispatch bodies via wildcard absorption (tls-external profile) | G3 | D-04 narrow | named entry + stub body via wildcard absorption reachability; CONTEXT.md D-01 "tls-external 빌드에서는 dispatch entry 본문 stub 가능" | triaged → G3 (tls-external profile; closed profile = Plan 03 re-proof, see G3 section footnote) |

**Meta-notes** (별도 evidence row 미생성):

- **bus.rs:351** `BusError::NotImplemented` 변종 정의 자체는 typed-error stub 이다. CONTEXT.md §Claude's Discretion 7번째 항목이 "BusError::NotImplemented 같은 typed-error stub 도 AUDIT-02 패턴 확장 대상 포함 여부" 를 plan-phase 결정 사항으로 두었고, 본 plan 은 5 wildcard 흡수 *사용처* 만 evidence row 로 추적하기로 결정. 변종 정의 자체는 D-04 의 "wildcard fallback" 표면을 받쳐주는 enum variant 일 뿐 별도 placeholder 가 아니다.
- **BusKind::Network (bus.rs:341, 845)** — 본 변종은 enum `BusKind` 와 `BusInstance::new()` match arm 양쪽에 unconditionally 등재되어 있다 (`#[cfg(feature = "tls-external")]` 게이트 없음). CONTEXT.md D-01 의 "closed 프로필에서는 (심볼 부재로) audit 대상 미진입" 표현은 실제 코드와 부분 불일치 — `BusKind::Network` enum 변종 자체는 closed 빌드에도 존재. closed-vs-tls-external 분기는 hsm_registry.rs:557-587 의 `handle_attach` Network arm 의 `#[cfg]` split (closed 빌드는 즉시 Denied collapse) + air_gap.rs:172-185 의 gap_self_check Layer 2-a/2-b 분기에 있음. Task 2 의 BusKind::Network 처리는 본 사실을 반영하여 단일 entry + 프로필 컬럼 형식 (Claude's Discretion CONTEXT.md L55-56) + 별도 footnote 로 표기.

## Phase 8~12 Re-adjustment Authority

본 section 은 ROADMAP §Phase 7 SC #4 + REQUIREMENTS.md AUDIT-04 의 1회 재조정 권한을 self-contained 절차로 구현한다. 후속 Phase 8~12 가 본 권한을 행사하려면 본 section 만 참조하면 충분하다.

### Trigger Conditions

다음 중 하나 이상이 충족되면 본 권한 행사 사유로 인정된다:

1. **G1 카운트 > 0** — 본 audit 의 `## G1` section 이 비어 있지 않다면 (REQ 부재 알려진 보안/정합성 결함 발견) Phase 8 진입 이전 G1-closure 미니 phase (예: `Phase 7.1: G1 Closure`) 삽입을 우선 검토. (CONTEXT.md §deferred "Phase 8 ENTR 진입 전 본체 사전 정비" 항목 매핑.)
2. **Phase 9 HAL lossless move 대상 9 파일 중 G4 판정 항목 발견** — Phase 9 SC #2 의 9 파일 (`src/{cpu,mmu,idt,boot,boot_stub,tss,vga,memory_map,syscall}.rs`) 중 본 audit 가 G4 (truly dead) 로 판정한 파일이 있다면 lossless move 의 9 파일 목록 축소 가능. (CONTEXT.md §deferred "Phase 9 HAL 의 lossless move 대상 파일 목록 재검토" 항목 매핑.)
3. **Phase 8~12 의 어느 REQ 가 본 audit 의 G2 architectural placeholder 와 직접 충돌** — 예: Phase 10 ARM 의 `secure_zero` HAL 추출이 기존 dead_code site 와 의미 충돌, Phase 8 ENTR 의 entropy 소스 활성화가 본 audit 의 G2 entropy-adjacent stub 와 정합 불일치, 등.
4. **사용자 판단** — 위 1..3 에 해당하지 않더라도 본 audit 결과를 본 후 사용자가 Phase 8~12 우선순위 / 범위 재평가가 필요하다고 판단한 경우.

### Quantitative Input

Task 2 종료 시점 bucket count 4-tuple 및 본 보고서의 정량 입력:

- **G1 = 0** (v1.0 종료 직후 알려진 결함 부재 — 자세한 narrative 는 `## G1` section)
- **G2 = 11** (architectural placeholder; D-01 + D-02→D-01 + D-01+D-04 와일드카드 흡수 cluster)
- **G3 = 1** (dispatch-reachable; D-04 narrow; E-17 BusKind::Network tls-external profile only — closed profile 은 Plan 03 air-gap re-proof 인계)
- **G4 = 5** (truly dead; D-02 conservative — E-09 borderline, Task 3 human review 결과 G4 유지 승인됨)
- **Raw evidence rows: 17** (Raw Evidence Appendix 의 ^\| E-[0-9]+ canonical regex 행 카운트)
- **Dropped rows: 17 - (0+11+1+5) = 0** (모든 raw evidence 가 정확히 하나의 bucket 으로 분류; orphan 행 부재)
- **Generated at commit: `39d4c72`** (frontmatter `generated_at_commit` 와 동일 SHA; Plan 02/03 는 본 SHA 와 자체 `git rev-parse --short HEAD` 비교로 drift 감지)

본 수치는 재조정 권한 발동 시 정량 근거로 인용된다. 예시:
- "G1 = 3 발견 → Phase 8 진입 전 G1-closure 미니 phase 7.1 삽입 제안"
- "Phase 9 HAL 9 파일 중 tss.rs 가 G4 단독 판정 → Phase 9 SC #2 의 9 파일 목록을 8 파일로 축소 제안"

### Procedure

본 권한 행사는 다음 6 step 순서를 strict 하게 따른다 (AUDIT-04 정본의 "ROADMAP.md 수정 + decision log 추가" 강화 절차):

- **Step 1** — 재조정 제안 작성. 변경 대상 Phase 번호 + 변경 내용 (순서 swap / 범위 축소 / 신규 sub-phase 삽입) + 본 보고서의 `### Quantitative Input` row 인용 + `### Trigger Conditions` 매핑. 제안서는 markdown 으로 작성하여 후속 review 가능 상태로 보존.

- **Step 2** — **사용자 합의**. 제안서 user-facing 표시 + 명시적 approve/reject. proceeding without approval 금지 — 본 권한은 단순 자동화가 아니라 사용자 협의 절차를 포함한 단방향 이벤트. 협의 채널은 GSD `/gsd:phase` CLI (제안 → 사용자 확인 → 적용) 또는 직접 대화.

- **Step 3** — 합의 시 `ROADMAP.md` 수정. 변경된 Phase 행 갱신 (Goal / Depends on / Requirements / Success Criteria 중 영향 받는 필드만 selective 수정). v2.0 마일스톤 마감일 영향 평가 — Phase 추가 / 범위 확장 시 마감 연기 여부 사용자 결정.

- **Step 4** — `STATE.md decision log` 추가. `### Decisions` 섹션에 다음 형식으로 1 entry 추가:
  ```
  [Phase 7]: AUDIT-04 행사 — Phase N 재조정 (trigger: <T#>, quantitative: G1=X G2=Y G3=Z G4=W, agreed: <YYYY-MM-DD>)
  ```
  여기서 `<T#>` 은 위 `### Trigger Conditions` 의 번호 (1..4), `<X/Y/Z/W>` 은 본 보고서의 quantitative input, `<YYYY-MM-DD>` 은 사용자 합의 일자.

- **Step 5** — `PROJECT.md Key Decisions table` 갱신 여부 판단. 재조정이 milestone scope 변경 수준 (예: 신규 Phase 삽입, 기존 Phase 폐기) 이면 Yes (Key Decisions table 에 새 row 추가). 단순 phase 내 순서 swap / 9 파일 → 8 파일 축소 수준이면 No (STATE.md decision log 만으로 충분). 사용자 판단 우선.

- **Step 6** — 본 권한 1회 소진 마킹. `.planning/audit/audit-report.md` 의 본 section 마지막 행 (`Authority Status` tracker) 을 다음 중 하나로 갱신:
  - `**Authority Status**: EXERCISED (Phase N, <YYYY-MM-DD>, see STATE.md decision log)` — 권한 행사 완료
  - `**Authority Status**: AVAILABLE (1 use remaining)` — 미행사 (초기 상태 유지)
  본 line 이 후속 phase / 후속 audit 가 권한 잔여 여부를 1초에 확인할 수 있는 single source of truth.

### Out-of-scope clarifications

본 권한이 다루지 않는 범위:

- **Phase 7 자체의 재계획** — 본 audit 가 본 audit 를 수정할 수 없음 (self-referential bootstrap 방지). Phase 7 결과에 결함 발견 시 Phase 7 재실행 또는 별도 sub-phase 가 정상 경로.
- **v2.0 마일스톤 자체의 폐기 / 연기** — Phase 8~12 의 재조정은 v2.0 milestone 범위 내. milestone 자체의 폐기 / 연기는 별도 `/gsd:milestone-revise` (또는 동등) 절차 필요.
- **v1.0 phase 들의 사후 수정** — Phase 1~6 + Phase 5.1 종료됨. 본 audit 가 발견한 G2/G4 항목이 v1.0 산출물에 속하더라도 v1.0 산출물 수정은 본 권한 범위 외 (RHW-01..03 별도 v2.0.1 또는 v2.1 처리).

---

**Authority Status**: AVAILABLE (1 use remaining)

## Triage Revision Log

Plan 02 (`docs/dispatch-reachability.md`) 의 authoritative 4 dispatch 축 매핑이 Plan 01 의 17 raw evidence verdict 와 cross-check 완료. G3 단일 entry (E-17 BusKind::Network tls-external profile) 가 dispatch-reachability.md 의 (axis=syscall, dispatch entry=named arm `BusKind::Network => Self::Network`, orphan?=no) 매핑과 정합. 다른 어떤 사이트도 D-04 narrow 정의 (named dispatch entry + stub body) 를 추가로 만족하지 않음 — E-10..E-14 는 wildcard 흡수로 D-04 narrow 정의 명시 배제, E-15/E-16 은 boot init 경로의 Phase 6 D-07 의도 fail-stop (placeholder 아님), E-01/E-02 는 IDT 벡터 → irq*_handler → pic_eoi_* 경로로 reachable 이나 본문 자체는 정상 PIC OUT 명령 (stub 본문 아님), E-03/E-09 는 orphan-handler 로 G4 verdict 와 일관.

No revisions: Plan 01 verdicts upheld

Bucket counts 동일 유지: G1=0, G2=11, G3=1, G4=5, dropped=0, raw evidence=17. Authority Status: AVAILABLE (1 use remaining).

## AUDIT-03 Air-Gap Dual-Gate Re-Proof

### Scope
Phase 6 의 air-gap dual-gate (build-time `tls-external` cfg + runtime NETWORK_ATTACH capability) 가 v2.0 진입 시점 closed 프로필 산출 바이너리에서도 zero-bypass 임을 1회 재증명.

### Method
`scripts/audit-no-network-rel.sh` (Plan 03 신규 — Phase 6 `scripts/check-no-network.sh` CI standing gate 와 분리된 audit-time wrapper) 가 `cargo build --release --target x86_64-unknown-none` (closed 프로필 = default features only) 산출물에 대해 nm/objdump/gobjdump fallback chain (모든 분기 -C/--demangle 강제 — Issue 5) 으로 7 패턴 부재 확인.

### Pattern Universe (7)
1. `NETWORK_ATTACH_CAP` — BSS static (Phase 6 D-02)
2. `NETWORK_CAP_STATE` — FSM enum BSS (Phase 6 D-02)
3. `init_network_cap` — kernel_main init 호출 site (Phase 6 D-02)
4. `take_network_cap` — sys_network_cap_take handler body (Phase 6 D-03)
5. `air_gap..network` — defense-in-depth 모듈 path regex (Phase 6 D-07 Layer 1) — **demangled form 필수**
6. `handle_attach.*Network` — handle_attach BusKind::Network arm body (Phase 6 D-01) — Plan 03 추가
7. `gen_token_u64.*air_gap` — CAP_DRBG → air_gap 호출 경계 defense-in-depth — Plan 03 추가

### Result
- Verdict: **PASS** (mirrors `.planning/audit/airgap-reproof.log` VERDICT line)
- Evidence log: `.planning/audit/airgap-reproof.log`
- Re-proof commit: `ee29a00e8b8605229f98ef76f12b14b42119d4c8`
- Binary SHA-256: `85c6931cfad20a203073551bec635fff1446270d8aa6d04e934b83647af2738c`
- Tool used: `objdump -C --syms` (fallback chain executed; demangle flag included)
- Patterns matched: `0` / 7 (0 = PASS, non-zero = FAIL = Phase 6 dual-gate regression)

### Relation to Phase 6 CI standing gate
`scripts/check-no-network.sh` 는 Phase 6 의 5-pattern CI 영구 게이트로 unchanged. 본 plan 은 그 위에 2-pattern 보강 + audit-time evidence log emission + **demangle 강제** 만 추가. 두 표면은 책임 분리:
- CI standing (`scripts/check-no-network.sh`): 매 빌드 5 patterns, fast-fail, log 없음. (Phase 6 prior art — nm 분기만 demangle.)
- Audit-time (`scripts/audit-no-network-rel.sh`): Phase 7 1회 7 patterns, evidence log emit, commit SHA pinning, **모든 fallback 분기에서 demangle 강제 (Issue 5 — `air_gap..network` 패턴 정확성 보장)**.

### Audit cross-reference
Plan 01 Task 2 에서 `BusVariant::Network closed profile entry` 는 "symbol absent — see Plan 03 air-gap re-proof" footnote 로 표기됨. 본 section 이 그 footnote 의 destination. Phase 6 dual-gate 가 정상 동작 = closed 프로필에서 audit 대상 자체 (symbol) 가 부재 = AUDIT-03 PASS.

## SC #5 cargo-machete CI Standing Gate

### Installation
- Tool: cargo-machete 0.9.2
- Method: `cargo install --locked cargo-machete`
- Permanent location: `$CARGO_HOME/bin/cargo-machete`
- Version policy: Plan 04 frontmatter must_haves.truths 가 `0.7+` 요구 cargo registry 의 현 stable 0.9.2 가 본 게이트 채택 (DEVIATION cargo-machete 0.7.x 패치 line 은 EOL `cargo install --locked cargo-machete` 가 최신 stable resolve)

### Whitelist Policy (`.machete.toml`)
- Initial state: `ignored = []` (empty per CONTEXT.md §Claude's Discretion resolution)
- Future entries: proc-macro / build.rs / derive-only crates ONLY, with per-line justification comment
- Forbidden: silencing genuine dead deps via whitelist (the gate exists to surface them)
- Per-crate ignore mechanism: `[package.metadata.cargo-machete]` ignored 리스트는 sibling user-space crate 의 deferred cleanup 격리에만 사용 (현재 `crates/iso-user-lumen/Cargo.toml` 의 6 entries — 별도 cleanup plan 으로 deferred, deferred-items.md D-PHASE7-001 참고)

### CI Wiring
- New Makefile target: `check-machete` (pure gate; invokes `cargo machete`; exit non-zero on dead-dep discovery)
- New composite: `ci-phase7: check-alloc-zero check-machete` (v2.0 first phase gate; v1.0 ci-phase1..6 unchanged)
- `.PHONY` single-line extension: Makefile:101 extended in place to contain both `ci-phase6` (existing) AND `check-machete` + `ci-phase7` (new) — single declaration, no bifurcation (Issue 4)
- Forward inheritance: Phase 8~12 가 ci-phase{8..12} composite 정의 시 동일 `check-machete` leg 포함 권장 (MTRX-04 가 Phase 12 에서 그대로 standing gate 로 영구화 — Plan 04 가 prior art)

### Round-Trip Test Evidence (Issue 6 — byteorder no_std-safe synthetic, no --offline, Cargo.lock cleanup)

#### Forward (clean PASS):
```
[machete] cargo-machete dead-dep + dead-pub-item gate
Analyzing dependencies of crates in this directory...
cargo-machete didn't find any unused dependencies in this directory. Good job!
Done!
exit=0
```

#### Reverse (synthetic dead dep `byteorder` with `default-features = false` → FAIL):
```
error: failed to get `aes` as a dependency of package `iso-light-k0 v1.0.0 (<worktree>)`
Caused by: failed to load source for dependency `aes`
Caused by: unable to update <worktree>/elib-k0-nt/aes
Caused by: failed to read <worktree>/elib-k0-nt/aes/Cargo.toml
Caused by: No such file or directory (os error 2)
[machete] cargo-machete dead-dep + dead-pub-item gate
Analyzing dependencies of crates in this directory...
cargo-machete found the following unused dependencies in this directory:
iso-light-k0 -- ./Cargo.toml:
	byteorder

If you believe cargo-machete has detected an unused dependency incorrectly,
you can add the dependency to the list of dependencies to ignore in the
`[package.metadata.cargo-machete]` section of the appropriate Cargo.toml.

Done!
make: *** [check-machete] Error 1
exit=2
```

#### Reset (synthetic removed + `git checkout HEAD -- Cargo.toml` byte-exact restore → PASS):
```
[machete] cargo-machete dead-dep + dead-pub-item gate
Analyzing dependencies of crates in this directory...
cargo-machete didn't find any unused dependencies in this directory. Good job!
Done!
exit=0
```

### Verdict
- Forward exit: 0 (PASS)
- Reverse exit: 2 (FAIL — detected synthetic dep `byteorder`)
- Reset exit: 0 (PASS)
- Round-trip integrity: **VERIFIED** (false-negative and false-positive both ruled out)
- **Residue check (Issue 6)**: Cargo.toml 에 `^byteorder` 0 hits + `PHASE7 PLAN04 SYNTHETIC` 0 hits; Cargo.lock 본 worktree 환경에서 generate 부재 (sibling path `../elib-k0-nt/*` 가 본 worktree symlink layout 에서 unresolved — but cargo-machete 는 Cargo.toml grep 기반 분석이라 Cargo.lock 부재 무관). `git status --short Cargo.toml Cargo.lock` 결과 empty.
- **Worktree environment note**: `cargo update -p byteorder` 와 `cargo update` 가 sibling path resolution 실패로 error 반환했으나 cargo-machete 의 분석은 Cargo.toml 직접 grep 기반이므로 detection 정확성에 영향 없음 (forward + reverse + reset 3 leg 모두 의도된 exit code 산출). 정상 (non-worktree) 환경에서는 `cargo update -p byteorder` 가 byteorder 를 Cargo.lock 에 추가하고 reset leg `cargo update` 가 다시 제거함.

### REQ Traceability (Issue 1 — explicit umbrella mapping rationale)
- Plan 04 `requirements: [AUDIT-01]` — **umbrella mapping**. Frontmatter `requirements_note` records the exact rationale: AUDIT-01 (4-bucket triage report) covers dead-code visibility responsibility; cargo-machete is the automated surface of that responsibility. SC #5 has no dedicated REQ-id in REQUIREMENTS.md §AUDIT because Phase 7 ROADMAP Goal lists cargo-machete as audit-process hygiene rather than a per-REQ v2.0 feature. This umbrella mapping is deliberate, not an oversight.
- ROADMAP §Phase 7 SC #5 정본 인용.
- Forward to Phase 12 MTRX-04: 동일 게이트가 4 cells 모두에서 영구 standing 으로 상속 — 본 Plan 04 가 prior art.

### Deferred Items Surface
- `crates/iso-user-lumen/Cargo.toml` 6 dead deps (`zeroize`, `constant-time`, `sha2`, `sha3`, `postcard`, `serde`) — `[package.metadata.cargo-machete]` per-crate ignore 로 격리 처리. 별도 cleanup plan 으로 deferred (`.planning/phases/07-integration-gap-audit/deferred-items.md` D-PHASE7-001 참고). 본 deferral 은 cargo-machete 게이트 작동의 evidence (false negative 부재) 인 동시에 향후 cleanup 작업 항목으로 등록됨.
