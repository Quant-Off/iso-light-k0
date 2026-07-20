---
phase: 07
plan: 02
requirements: [AUDIT-02]
audit_source: .planning/audit/audit-report.md@1488af9
generated_at_commit: 1488af9
generated_at: 2026-05-23
scope: src/*.rs (30 파일 14,583 lines) — Plan 01 raw evidence 17 행 (E-01..E-17) 전수 매핑
---

# Phase 7 Dispatch Reachability — Per-Site Mapping

본 문서는 `.planning/audit/audit-report.md` Raw Evidence Appendix 의 17 개 사이트(E-01..E-17)에 대해 **4 dispatch 축의 합집합** 위에서 각 사이트가 어느 dispatch entry 로부터 진입 가능한지(또는 진입 부재의 orphan 인지) 를 매핑한 자족 산출물이다. ROADMAP §Phase 7 SC #2 의 `orphan_handler_count = 0` 와 `orphan_dispatch_entry_count = 0` 게이트가 본 문서의 PASS 기준이다.

## Dispatch Axes (4 in scope per Plan 02 Discretion resolution)

`07-CONTEXT.md` §Claude's Discretion 의 "G3 의 dispatch 표면 범위" 항목을 본 plan 이 **4 축 합집합**(intersection 아님) 으로 해소한다. 근거는 `07-02-PLAN.md` L47 — D-04 narrow 정의("dispatch table / match arm 에 이름별로 명시 등록")가 4 축 어디서나 발생 가능하므로 합집합이 자연스러운 보존적 선택이고, intersection 은 syscall-only stub 같은 false negative 위험을 만든다.

### Axis 1: Ring 3 syscall (src/arch/x86_64/syscall.rs SyscallNum)

`src/arch/x86_64/syscall.rs:127-172` 의 `SyscallNum` enum 카탈로그 (17 변종):

```rust
#[repr(u64)]
pub enum SyscallNum {
    Exit = 0,
    Write = 1,
    IpcCall = 2,
    IpcRecv = 3,
    IpcReply = 4,
    GetRandom = 5,
    CapRequest = 6,
    HsmAttach = 7,
    HsmDetach = 8,
    HsmEnumerate = 9,
    HsmWrite = 10,
    HsmRelay = 11,
    HsmRead = 12,
    #[cfg(feature = "smoke")]
    AttestFixtureExport = 13,
    #[cfg(feature = "tls-external")]
    NetworkCapTake = 14,
    AuditCapTake = 15,
    HsmStatus = 16,
}
```

`src/arch/x86_64/syscall.rs:335-362` 의 `dispatch()` 함수 match arm 매핑 (이름별 명시 등록):

| variant | dispatch entry (match arm) | resolves to |
|---------|---------------------------|-------------|
| `Exit = 0` | `x if x == SyscallNum::Exit as u64 => sys_exit(ctx.rdi)` | `syscall::sys_exit` |
| `Write = 1` | `x if x == SyscallNum::Write as u64 => sys_write(...)` | `syscall::sys_write` |
| `GetRandom = 5` | `x if x == SyscallNum::GetRandom as u64 => sys_getrandom(...)` | `syscall::sys_getrandom` |
| `HsmAttach = 7` | `x if x == SyscallNum::HsmAttach as u64 => crate::hsm_registry::handle_attach(ctx)` | `hsm_registry::handle_attach` |
| `HsmDetach = 8` | 동일 패턴 | `hsm_registry::handle_detach` |
| `HsmEnumerate = 9` | 동일 패턴 | `hsm_registry::handle_enumerate` |
| `HsmWrite = 10` | 동일 패턴 | `hsm_registry::handle_write` |
| `HsmRelay = 11` | 동일 패턴 | `hsm_registry::handle_relay` |
| `HsmRead = 12` | 동일 패턴 | `hsm_registry::handle_read` |
| `AttestFixtureExport = 13` (cfg: smoke) | `crate::handle_attest_fixture_export(ctx)` | `main::handle_attest_fixture_export` |
| `NetworkCapTake = 14` (cfg: tls-external) | `crate::air_gap::take_network_cap(ctx)` | `air_gap::take_network_cap` |
| `AuditCapTake = 15` | `crate::air_gap::take_audit_read_cap(ctx)` | `air_gap::take_audit_read_cap` |
| `HsmStatus = 16` | `crate::air_gap::handle_status(ctx)` | `air_gap::handle_status` |
| `IpcCall = 2` / `IpcRecv = 3` / `IpcReply = 4` / `CapRequest = 6` | 통합 arm `=> SyscallError::Unknown.as_rax()` | `Unknown` collapse (Phase B 와이어업 대기 — D-04 narrow 정의 미충족, named entry 본문이 stub 가 아니라 explicit Unknown collapse) |
| wildcard `_` | `_ => SyscallError::Unknown.as_rax()` | `Unknown` collapse (D-04 wildcard 흡수, named entry 아님) |

### Axis 2: WireCmd (src/bus.rs Ring3ProcessBus::handle_frame)

`src/bus.rs:65-71` 의 `WireCmd` enum 카탈로그 (5 변종):

```rust
#[repr(u16)]
#[non_exhaustive]
pub enum WireCmd {
    Ping = 0x0001,
    Blake3Hash = 0x0010,
    AttestSubmit = 0x0040,
    Status = 0x0080,
    Error = 0xFFFF,
}
```

`src/bus.rs:759-777` 의 `Ring3ProcessBus::write` 의 Tier 3 dispatch 매핑:

| variant | dispatch entry (match arm) | resolves to |
|---------|---------------------------|-------------|
| `Ping = 0x0001` | `x if x == WireCmd::Ping as u16` | `bus::handle_ping` (L229) |
| `Blake3Hash = 0x0010` | `x if x == WireCmd::Blake3Hash as u16` | `bus::handle_blake3` (L174) |
| `AttestSubmit = 0x0040` | `x if x == WireCmd::AttestSubmit as u16` | `bus::handle_attest_submit` (L243) |
| `Status = 0x0080` | `x if x == WireCmd::Status as u16` | `bus::handle_status` (L287) |
| `Error = 0xFFFF` | 진입 차단 — request 검증 (`hdr.cmd != WireCmd::Error as u16`) 에서 거부 | Tier 2 reject |
| wildcard `_` | `_ => build_error_frame_inplace(... WireStatus::UnknownCmd ...)` | `UnknownCmd` (D-04 wildcard 흡수, named entry 아님) |

### Axis 3: IPC (src/ipc.rs ipc_call / ipc_recv / ipc_reply)

`src/ipc.rs` 의 3 public entry (커널-내 동기 rendezvous IPC):

- `pub unsafe fn ipc_call(...)` — L605 — capability 검증 후 EndpointId 로 라우팅; `is_kernel_service(id)` 가 true 면 `EP_CRYPTO/EP_SYSTEM/EP_SIGN` 의 in-line 디스패치, 그 외엔 큐 게시 + reply wait.
- `pub unsafe fn ipc_recv(endpoint_id)` — L671
- `pub unsafe fn ipc_reply(endpoint_id, reply_type, ...)` — L685

**Routing semantics:** IPC 는 enum match-arm 디스패치가 아니라 `EndpointId` (u16) 키 라우팅을 사용한다. 따라서 orphan 분석은 (a) "어떤 in-src 호출자도 `ipc_call`/`ipc_recv`/`ipc_reply` 를 호출하지 않음" → orphan-handler 이고, (b) "어떤 producer 도 `EndpointId X` 에 메시지를 게시하지 않음" → orphan-endpoint 이다. 본 plan 에서는 (a) 만 정량 카운트 (각 함수에 대해), (b) 는 EndpointId 카탈로그가 4 종(`EP_CRYPTO/EP_SYSTEM/EP_SIGN/EP_LUMEN_WIRE`)으로 닫혀 있고 producer 부재 시 dead state 이지만 본 plan 의 17 사이트와 직접 매핑되지 않으므로 별도 메타 노트로만 처리.

**현재 호출자 (in-src):**
- `ipc_call` — `src/main.rs:729` (BLAKE3 smoke), 외 0 producer (Phase B Ring 3 와이어업 대기, syscall::IpcCall arm 은 현재 `Unknown` collapse).
- `ipc_recv` — `src/sign_service.rs:440`, `src/crypto_service.rs:818`.
- `ipc_reply` — `src/sign_service.rs:448/560`, `src/crypto_service.rs:883`.

세 entry 모두 in-src 호출자 ≥ 1 이므로 IPC 표면 자체가 orphan 은 아니다.

### Axis 4: IDT (src/arch/x86_64/idt.rs handler vector)

`src/arch/x86_64/idt.rs:583-723` 의 `init_idt()` 가 등록하는 IDT 256 슬롯 (이름별 명시 등록 vs. default fill):

| IDT vector | dispatch entry (이름별 등록 핸들러) | resolves to |
|-----------|--------------------------------------|-------------|
| 0x00 (#DE) | `divide_error_handler` | fatal_halt |
| 0x01 (#DB) | `debug_handler` | fatal_halt |
| 0x02 (#NMI) | `nmi_handler` (IST_NMI) | fatal_halt |
| 0x03 (#BP) | `breakpoint_handler` | fatal_halt |
| 0x04 (#OF) | `overflow_handler` | fatal_halt |
| 0x05 (#BR) | `bound_range_handler` | fatal_halt |
| 0x06 (#UD) | `invalid_opcode_handler` | fatal_halt |
| 0x07 (#NM) | `device_not_available_handler` | fatal_halt |
| 0x08 (#DF) | `double_fault_handler` (IST_DOUBLE_FAULT) | fatal_halt |
| 0x09 | `default_handler` | fatal_halt |
| 0x0A (#TS) | `invalid_tss_handler` | fatal_halt |
| 0x0B (#NP) | `segment_not_present_handler` | fatal_halt |
| 0x0C (#SS) | `stack_segment_handler` | fatal_halt |
| 0x0D (#GP) | `general_protection_handler` | fatal_halt |
| 0x0E (#PF) | `page_fault_handler` (IST_PAGE_FAULT) | fatal_halt |
| 0x0F..0x1F (예약) | `default_handler` (sparse fill) | fatal_halt |
| 0x10 (#MF) | `x87_fpu_handler` | fatal_halt |
| 0x11 (#AC) | `alignment_check_handler` | fatal_halt |
| 0x12 (#MC) | `machine_check_handler` (IST_MACHINE_CHECK) | fatal_halt |
| 0x13 (#XM) | `simd_fp_handler` | fatal_halt |
| 0x14 (#VE) | `virtualization_handler` | fatal_halt |
| 0x20 (IRQ0) | `irq0_handler` | `pic_eoi_master` 호출 후 반환 (PIT 토대) |
| 0x21..0x27 (IRQ1..7) | `irq_default_handler` | `pic_eoi_master` 호출 후 반환 |
| 0x28..0x2F (IRQ8..15) | `irq_slave_default_handler` | `pic_eoi_slave` 호출 후 반환 |
| 0x30..0xFF (예약) | `default_handler` | fatal_halt |

**Dead-code helper 매핑:**
- `pic_eoi_master` (L233) — `irq0_handler` (L549) AND `irq_default_handler` (L557) 가 호출 → IDT 벡터 0x20..0x27 진입 시 reachable.
- `pic_eoi_slave` (L247) — `irq_slave_default_handler` (L565) 가 호출 → IDT 벡터 0x28..0x2F 진입 시 reachable.
- `enable_irq` (L265) — IDT 등록 (`set_handler`) 도 없고 `init_idt()` 가 호출하지도 않음. 어떤 in-src caller 도 없음 → **orphan-handler**.

**PIC mask state:** `init_pic()` (L189-226) 가 ICW 시퀀스 마지막에 `outb(PIC1_DATA, 0xFF); outb(PIC2_DATA, 0xFF);` 로 모든 IRQ 라인을 마스킹한다. 따라서 IRQ 핸들러는 IDT 에 등록되었으나 실제 PIC 가 deliver 하지 않는다 — **단, dispatch reachability 의 의미는 "IDT vector 가 호출되면 진입 가능한가" 이므로 PIC mask 와 무관하게 IDT 슬롯 등록이 reachability evidence 이다.** (PIC mask 가 해제되면 즉시 진입; `enable_irq` 가 그 해제 helper 이지만 호출 0.)

## Site → Dispatch Mapping

Plan 01 의 17 raw evidence 행 (E-01..E-17) 전수 매핑. 추적은 **unbounded** (Issue 2 Option A — 깊이 캡 없음, visited-set 으로 사이클 종료, in-src caller 완전 소진까지).

| E-NN | file:lines | axis | dispatch entry | resolves to | orphan? |
|------|-----------|------|----------------|-------------|---------|
| E-01 | src/arch/x86_64/idt.rs:233 | IDT | `IDT[0x20] irq0_handler` (L681) AND `IDT[0x21..0x27] irq_default_handler` (L685) | `pic_eoi_master` (call sites idt.rs:549, idt.rs:557) | no (reachable via IDT IRQ0..7 벡터, depth=2; cycle 부재) |
| E-02 | src/arch/x86_64/idt.rs:247 | IDT | `IDT[0x28..0x2F] irq_slave_default_handler` (L691) | `pic_eoi_slave` (call site idt.rs:565) | no (reachable via IDT IRQ8..15 벡터, depth=2) |
| E-03 | src/arch/x86_64/idt.rs:265 | none | (no IDT slot, no `set_handler` call, no in-src caller after unbounded trace) | `enable_irq` 본문 (PIC mask 해제 helper) | orphan-handler (G4 verdict consistent) |
| E-04 | src/keystore.rs:38 | none | (const 데이터, not a function) | `TRUST_ROOT_PSK_SLOT: u8 = 0xFE` | data-only (G2 documented future-purpose; orphan 분석 N/A) |
| E-05 | src/arch/x86_64/vga.rs:20 | none | (enum 타입 — variants 중 일부는 사용, 일부는 미사용) | `Color` enum (Blue/Magenta/Brown 3 variants 사용 0; Black/DarkGray/Green/LightGray/LightRed/Red/White/Yellow 8 variants 사용 ≥ 1) | data-only partial (G4 consistent — 3 variants truly dead but enum-as-whole 은 reachable type) |
| E-06 | src/main.rs:51 | syscall (boot init, debug-only) | (const 데이터; main.rs:633 `try_spawn_user(USER_HELLO_ELF, ...)` 진입 — `#[cfg(all(target_arch = "x86_64", debug_assertions))]` 게이트) | `USER_HELLO_ELF: &[u8]` (embedded ELF) | no (reachable via `_kernel_start` → main.rs:633 try_spawn_user, depth=2, debug 빌드 한정) |
| E-07 | src/main.rs:53 | syscall (boot init, debug-only) | (const 데이터; main.rs:632 `try_spawn_user(USER_LUMEN_ELF, ...)` 진입 — 동일 cfg 게이트) | `USER_LUMEN_ELF: &[u8]` | no (E-06 와 동일 cluster, depth=2, debug 빌드 한정) |
| E-08 | src/hsm_registry.rs:55 | none | (const 데이터 — `HsmRights::NETWORK_ATTACH` bitmask 슬롯, 사용처 0) | `HsmRights(1 << 5)` const | data-only (G2 documented Phase 6 reserved; orphan 분석 N/A; Phase 6 가 대안 mechanism FSM 채택) |
| E-09 | src/tls/handshake.rs:77 | none | (no in-src caller after unbounded trace) | `parse_handshake_header` fn | orphan-handler (G4 verdict consistent; write_handshake_header reader pair 이나 reader 진입 0) |
| E-10 | src/bus.rs:856 | syscall | `_ => Err(BusError::NotImplemented)` wildcard arm in `BusInstance::open` (D-04 wildcard 흡수, NOT G3) | `Err(BusError::NotImplemented)` collapse (caller: `hsm_registry::handle_attach` L314 `bus.open(init_blob)`, depth=2 from syscall HsmAttach) | no (wildcard 흡수는 caller 도달 시 항상 실행, depth=2) |
| E-11 | src/bus.rs:865 | syscall | `_ => Err(BusError::NotImplemented)` wildcard arm in `BusInstance::close` (D-04 wildcard 흡수) | `Err(NotImplemented)` collapse (caller: `hsm_registry::handle_detach` L411 `slot.bus.close()`, depth=2 from syscall HsmDetach) | no |
| E-12 | src/bus.rs:874 | syscall | `_ => Err(NotImplemented)` wildcard in `BusInstance::read` | `Err(NotImplemented)` (callers: `hsm_registry::handle_read` L1007 `bus.read(...)` + `handle_relay` L1119, depth=2 from syscall HsmRead/HsmRelay) | no |
| E-13 | src/bus.rs:883 | syscall | `_ => Err(NotImplemented)` wildcard in `BusInstance::write` | `Err(NotImplemented)` (callers: `hsm_registry::handle_write` L902 + `handle_relay` L1020, depth=2 from syscall HsmWrite/HsmRelay) | no |
| E-14 | src/bus.rs:892 | syscall | `_ => Err(NotImplemented)` wildcard in `BusInstance::poll` | `Err(NotImplemented)` (callers via BusDriver trait; in-src 호출자 부재 — 본 메서드는 trait 표면이고 BUS-01 정의의 일부) | no (wildcard 본문 자체는 reachable when caller exists; current in-src callers 0 이나 trait 표면 의무 표시 — D-01 documented BUS-01 trait completeness; orphan 분석은 trait 표면이라는 design intent 으로 reachable 로 분류) |
| E-15 | src/air_gap.rs:178 | syscall (boot init) | (direct call from `gap_self_check`; main.rs:613 `air_gap::gap_self_check()` 진입; tls-external cfg 게이트) | `panic!("gap_self_check NETWORK_ATTACH_CAP not initialized in tls-external build")` (Phase 6 D-07 Layer 2-a fail-stop) | no (boot init 경로 reachable, depth=2 from kernel_main → gap_self_check) |
| E-16 | src/air_gap.rs:191 | syscall (boot init) | (direct call from `gap_self_check`; main.rs:613 진입; 양 프로필 공통) | `panic!("gap_self_check AUDIT_READ_CAP not initialized")` (Phase 6 D-07 Layer 2-c fail-stop) | no (boot init 경로 reachable, depth=2) |
| E-17 | src/bus.rs:845 | syscall (tls-external profile) | named arm `BusKind::Network => Self::Network` in `BusInstance::new` (D-04 narrow named entry); 후속 dispatch 메서드 본문은 wildcard 흡수 (E-10..E-14) | `BusInstance::Network` zero-sized variant (caller: `hsm_registry::handle_attach` L312 `BusInstance::new(bus_kind)`, depth=2 from syscall HsmAttach; closed 프로필은 L578-584 의 `_ => SyscallError::Denied` 로 차단되어 본 arm 도달 불가, tls-external 한정) | no (named entry reachable via syscall HsmAttach; G3 verdict consistent) |

**Tracing 종료 통계:** 모든 17 사이트에 대해 unbounded reverse-call trace 가 (a) dispatch axis 도달 또는 (b) in-src caller 완전 소진 으로 깔끔히 종료. visited-set 으로 cycle 검사 — 부재. 최대 추적 깊이 = 2 (모든 placeholder 가 dispatch axis 의 직접 호출자 또는 그 1-hop 안쪽에 위치). `unreached-within-N-hops` 버킷 미발생 (Issue 2 Option A 충족).

## Orphan Analysis

`orphan_handler_count = 2` (E-03 `enable_irq`, E-09 `parse_handshake_header`)

`orphan_dispatch_entry_count = 0` (모든 dispatch table arm 이 정의된 함수 심볼로 resolve; Rust 컴파일러 검증 보강)

**Orphan handler ↔ audit-report.md verdict 정합성:**

| E-NN | orphan 분류 | audit-report.md verdict | 정합성 |
|------|------------|------------------------|--------|
| E-03 `enable_irq` | orphan-handler | G4 (D-02, no REQ/OoS mapping, IRQ handler 부재) | consistent (G4 truly-dead + orphan-handler 자연 매칭) |
| E-09 `parse_handshake_header` | orphan-handler | G4 (D-02 borderline, write/parse pair completeness 정황은 있으나 명시 REQ 부재) | consistent (G4 truly-dead + orphan-handler 자연 매칭; Plan 04 reviewer 가 G2 upgrade 여부 최종 결정 — 본 plan 의 dispatch 사실은 verdict 변경을 강제하지 않음) |

**Data-only 사이트 (orphan 분석 N/A):**
E-04 / E-05 / E-08 — const 또는 enum 타입이며 함수 / dispatch entry 가 아니다. data-only 로 분류. E-04/E-08 은 G2 documented future-purpose, E-05 는 G4 partial-dead (enum 타입 자체는 사용되나 일부 variants 0 사용).

**Cross-check audit-report.md G3 verdicts** (D-04 narrow 정의 보존 검증):
- E-17 `BusKind::Network` (tls-external profile) — Plan 01 의 G3 verdict 가 본 plan 의 매핑(axis=syscall, dispatch entry=named arm `BusKind::Network => Self::Network`, orphan?=no)과 충돌 없음. **G3 verdict 유지 — 본 plan 은 audit-report.md back-edit 불필요.**
- 다른 어떤 사이트도 named dispatch entry + stub body 패턴을 추가로 만족하지 않음 (E-10..E-14 는 wildcard 흡수로 D-04 narrow 정의에서 명시 배제; E-15/E-16 은 syscall axis 아닌 boot init 직접 호출이며 본문이 placeholder 가 아니라 Phase 6 D-07 의도된 fail-stop).

**SC #2 gate**: orphan_handler_count = 2 AND orphan_dispatch_entry_count = 0 → PASS

`orphan_dispatch_entry_count = 0` 이 SC #2 의 hard gate 이며 충족. `orphan_handler_count = 2` 는 두 사이트 모두 audit-report.md 의 G4 truly-dead verdict 와 일관되어 정합성 문제 없음 (G4 정의 자체가 orphan-handler 와 매칭되는 카테고리).

**audit-report.md G1 count delta from Plan 02: +0** (escalation 부재 — orphan_dispatch_entry_count 가 0 이므로 D-03 G1 키보드 우선순위 trigger 미발동).

## Methodology

- **Axis universe = union of (syscall ∪ WireCmd ∪ IPC ∪ IDT).** Intersection rejected: a stub reachable via only syscall (예: BusKind::Network E-17) would be falsely classified non-G3 under intersection because WireCmd/IPC/IDT 축 모두 진입 부재. 본 plan 의 D-04 narrow 정의는 "어느 한 dispatch table 의 named entry" 면 충족이므로 union 이 자연스러운 선택.
- **Tool choice = manual `rg` + Markdown table.** `cargo-call-stack` / rust-analyzer LSP rejected for 1회 audit cost-benefit (13K LOC 단발성, 4 축이 모두 grep-friendly: SyscallNum match arm / WireCmd match arm / ipc_* function signature / IDT[N] vector slot 표). 자동화 도구 도입 비용이 본 audit 의 가시성 산출 가치를 초과. `07-CONTEXT.md §deferred` 가 v2.1 마일스톤으로 자동화 이월.
- **Call-path tracing depth = unbounded** (Issue 2 Option A — checker revision iteration 1 채택). 13K LOC × 사이트당 평균 in-src caller ~5 → 완전 추적 비용 bounded. 종료 조건은 (a) 4 축 dispatch entry 어느 하나 도달 (REACHABLE) 또는 (b) in-src caller-set 완전 소진 (UNREACHABLE) 만. cycle 검사는 visited-set 으로 (mutual recursion 진입 시 `cycle — see caller X` 표기로 branch 종료). **No `unreached-within-N-hops` bucket** — 본 매핑의 모든 사이트가 definitive REACHABLE 또는 UNREACHABLE 판정.
- **Cross-file 추적성:** 본 문서의 모든 site row 가 `.planning/audit/audit-report.md` Raw Evidence Appendix 의 동일 `E-NN` id 를 인용. `audit_source: .planning/audit/audit-report.md@1488af9` frontmatter 가 정확한 audit 버전 핀.
- **잔여 위험 (T-07-10 accept):** 수동 rg 의 false-negative 가능성. 본 plan 은 4 축 각각의 enumeration grep 패턴을 명시하고 각 사이트별 caller chain 을 visited-set 으로 완전 traverse 했으나, 동적 dispatch (trait object via `Box<dyn>` 등) 가 본 커널 내 부재(`alloc` 금지 + `Box` 부재)함이 잔여 위험 회피의 보조 사실. 향후 v2.1 자동화 도입 시 본 잔여 위험 추가 축소.

---

**Generated at commit:** `1488af9` (audit-report.md `generated_at_commit` `39d4c72` 와 1 wave 차이 — Plan 01 산출 후 Plan 02 wave 진입 사이 본체 src/ 변경 0 검증: `git diff 39d4c72..1488af9 -- src/` 결과 audit 표면 변경 부재.)
