# Lumen Wire Protocol v1

본 문서는 iso-light-k0 커널과 외부 HSM 어플라이언스 (Ring 3 lumen 프로세스, USB CCID, serial 첨가물, smartcard, 향후 air-gapped data-diode) 사이의 wire 프로토콜 v1 을 정의한다. 본 명세는 byte-level 정합 baseline 으로, 외부 어플라이언스 펌웨어 엔지니어가 본 문서만 읽고 호환 구현을 산출할 수 있어야 한다.

본 프로토콜은 Phase 4 의 D-01 (WireFrameHeader 16B `#[repr(C)]`), D-02 (`WIRE_FRAME_MAX = 4096`), D-03 (`WireCmd` 5 종 enum), D-06 (sys_hsm_read 회수 syscall), D-13 (`EP_LUMEN_WIRE = EndpointId(0x0003)`), D-15 (postcard + serde `default-features = false`), D-17 (`WireStatus` 5 종 enum), D-18 (CT 응답 Error frame `payload_len = 0`) 의 18 결정 본문을 byte-level 화한 결과물이다. 동적 할당 (`alloc`) 0, postcard `fixint::le` 강제, fixed-size frame, Topology C (커널 - Ring 3 lumen - 외부 어플라이언스 동일 wire) 정신을 모두 유지한다.

본 명세는 v1 (`version = 0x0001`) 이며, kernel 측 정의 위치는 `src/bus.rs` 의 `WireFrameHeader` / `WireCmd` / `WireStatus` / `WIRE_FRAME_MAX` / `WIRE_PAYLOAD_MAX` / `WIRE_MAGIC` / `WIRE_VERSION` / `WIRE_CMD_RESPONSE_BIT` 8 종 const 와 enum 이고, lumen 측 mirror 정의 위치는 Plan 04 의 `crates/iso-user-lumen/src/main.rs::wire_blake3_phase4_test` 에서 추가될 예정이다.

## Header layout

모든 wire frame 의 첫 16 바이트는 다음 fixed-size header 로 시작한다. `#[repr(C)]` + 자연 정렬 (align 4) + `postcard::fixint::le` 어댑터 적용. padding 옥텟 부재 — 16 옥텟 전부 가시 필드.

| Offset | Size | Field         | Type       | Value                                 |
|--------|------|---------------|------------|---------------------------------------|
| 0..4   | 4    | `magic`       | `[u8; 4]`  | `b"LWK0"` exact (raw byte sequence)   |
| 4..6   | 2    | `version`     | `u16` LE   | `0x0001` (v1 본 명세)                 |
| 6..8   | 2    | `cmd`         | `u16` LE   | `WireCmd` (§Command codes 표 참조)    |
| 8..12  | 4    | `req_id`      | `u32` LE   | request 시 호출자 정의, response 시 echo |
| 12..14 | 2    | `payload_len` | `u16` LE   | `0..=4080` (= `WIRE_PAYLOAD_MAX`)     |
| 14..16 | 2    | `status`      | `u16` LE   | request 시 `0`, response 시 `WireStatus` |

직렬화 / 역직렬화 규칙

- 모든 `u16` / `u32` 정수 필드는 little-endian 으로 직렬화한다. `postcard::fixint::le` 어댑터 또는 수동 `to_le_bytes` / `from_le_bytes` 사용
- `magic` 은 `[u8; 4]` raw byte sequence 이며 endianness 무관. byte 0..4 가 정확히 `0x4C 0x57 0x4B 0x30` (`"LWK0"` ASCII)
- header parse 시 16-byte 전체를 stack-local `[u8; 16]` 으로 복사 후 필드별 LE 디코드 권장 (alignment 위반 회피, Pitfall 1)
- postcard varint 함정 회피 — `#[serde(with = "postcard::fixint::le")]` 가 반드시 모든 정수 필드에 적용되어야 wire 길이가 결정론적으로 16 옥텟

수치 invariant

- `size_of::<WireFrameHeader>() == 16`
- `align_of::<WireFrameHeader>() == 4`
- 본 명세의 byte offset 0..16 은 영구 보존 (forward-compat 시 `version` 필드 증가로 신호)

## Command codes

`WireCmd` `#[repr(u16)]` `#[non_exhaustive]` enum. 코드 공간은 다음 3 구간으로 분할된다.

| 구간             | 범위              | 의미                                       |
|------------------|-------------------|--------------------------------------------|
| Request          | `0x0001..=0x7FFF` | host (lumen / 어플라이언스) → kernel       |
| Response         | `0x8000..=0xFFFE` | kernel → host (= request cmd \| `0x8000`)  |
| Error (response) | `0xFFFF`          | 단일 — Error frame 전용 (`WireCmd::Error`) |

v1 정의 5 variant

| Code     | Name           | Direction      | Auth required             | Phase       | Payload layout                                              |
|----------|----------------|----------------|---------------------------|-------------|-------------------------------------------------------------|
| `0x0001` | `Ping`         | request        | no (unauthenticated probe)| 4 active    | empty (`payload_len = 0`)                                   |
| `0x0010` | `Blake3Hash`   | request        | yes (cap, `HsmRights::USE`) | 4 active  | `cap_token (16B) \|\| input (variable, ≤ 4064B)`            |
| `0x0040` | `AttestSubmit` | request        | yes (Phase 5 attestation) | 5 reserved  | (Phase 5 가 정의)                                           |
| `0x0080` | `Status`       | request        | yes (Phase 6 admin)       | 6 reserved  | (Phase 6 가 정의)                                           |
| `0xFFFF` | `Error`        | response 전용  | n/a                       | 4 active    | empty (`payload_len = 0`)                                   |

response cmd 계산 규칙

- 정상 응답 cmd = request cmd `|` `0x8000`
  - 예 `WireCmd::Ping` (`0x0001`) 의 응답 cmd = `0x8001`
  - 예 `WireCmd::Blake3Hash` (`0x0010`) 의 응답 cmd = `0x8010`
- 에러 응답 cmd = `0xFFFF` (단일, `WireCmd::Error`)

request 거부 invariant (Tier 2)

- `(cmd & 0x8000) != 0` 인 요청 (response bit 세움) → kernel 이 Tier 2 거부 (frame parse 실패와 동일 collapse)
- `cmd == 0xFFFF` (`WireCmd::Error`) 인 요청 → kernel 이 Tier 2 거부 (Pitfall 6)
- 이 두 invariant 는 src/bus.rs 의 `cmd_is_request` 비트로 단일 collapse 검증된다

Payload byte layout (per-cmd 상세)

`WireCmd::Blake3Hash` (`0x0010`)
- offset 0..16 cap_token — 16 옥텟 `HsmCapability` byte-level mirror (Phase 1 D-02 ABI 그대로)
  - `token: u64 LE` (offset 0..8)
  - `slot: u8` (offset 8)
  - `_pad0: u8` (offset 9, 0 강제)
  - `rights: u16 LE` (offset 10..12)
  - `_pad: u8` (offset 12, 0 강제)
  - `_pad1: [u8; 3]` (offset 13..16, 0 강제)
- offset 16..(16 + N) input — Blake3 해시 대상 byte sequence (`N ≤ 4064` = `WIRE_PAYLOAD_MAX - 16`)

`WireCmd::Blake3Hash` 의 정상 응답 (`cmd = 0x8010`)
- `payload_len = 32` (Blake3 digest 길이)
- offset 0..32 digest — 32 옥텟 raw byte (little-endian 또는 raw 의 구분 없음 — Blake3 는 octet 시퀀스)

`WireCmd::Ping` (`0x0001`)
- `payload_len = 0` (request)
- 정상 응답 `cmd = 0x8001`, `payload_len = 0`

## Status codes

`WireStatus` `#[repr(u16)]` `#[non_exhaustive]` enum. request frame 의 `status` 필드는 `0` 으로 강제, response frame 의 `status` 는 다음 5 종 중 하나.

| Code | Name         | Meaning                  | Trigger                                                   |
|------|--------------|--------------------------|-----------------------------------------------------------|
| `0`  | `Ok`         | 정상 응답                | cmd 본문 성공                                             |
| `1`  | `BadFrame`   | request frame 형식 오류  | header parse 실패 시 response status 로만 사용            |
| `2`  | `UnknownCmd` | dispatcher 가 모르는 cmd | Phase 5/6 예약 cmd 도 Phase 4 dispatcher 에서는 본 status |
| `3`  | `Denied`     | cap 인증 실패 / 권한 부족| Phase 1 `authenticate` collapse 표면 (`HsmCapError::*`)   |
| `4`  | `Internal`   | 커널 내부 오류           | Phase 1 Pitfall 7 collapse — `BusError::*` 전 variant     |

forward compat — `#[non_exhaustive]` 명시

- v1 dispatcher 는 위 5 종만 발신한다
- 외부 어플라이언스 reviewer 는 v1+N 명세에서 추가 variant 가 등장할 수 있음을 가정한다 (lumen 측 churn 0)
- 미지정 variant 수신 시 lumen / 외부 어플라이언스는 본 frame 을 `Internal` 등가로 처리할 권장

## Max sizes

`WIRE_FRAME_MAX` 와 `WIRE_PAYLOAD_MAX` 의 const 정의

| Const               | Value                              | 위치 (kernel)                           |
|---------------------|------------------------------------|-----------------------------------------|
| `WIRE_FRAME_MAX`    | `4096` (`0x1000`) 옥텟             | `src/bus.rs::WIRE_FRAME_MAX`            |
| `WIRE_PAYLOAD_MAX`  | `4080` (`= WIRE_FRAME_MAX - 16`) 옥텟 | `src/bus.rs::WIRE_PAYLOAD_MAX`         |
| header 크기         | `16` 옥텟 (`= WIRE_FRAME_MAX - WIRE_PAYLOAD_MAX`) | `size_of::<WireFrameHeader>()` |

검증 규칙

- `data.len() < 16 || data.len() > WIRE_FRAME_MAX` 인 request → Tier 1 거부, response frame 미생성, `sys_hsm_write` RAX = `SyscallError::BadArg`
- `payload_len > WIRE_PAYLOAD_MAX` 또는 `(payload_len as usize) + 16 > data.len()` 인 request → Tier 2 거부, response frame 미생성
- response frame 의 총 길이 = `16 + payload_len` 가 항상 16..=`WIRE_FRAME_MAX` 범위 유지

RELAY_BUF 정합

- Phase 3 의 `CHAN_MAX = 4096` (`src/hsm_registry.rs::CHAN_MAX`) 과 `WIRE_FRAME_MAX = 4096` 가 동일 — kernel staging buffer 단일 게이트
- `sys_hsm_read` 의 `out_len` 검증 범위 = `[16, WIRE_FRAME_MAX]` (= `src/hsm_registry.rs::handle_read` step 2)

## Endianness

본 명세의 모든 multi-byte 정수 필드는 little-endian 으로 직렬화된다. magic 은 raw byte sequence 라 endianness 무관.

| 필드            | 직렬화                                    |
|-----------------|-------------------------------------------|
| `magic`         | raw `[u8; 4]` byte sequence (`"LWK0"`)    |
| `version`       | u16 little-endian (`0x01 0x00` byte)      |
| `cmd`           | u16 little-endian                         |
| `req_id`        | u32 little-endian                         |
| `payload_len`   | u16 little-endian                         |
| `status`        | u16 little-endian                         |
| payload (per-cmd) | per-cmd 명세 — `cap_token` 등 결정론적 LE |

`#[repr(C)]` 자연 정렬 강제. padding 옥텟 없음 — alignment 와 size 가 컴파일-타임 `assert!` 로 잠금 (`size_of::<WireFrameHeader>() == 16`, `align_of::<WireFrameHeader>() == 4`).

postcard `fixint::le` 어댑터 — varint 강제 함정 회피 (Pitfall 1). 외부 어플라이언스 구현체는 수동 LE 직렬화로도 byte-level 호환 보장됨 (kernel 측 `parse_header` 가 `from_le_bytes` 기반 수동 디코드).

## Error frame

Error frame 은 dispatcher 가 cmd 본문 실패 시 lumen 측으로 회신하는 결정론적 16-byte frame 이다. D-18 (CT 응답) 정신에 따라 `payload_len = 0` 강제 — 어떤 status 라도 frame 총 길이는 정확히 16 옥텟이며, payload size-side-channel 정보 노출 0.

Error frame layout

| Field         | Value                                                    |
|---------------|----------------------------------------------------------|
| `magic`       | `b"LWK0"` exact                                          |
| `version`     | `0x0001`                                                 |
| `cmd`         | `0xFFFF` (`WireCmd::Error`)                              |
| `req_id`      | request 의 `req_id` echo (lumen 측 매칭용)               |
| `payload_len` | `0` 강제 (CT 응답 — payload size-side-channel 0)         |
| `status`      | `WireStatus` `1..=4` (원인 코드, 단일 정보 노출 표면)    |

Tier 분리 정책 (D-16 + D-18)

| Tier | 발생 조건                                          | 처리                                                                      |
|------|----------------------------------------------------|---------------------------------------------------------------------------|
| Tier 1 | `data.len() < 16 \|\| data.len() > WIRE_FRAME_MAX` | sys_hsm_write RAX = `SyscallError::BadArg` 즉시, Error frame 미생성       |
| Tier 2 | magic / version / payload_len overflow / cmd_is_request 4 invariant 중 하나 실패 | sys_hsm_write RAX = `SyscallError::Denied` 즉시, Error frame 미생성       |
| Tier 3 | cmd 미지정 / cap 인증 실패 / 본문 실패              | Error frame 적재 + sys_hsm_write RAX = `0` (정상 적재 완료), 후속 `sys_hsm_read` 가 회수 |

Tier 3 의 status 매핑

| 발생 사유                              | `WireStatus`     |
|---------------------------------------|------------------|
| 미지정 cmd (Phase 5/6 reserved 포함)  | `UnknownCmd` (2) |
| cap 인증 실패 (`HsmCapError::*`)      | `Denied` (3)     |
| `BusError::*` 전 variant collapse      | `Internal` (4)   |
| frame 자체 invariant 실패 (response 전용 status) | `BadFrame` (1)   |

회수 ABI (`sys_hsm_read`)

- ABI `rdi = cap_ptr (16B)`, `rsi = out_ptr`, `rdx = out_len ∈ [16, WIRE_FRAME_MAX]`
- RAX = `bytes_read` (정상) 또는 `SyscallError::*.as_rax()` (오류)
- 변환 표 (`src/hsm_registry.rs::handle_read`)

| 발생 조건                              | RAX 매핑                       |
|---------------------------------------|--------------------------------|
| `out_len` 범위 위반                   | `SyscallError::BadArg`         |
| `cap_ptr` / `out_ptr` 사용자 영역 외부 | `SyscallError::BadAddress`     |
| authenticate USE 실패                 | `SyscallError::Denied`         |
| `BusError::*` 전 variant              | `SyscallError::Internal`       |

## Versioning

본 명세는 v1 (`version = 0x0001`). 차후 frame ABI 변경 시 `version` 필드를 증가시킨다.

dispatcher 정책

- v1 dispatcher 는 `version != 0x0001` 인 request 를 Tier 2 거부 (frame parse 실패 collapse 와 동일 매핑)
- 외부 어플라이언스 구현체는 자신의 지원 version 범위를 사전 협상하지 않으며, mismatched version 은 즉시 Tier 2 거부로 신호된다

forward-compat 보장

- `WireCmd` `#[non_exhaustive]` — variant 추가 (예 Phase 5 `AttestSubmit` 활성화) 는 ABI 변경 아님
- `WireStatus` `#[non_exhaustive]` — variant 추가 (예 Phase 6 의 새 오류 코드) 는 ABI 변경 아님
- header layout 변경, `magic` / `version` 의미 변경, payload encoding 변경은 ABI 변경 — version 증가 필수

backward-compat 보장 (v1+N dispatcher 의 v1 frame 수용)

- v1+N kernel 은 v1 frame 을 `version = 0x0001` 로 인식하고 v1 dispatcher 호환 분기로 라우팅 권장 (의무 X — 구현 재량)
- v1 외부 어플라이언스는 v1+N response 의 `non_exhaustive` 추가 variant 를 `Internal` 등가로 처리

# Conformance

본 § 은 외부 lumen 어플라이언스 (Ring 3 lumen, USB CCID 토큰, serial 토큰, smartcard, air-gapped data-diode) 가 본 명세를 byte-level 으로 충족하기 위해 반드시 만족해야 할 7 invariant 이다. invariant 1..7 중 어느 하나라도 위반 시 본 명세 비호환으로 간주한다.

I-1 magic + version exact

- header offset 0..4 = `b"LWK0"` exact (4 옥텟 raw byte sequence)
- header offset 4..6 = `0x0001` u16 LE (v1 본 명세)
- 임의 다른 magic 또는 version 송신 시 kernel dispatcher 의 Tier 2 거부 발동

I-2 fixed 16-byte header

- 모든 frame 의 첫 16 옥텟이 본 §Header layout 의 byte offset 표와 byte-for-byte 일치
- header 길이 가변 금지 — 16 옥텟 영구 보존
- `size_of::<WireFrameHeader>() == 16` 컴파일-타임 게이트 (`src/bus.rs`)

I-3 little-endian + no padding + no varint

- multi-byte 정수 필드는 LE 직렬화 (`u16` / `u32`)
- header / payload 어느 곳에도 padding 옥텟 부재 (header 16 옥텟은 전부 가시 필드, payload 는 per-cmd 명세대로 결정론적 byte sequence)
- postcard `fixint::le` 어댑터 또는 수동 LE 직렬화 — postcard varint encoding 금지 (frame 결정론 16 옥텟 보장)

I-4 alloc-free 강제

- 외부 어플라이언스 구현체는 호출자 제공 static / stack buffer 만 사용한다
- postcard `to_allocvec` / `to_stdvec` / `to_vec` / `serde::std::` 경로 사용 금지
- kernel 측 `check-no-alloc.sh` 의 14 패턴 grep 게이트가 이 invariant 를 본 repo 내부에서 회귀 차단 (Plan 04-01 산출)

I-5 per-cmd payload layout 정합

- `WireCmd::Ping` payload — empty (`payload_len = 0`)
- `WireCmd::Blake3Hash` payload — `cap_token (16B) || input (≤ 4064B)`, `cap_token` 의 16 옥텟 byte layout 은 Phase 1 D-02 `HsmCapability` 와 byte-for-byte 일치
- `WireCmd::Error` payload — empty (`payload_len = 0`, CT 응답)
- AttestSubmit / Status — Phase 5 / Phase 6 가 정의, v1 dispatcher 는 `UnknownCmd` 응답

I-6 response cmd 계산 규칙

- 정상 응답 cmd = request cmd `|` `0x8000`
- 단일 예외 — Error frame cmd = `0xFFFF` (response bit 적용 후 변경 X)
- `(response_cmd & 0x8000) == 0x8000` 또는 `response_cmd == 0xFFFF` 이외의 response 송신 금지

I-7 Error frame payload_len = 0

- Error frame (`cmd = 0xFFFF`) 의 `payload_len` 은 항상 `0`
- `status` u16 (offset 14..16) 가 유일한 정보 노출 표면 — payload size-side-channel 0 (D-18)
- 4 종 `WireStatus` (BadFrame / UnknownCmd / Denied / Internal) 어떤 값이라도 frame 총 길이는 정확히 16 옥텟

## Reference implementation

kernel 측 정의 위치

| 표면                          | 정의 위치 (src/bus.rs)                                           |
|-------------------------------|------------------------------------------------------------------|
| `WireFrameHeader` (16B)       | Plan 04-01 추가, line range 는 SUMMARY 참조                      |
| `WireCmd` / `WireStatus` enum | Plan 04-01 추가                                                  |
| 5 const + 3 추가 const        | `WIRE_FRAME_MAX` / `WIRE_PAYLOAD_MAX` / `WIRE_MAGIC` / `WIRE_VERSION` / `WIRE_CMD_RESPONSE_BIT` |
| `Ring3ProcessBus` 확장        | `pending_response: [u8; WIRE_FRAME_MAX]` + `response_len: u16`   |
| 6 wire 헬퍼 함수              | `parse_header` / `write_header` / `build_response_frame` / `build_error_frame_inplace` / `handle_blake3` / `handle_ping` (Plan 04-02 추가) |
| 3-tier dispatcher 본문        | `impl BusDriver for Ring3ProcessBus::{read, write, poll}` (Plan 04-02 추가) |

syscall 표면

| Syscall          | Number | ABI                                                      | 정의 위치                         |
|------------------|--------|----------------------------------------------------------|-----------------------------------|
| `sys_hsm_write`  | 10     | `rdi=cap_ptr`, `rsi=data_ptr`, `rdx=data_len`            | Phase 3 / Plan 04-02 dispatcher 본문 |
| `sys_hsm_read`   | 12     | `rdi=cap_ptr`, `rsi=out_ptr`, `rdx=out_len`              | Plan 04-03 `handle_read` 신규 |

회귀 테스트 위치 (elib-k0-nt sibling crate)

- Plan 04-02 의 9 종 wire_*.rs host 단위테스트 (`constant-time/tests/wire_*.rs`) — magic / version / cmd / status / Blake3 / single-flight / postcard bit-level cross-validation

향후 lumen 측 mirror 위치

- Plan 04 의 `crates/iso-user-lumen/src/main.rs::wire_blake3_phase4_test` — request 빌드 + sys_hsm_write 호출 + sys_hsm_read 회수 + response Blake3 digest 비교 round-trip

엔드포인트 binding

- `EP_LUMEN_WIRE = EndpointId(0x0003)` (`src/capability.rs::EP_LUMEN_WIRE`) — Plan 04-01 등록
- `Ring3ProcessBus::open` 의 `endpoint_exists` 게이트 통과 (Plan 04-01 Pitfall 5)
- 0x0000 / 0x0001 / 0x0002 (기존 EP) 와 충돌 없음, INVALID(`0xFFFF`) 분리
