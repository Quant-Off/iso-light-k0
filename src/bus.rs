use crate::capability::EndpointId;
use crate::capability::rand_bytes;
use aes::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
use blake::{BLAKE3_OUT_LEN, Blake3};
use constant_time::CtEqOps;
use mldsa;
use serde::{Deserialize, Serialize};
use zeroize::Secret;
use zeroize::Zeroize;

//
// 상수 / 컴파일-타임 불변식
//

// Phase 3 Plan-01 SoftwareBus + role(1) + Option<SoftHsmAesGcmState>(~48) 수용
// Phase 4 Plan 01 Ring3ProcessBus 가 WIRE_FRAME_MAX (4096) + response_len(2) + endpoint(2) + open_state(1) + padding 을
// 인라인 보유하므로 4224 로 확장 (RESEARCH Pitfall 2 + Pattern 3)
pub const BUS_INSTANCE_MAX: usize = 4224;
pub const MAX_BUS_INIT_BLOB: usize = 32; // PLANNER CHOICE Plan-01 (RESEARCH §12 #2)
pub const SW_BUS_BUF: usize = 64; // PLANNER CHOICE Plan-01 (RESEARCH §12 #3)

//
// Phase 4 Plan 01 Lumen Wire Contract ABI 표면 (D-01, D-02, D-03, D-17)
//

/// 와이어 프레임 최대 크기 (D-02, RESEARCH Pattern 1)
pub const WIRE_FRAME_MAX: usize = 4096;

/// 와이어 페이로드 최대 크기 (= WIRE_FRAME_MAX - 16B 헤더)
pub const WIRE_PAYLOAD_MAX: usize = WIRE_FRAME_MAX - 16;

/// 와이어 프레임 magic 4 bytes (D-01)
pub const WIRE_MAGIC: [u8; 4] = *b"LWK0";

/// 와이어 프로토콜 버전 (D-01)
pub const WIRE_VERSION: u16 = 0x0001;

/// 응답 프레임을 가리키는 cmd MSB (RESEARCH Pattern 2)
pub const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;

/// 16-byte fixed wire frame 헤더 (D-01)
///
/// `#[repr(C)]` 으로 ABI 고정, postcard 의 varint 함정 회피를 위해 모든 정수 필드는
/// `postcard::fixint::le` 어댑터로 little-endian 정수 직렬화를 강제한다 (RESEARCH Pitfall 1)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireFrameHeader {
    pub magic: [u8; 4],
    #[serde(with = "postcard::fixint::le")]
    pub version: u16,
    #[serde(with = "postcard::fixint::le")]
    pub cmd: u16,
    #[serde(with = "postcard::fixint::le")]
    pub req_id: u32,
    #[serde(with = "postcard::fixint::le")]
    pub payload_len: u16,
    #[serde(with = "postcard::fixint::le")]
    pub status: u16,
}

/// 와이어 cmd 카탈로그 5 종 (D-03)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum WireCmd {
    Ping = 0x0001,
    Blake3Hash = 0x0010,
    AttestSubmit = 0x0040,
    Status = 0x0080,
    Error = 0xFFFF,
}

/// 와이어 status 코드 5 종 (D-17)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
#[non_exhaustive]
pub enum WireStatus {
    Ok = 0,
    BadFrame = 1,
    UnknownCmd = 2,
    Denied = 3,
    Internal = 4,
}

/// Phase 5.1 D-01 wire AttestSubmit payload 정확 길이 pk 1312 ‖ bus_kind 1 ‖ sig 2420 = 3733
///
/// Pitfall 1 회피 syscall attach 의 ATTEST_EXACT 3732 와 1 옥텟 차이
/// wire 는 bus_kind 옥텟이 payload 안에 인라인 포함
pub const WIRE_ATTEST_LEN: usize = mldsa::MLDSA44::PK_LEN + 1 + mldsa::MLDSA44::SIG_LEN;

// 컴파일-타임 size/align 핀 (RESEARCH Pattern 1 + PATTERNS SH-4)
const _: () = assert!(core::mem::size_of::<WireFrameHeader>() == 16);
const _: () = assert!(core::mem::align_of::<WireFrameHeader>() == 4);
const _: () = assert!(core::mem::size_of::<WireCmd>() == 2);
const _: () = assert!(core::mem::size_of::<WireStatus>() == 2);
const _: () = assert!(WIRE_PAYLOAD_MAX + 16 == WIRE_FRAME_MAX);
const _: () = assert!(WIRE_ATTEST_LEN == 3733);

//
// Phase 4 Plan 02 Wire 헬퍼 6 함수 (D-08 / D-11 / D-16 / D-17 / D-18)
//
// parse_header / write_header 는 postcard varint 함정을 우회한 수동 byte parse (Pitfall 1)
// build_response_frame / build_error_frame_inplace 는 Ring3ProcessBus::pending_response 적재 진입점
// handle_blake3 / handle_ping 은 Tier 3 cmd dispatch 의 실 본문 (handle_blake3 는 Phase 1 authenticate + Phase 3 SoftHsmRole::Blake3 재사용)
//

/// 16 byte raw frame 헤더를 6 필드 WireFrameHeader 로 디코드한다
pub fn parse_header(bytes: &[u8; 16]) -> WireFrameHeader {
    WireFrameHeader {
        magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
        version: u16::from_le_bytes([bytes[4], bytes[5]]),
        cmd: u16::from_le_bytes([bytes[6], bytes[7]]),
        req_id: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        payload_len: u16::from_le_bytes([bytes[12], bytes[13]]),
        status: u16::from_le_bytes([bytes[14], bytes[15]]),
    }
}

/// WireFrameHeader 6 필드를 little-endian 으로 16 byte raw 슬롯에 인코드한다
pub fn write_header(h: &WireFrameHeader, out: &mut [u8; 16]) {
    out[0..4].copy_from_slice(&h.magic);
    out[4..6].copy_from_slice(&h.version.to_le_bytes());
    out[6..8].copy_from_slice(&h.cmd.to_le_bytes());
    out[8..12].copy_from_slice(&h.req_id.to_le_bytes());
    out[12..14].copy_from_slice(&h.payload_len.to_le_bytes());
    out[14..16].copy_from_slice(&h.status.to_le_bytes());
}

/// 응답 프레임을 pending_response 슬롯에 적재한다  cmd 필드는 WIRE_CMD_RESPONSE_BIT OR
pub fn build_response_frame(
    req_id: u32,
    cmd: WireCmd,
    status: WireStatus,
    payload: &[u8],
    out: &mut [u8; WIRE_FRAME_MAX],
) -> usize {
    let payload_len = payload.len() as u16;
    let hdr = WireFrameHeader {
        magic: WIRE_MAGIC,
        version: WIRE_VERSION,
        cmd: (cmd as u16) | WIRE_CMD_RESPONSE_BIT,
        req_id,
        payload_len,
        status: status as u16,
    };
    let mut hdr_bytes = [0u8; 16];
    write_header(&hdr, &mut hdr_bytes);
    out[..16].copy_from_slice(&hdr_bytes);
    out[16..16 + payload.len()].copy_from_slice(payload);
    16 + payload.len()
}

/// 에러 프레임을 적재한다  D-18 — payload_len = 0 으로 size-side-channel 제거
pub fn build_error_frame_inplace(
    req_id: u32,
    status: WireStatus,
    out: &mut [u8; WIRE_FRAME_MAX],
) -> usize {
    let hdr = WireFrameHeader {
        magic: WIRE_MAGIC,
        version: WIRE_VERSION,
        cmd: WireCmd::Error as u16,
        req_id,
        payload_len: 0,
        status: status as u16,
    };
    let mut hdr_bytes = [0u8; 16];
    write_header(&hdr, &mut hdr_bytes);
    out[..16].copy_from_slice(&hdr_bytes);
    16
}

/// Blake3Hash 디스패치  payload 첫 16B = cap_blake3, 이후 input  Phase 1 authenticate + Phase 3 SoftwareBus::write/read 재사용
fn handle_blake3(req_id: u32, payload: &[u8], out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
    // (1) cap_token slot 미달은 BadFrame 으로 surface  payload_len = 0
    if payload.len() < 16 {
        return build_error_frame_inplace(req_id, WireStatus::BadFrame, out);
    }
    // (2) 위조 cap 도 일단 stack 으로 복사  authenticate CT-AND 가 무력화 책임
    let mut cap = crate::hsm_registry::HsmCapability::invalid();
    // SAFETY  payload[..16] 는 kernel internal 영역 (handle_write 가 RELAY_BUF 로 SMAP 통과 후 진입)  cap 16B 정확 복사
    unsafe {
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            &mut cap as *mut crate::hsm_registry::HsmCapability as *mut u8,
            16,
        );
    }
    // (3) Phase 1 CT-AND 5 invariant (token_nonzero & state_ok & token_eq & stored_rights_ok & cap_rights_ok)
    // SAFETY  BSP 단일 코어  syscall 진입은 preempt-disable
    let auth_ok = unsafe {
        crate::hsm_registry::with_registry(|r| {
            r.authenticate(&cap, crate::hsm_registry::HsmRights::USE)
        })
    };
    if !auth_ok {
        cap.zeroize();
        return build_error_frame_inplace(req_id, WireStatus::Denied, out);
    }
    // (4) Phase 3 SoftHsmRole::Blake3 슬롯의 SoftwareBus 가 hash 계산 + 32B ring 저장
    let slot_idx = cap.slot.0 as usize;
    let input = &payload[16..];
    let mut digest = [0u8; 32];
    // SAFETY  with_registry 와 동일 단일 코어 invariant
    let ok = unsafe {
        crate::hsm_registry::with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => {
                if bus.write(input).is_err() {
                    return false;
                }
                matches!(bus.read(&mut digest), Ok(32))
            }
            None => false,
        })
    };
    // (5) cap 회수  Pitfall 4 zeroize 모든 경로에서 적용
    cap.zeroize();
    if !ok {
        digest.zeroize();
        return build_error_frame_inplace(req_id, WireStatus::Internal, out);
    }
    // (6) digest 응답 프레임 적재 후 stack-local digest zeroize
    let n = build_response_frame(req_id, WireCmd::Blake3Hash, WireStatus::Ok, &digest, out);
    digest.zeroize();
    n
}

/// Ping 디스패치  빈 payload 의 Ok 응답 프레임 (D-Discretion)
fn handle_ping(req_id: u32, out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
    build_response_frame(req_id, WireCmd::Ping, WireStatus::Ok, &[], out)
}

/// Phase 5.1 D-01 wire AttestSubmit 디스패치  epoch-rollover 재 attestation
///
/// # Safety
/// 호출자가 Tier 1/2 sanity 통과한 payload 만 전달 data.len ∈ [16, 4096] + magic LWK0 + version 1
///
/// # Errors
/// payload.len() != WIRE_ATTEST_LEN 3733 → BadFrame
/// bus_octet ∉ {0, 1} → BadFrame
/// verify_attest Err → Denied audit_enqueue result=6 WireReattestFail
/// 성공 → Ok audit_enqueue result=5 WireReattestOk slot mutation 0
fn handle_attest_submit(req_id: u32, payload: &[u8], out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
    // (1) payload 길이 정확 3733 옥텟 (Pitfall 1 회피)
    if payload.len() != WIRE_ATTEST_LEN {
        return build_error_frame_inplace(req_id, WireStatus::BadFrame, out);
    }
    // (2) split — wire layout fixed offset pk 1312 || bus_kind 1 || sig 2420
    // SAFETY  payload.len == WIRE_ATTEST_LEN 검증 통과, repr 균등 byte stream
    let pk: &[u8; mldsa::MLDSA44::PK_LEN] = unsafe {
        &*(payload.as_ptr() as *const [u8; mldsa::MLDSA44::PK_LEN])
    };
    let bus_octet = payload[mldsa::MLDSA44::PK_LEN];
    let sig: &[u8; mldsa::MLDSA44::SIG_LEN] = unsafe {
        &*(payload[mldsa::MLDSA44::PK_LEN + 1..].as_ptr()
            as *const [u8; mldsa::MLDSA44::SIG_LEN])
    };
    // (3) BusKind octet decode 유효 variant 만 허용
    let bus_kind = match bus_octet {
        0 => BusKind::Software,
        1 => BusKind::Ring3Process,
        _ => return build_error_frame_inplace(req_id, WireStatus::BadFrame, out),
    };
    // (4) verify_attest 호출 Phase 5 가드 그대로 재사용 slot mutation 0
    let result = crate::hsm_attest::verify_attest(pk, bus_kind, sig);
    // (5) audit_enqueue wire-side re-attestation event slot=0xFE wire marker
    let prefix = crate::hsm_attest::pk_hash_prefix(pk);
    let (audit_result_code, status) = match result {
        Ok(()) => (5u8, WireStatus::Ok),
        Err(_) => (6u8, WireStatus::Denied),
    };
    crate::hsm_attest::audit_enqueue(0xFE, audit_result_code, bus_octet, prefix);
    // (6) 응답 frame Ok 는 16B header only Denied 는 error frame
    match status {
        WireStatus::Ok => {
            build_response_frame(req_id, WireCmd::AttestSubmit, WireStatus::Ok, &[], out)
        }
        _ => build_error_frame_inplace(req_id, WireStatus::Denied, out),
    }
}

/// Phase 5.1 D-02 wire Status 디스패치  audit_snapshot 직렬화
///
/// # Errors
/// payload 가 비어있지 않으면 BadFrame
/// 성공 시 payload = [written u16 LE | total u32 LE | 2B reserved | EnrollEvent[written] raw 12 옥텟]
fn handle_status(req_id: u32, payload: &[u8], out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
    // (1) payload empty 정합성
    if !payload.is_empty() {
        return build_error_frame_inplace(req_id, WireStatus::BadFrame, out);
    }
    // (2) caller buffer 시뮬레이션 staging stack-local AUDIT_RING_CAPACITY 슬롯
    let mut events_local = [crate::hsm_attest::EnrollEvent::default();
        crate::hsm_attest::AUDIT_RING_CAPACITY];
    let (written, total) = crate::hsm_attest::audit_snapshot(&mut events_local);
    // (3) wire payload 직렬화 manual LE byte-level (Pitfall 2 transmute 미사용)
    let header_len: usize = 8; // written u16 + total u32 + reserved u16
    let event_bytes = written * core::mem::size_of::<crate::hsm_attest::EnrollEvent>();
    let payload_len = header_len + event_bytes;
    debug_assert!(payload_len <= WIRE_PAYLOAD_MAX); // Pitfall 4 future-proof
    // staging = 8 + 32 * 12 = 392 옥텟
    let mut staging = [0u8; 8
        + crate::hsm_attest::AUDIT_RING_CAPACITY
            * core::mem::size_of::<crate::hsm_attest::EnrollEvent>()];
    staging[0..2].copy_from_slice(&(written as u16).to_le_bytes());
    staging[2..6].copy_from_slice(&total.to_le_bytes());
    // staging[6..8] reserved 이미 0 초기화
    for i in 0..written {
        let off = 8 + i * core::mem::size_of::<crate::hsm_attest::EnrollEvent>();
        // Pitfall 2 회피 명시 byte 조립 transmute 미사용
        staging[off..off + 4].copy_from_slice(&events_local[i].seq.to_le_bytes());
        staging[off + 4] = events_local[i].slot_idx;
        staging[off + 5] = events_local[i].result;
        staging[off + 6] = events_local[i].bus_kind;
        staging[off + 7] = events_local[i]._pad;
        staging[off + 8..off + 12].copy_from_slice(&events_local[i].pk_hash_prefix);
    }
    build_response_frame(
        req_id,
        WireCmd::Status,
        WireStatus::Ok,
        &staging[..payload_len],
        out,
    )
}

//
// BusKind — 외부 HSM 트랜스포트 분류 (BUS-02). #[non_exhaustive] 으로 후속 페이즈 variant 추가 backward-compat.
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum BusKind {
    Software = 0,
    Ring3Process = 1,
    Usb = 2,
    Spi = 3,
    Serial = 4,
    SmartCard = 5,
    Network = 6,
}

//
// BusError — internal-only. syscall 경계에서 SyscallError::{BadArg, Denied, Internal} 로 collapse (Pitfall 7, Plan 02).
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BusError {
    NotImplemented,
    NotOpen,
    AlreadyOpen,
    WireNotReady,
    BadInit,
    BufferTooSmall,
    Closed,
    Internal,
}

//
// BusReady — poll() 결과 (D-07: 단순 3-bool 구조체).
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusReady {
    pub readable: bool,
    pub writable: bool,
    pub closed: bool,
}

//
// BusDriver — 6 메서드 표면 (BUS-01). caller-provided slice 만 받음. alloc / Vec / Box 부재 grep 검증.
//

pub trait BusDriver {
    fn open(&mut self, init: &[u8]) -> Result<(), BusError>;
    fn close(&mut self) -> Result<(), BusError>;
    fn read(&mut self, out: &mut [u8]) -> Result<usize, BusError>;
    fn write(&mut self, data: &[u8]) -> Result<usize, BusError>;
    fn poll(&mut self) -> Result<BusReady, BusError>;
    fn kind(&self) -> BusKind;
}

//
// SoftHsmRole — SoftwareBus 의 mode-aware 디스패치 키 (D-07)  Echo 는 Phase 2 호환, Blake3/AesGcm 가 Phase 3 신규
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum SoftHsmRole {
    Echo = 0,
    Blake3 = 1,
    AesGcm = 2,
}

//
// SoftHsmAesGcmState — AesGcm 모드 비밀 상태 (D-12)  key 는 attach 시점 fresh, nonce_counter 는 매 write 단조 증가
//

pub struct SoftHsmAesGcmState {
    pub key: Secret<[u8; 32]>,
    pub nonce_counter: u64,
}

impl Zeroize for SoftHsmAesGcmState {
    // secrets-first  key zeroize 먼저 (Pitfall 4), counter 는 단순 평문 metadata
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce_counter = 0;
    }
}

//
// SoftwareBus — 64-byte 루프백 echo (D-10). 비밀 페이로드 아님, 그러나 Phase 1 일관성으로 zeroize 명시.
//

pub struct SoftwareBus {
    ring: [u8; SW_BUS_BUF],
    write_len: usize,
    read_pos: usize,
    open_state: bool,
    role: SoftHsmRole,                       // D-07 active role  Phase 2 backward compat 기본 Echo
    aes_state: Option<SoftHsmAesGcmState>,   // D-12 AesGcm 만 Some  Echo/Blake3 는 None
}

impl SoftwareBus {
    pub const fn new() -> Self {
        Self {
            ring: [0u8; SW_BUS_BUF],
            write_len: 0,
            read_pos: 0,
            open_state: false,
            role: SoftHsmRole::Echo,
            aes_state: None,
        }
    }
}

impl BusDriver for SoftwareBus {
    fn open(&mut self, init: &[u8]) -> Result<(), BusError> {
        if self.open_state {
            return Err(BusError::AlreadyOpen);
        }
        // init_blob[0] = role discriminant  빈 슬라이스는 Phase 2 호환 Echo
        let role = if init.is_empty() {
            SoftHsmRole::Echo
        } else {
            match init[0] {
                0 => SoftHsmRole::Echo,
                1 => SoftHsmRole::Blake3,
                2 => SoftHsmRole::AesGcm,
                _ => return Err(BusError::BadInit),
            }
        };
        // init_blob[1..] trailing zeros 강제  forward-reserve (Phase 5 attestation 헤드룸)
        let mut i = 1usize;
        while i < init.len() {
            if init[i] != 0 {
                return Err(BusError::BadInit);
            }
            i += 1;
        }
        // AesGcm 만 capability::rand_bytes 로 32B 키 prime
        if matches!(role, SoftHsmRole::AesGcm) {
            let mut key_bytes = [0u8; 32];
            // SAFETY  BSP 단일 코어  capability::init_prng 는 부팅 시 완료 (Phase 1 D-05)
            unsafe {
                rand_bytes(&mut key_bytes).map_err(|_| BusError::Internal)?;
            }
            self.aes_state = Some(SoftHsmAesGcmState {
                key: Secret::new(key_bytes),
                nonce_counter: 0,
            });
            // Pitfall 4  Secret::new 가 소유권을 가져갔어도 스택 슬롯 명시 zeroize
            key_bytes.zeroize();
        } else {
            // Echo / Blake3 는 aes_state 없음  invariant tighten (재-open 방어)
            self.aes_state = None;
        }
        // commit (Phase 2 reset 의미 보존)
        self.role = role;
        self.ring = [0u8; SW_BUS_BUF];
        self.write_len = 0;
        self.read_pos = 0;
        self.open_state = true;
        Ok(())
    }

    fn close(&mut self) -> Result<(), BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        self.ring = [0u8; SW_BUS_BUF];
        self.write_len = 0;
        self.read_pos = 0;
        self.open_state = false;
        Ok(())
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        let available = self.write_len.saturating_sub(self.read_pos);
        let n = available.min(out.len());
        out[..n].copy_from_slice(&self.ring[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        Ok(n)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        match self.role {
            // Echo  Phase 2 loopback echo 본문 verbatim 보존 (INV-3 regression guard)
            SoftHsmRole::Echo => {
                // Pitfall 6  overflow 는 정직한 에러로 surface, silent drop 금지
                if data.len() > SW_BUS_BUF.saturating_sub(self.write_len) {
                    return Err(BusError::BufferTooSmall);
                }
                self.ring[self.write_len..self.write_len + data.len()].copy_from_slice(data);
                self.write_len += data.len();
                Ok(data.len())
            }
            // Blake3  hasher 빌더 → 32B digest → ring overwrite  digest 는 SecureBuffer Drop 으로 zeroize
            SoftHsmRole::Blake3 => {
                // Pitfall 6  컴파일-타임 assert 가 보장하지만 defense-in-depth
                if SW_BUS_BUF < BLAKE3_OUT_LEN {
                    return Err(BusError::BufferTooSmall);
                }
                let mut hasher = Blake3::new();
                hasher.update(data);
                let digest = hasher.finalize().map_err(|_| BusError::Internal)?;
                self.ring[..BLAKE3_OUT_LEN]
                    .copy_from_slice(&digest.as_slice()[..BLAKE3_OUT_LEN]);
                self.write_len = BLAKE3_OUT_LEN;
                self.read_pos = 0;
                Ok(BLAKE3_OUT_LEN)
            }
            // AesGcm  counter 증가 → encrypt out-param → ring 에 nonce||ct||tag 직렬화  stack nonce/tag 명시 zeroize
            SoftHsmRole::AesGcm => {
                let state = self.aes_state.as_mut().ok_or(BusError::Internal)?;
                // D-12 fail-stop  counter overflow = (key, nonce) 재사용 차단
                if state.nonce_counter == u64::MAX {
                    return Err(BusError::Internal);
                }
                // Pitfall 6  ring fit honest surface
                let total = data.len() + GCM_NONCE_SIZE + GCM_TAG_SIZE;
                if total > SW_BUS_BUF {
                    return Err(BusError::BufferTooSmall);
                }
                // counter 단조 증가  위 == u64::MAX 가드로 wrap 미발생
                state.nonce_counter = state.nonce_counter.wrapping_add(1);
                let mut nonce = [0u8; GCM_NONCE_SIZE];
                nonce[..8].copy_from_slice(&state.nonce_counter.to_le_bytes());
                let cipher = AES256GCM::new(state.key.expose());
                let mut tag = [0u8; GCM_TAG_SIZE];
                cipher.encrypt(
                    &nonce,
                    &[],
                    data,
                    &mut self.ring[GCM_NONCE_SIZE..GCM_NONCE_SIZE + data.len()],
                    &mut tag,
                );
                self.ring[..GCM_NONCE_SIZE].copy_from_slice(&nonce);
                self.ring[GCM_NONCE_SIZE + data.len()..total].copy_from_slice(&tag);
                self.write_len = total;
                self.read_pos = 0;
                // Pitfall 4  stack-local 명시 zeroize
                nonce.zeroize();
                tag.zeroize();
                Ok(total)
            }
        }
    }

    fn poll(&mut self) -> Result<BusReady, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        let readable = self.write_len > self.read_pos;
        let writable = self.write_len < SW_BUS_BUF;
        let closed = false;
        Ok(BusReady {
            readable,
            writable,
            closed,
        })
    }

    fn kind(&self) -> BusKind {
        BusKind::Software
    }
}

// debug-only 접근자  Plan 04 chan_phase3_smoke_test (H4 검증 모델, RESEARCH §Risk #6)
// release 빌드에서는 본 두 메서드 모두 부재  외부 가시 surface 0
#[cfg(debug_assertions)]
impl SoftwareBus {
    pub fn debug_aes_state(&self) -> Option<&SoftHsmAesGcmState> {
        self.aes_state.as_ref()
    }
    pub fn debug_ring(&self) -> &[u8; SW_BUS_BUF] {
        &self.ring
    }
}

// Zeroize cascade (D-15)  secrets-first  key → discriminant reset → ring → metadata
impl Zeroize for SoftwareBus {
    fn zeroize(&mut self) {
        if let Some(state) = self.aes_state.as_mut() {
            state.key.zeroize();
            state.nonce_counter = 0;
        }
        self.aes_state = None;
        self.role = SoftHsmRole::Echo;
        self.ring.zeroize();
        self.write_len = 0;
        self.read_pos = 0;
        self.open_state = false;
    }
}

impl Drop for SoftwareBus {
    // SAFETY-net: Drop 폴백 (Phase 1 voice). 정상 detach 경로가 우선 호출.
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// Ring3ProcessBus — Ring 3 IPC 엔드포인트 바인딩 (D-12). read/write/poll 는 WireNotReady (D-14).
//

pub struct Ring3ProcessBus {
    endpoint: EndpointId,
    open_state: bool,
    // Phase 4 Plan 01 single-flight 응답 버퍼 (D-08, Pattern 3)
    // raw [u8; N] 사용 — Secret::new 가 non-const 라 BusInstance::new const fn 깨짐 회피 (Pitfall 4)
    pending_response: [u8; WIRE_FRAME_MAX],
    response_len: u16,
}

impl Ring3ProcessBus {
    pub const fn new() -> Self {
        Self {
            endpoint: EndpointId::INVALID,
            open_state: false,
            pending_response: [0u8; WIRE_FRAME_MAX],
            response_len: 0,
        }
    }
}

impl BusDriver for Ring3ProcessBus {
    fn open(&mut self, init: &[u8]) -> Result<(), BusError> {
        if self.open_state {
            return Err(BusError::AlreadyOpen);
        }
        // (1) init blob 길이 검증 — endpoint id 는 2 bytes (u16 LE)
        if init.len() < 2 {
            return Err(BusError::BadInit);
        }
        // (2) decode EndpointId
        let id_raw = u16::from_le_bytes([init[0], init[1]]);
        let endpoint = EndpointId(id_raw);
        // (3) forward-reserve zeros — init_blob[2..] 는 Phase 5 chunk header 헤드룸, Phase 2 에서는 zero 강제
        let mut i = 2usize;
        while i < init.len() {
            if init[i] != 0 {
                return Err(BusError::BadInit);
            }
            i += 1;
        }
        // (4) INVALID 거부
        if endpoint == EndpointId::INVALID {
            return Err(BusError::BadInit);
        }
        // (5) endpoint 존재성만 검증 (caller 권한 게이트는 Phase 5 — Pitfall B + A3)
        if !crate::ipc::endpoint_exists(endpoint) {
            return Err(BusError::BadInit);
        }
        // (6) commit
        self.endpoint = endpoint;
        self.open_state = true;
        Ok(())
    }

    fn close(&mut self) -> Result<(), BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        self.endpoint = EndpointId::INVALID;
        self.open_state = false;
        Ok(())
    }

    // 응답 회수 (D-09)  happy path 직후 pending_response 명시 zeroize + response_len = 0
    fn read(&mut self, out: &mut [u8]) -> Result<usize, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        if self.response_len == 0 {
            return Err(BusError::WireNotReady);
        }
        let n = self.response_len as usize;
        // out 슬롯 부족은 BufferTooSmall 부재로 Internal 로 collapse (Plan 02 의 BusError variant 보존 결정)
        if out.len() < n {
            return Err(BusError::Internal);
        }
        out[..n].copy_from_slice(&self.pending_response[..n]);
        // SH-3  회수 직후 stale 자료 cascade 차단 (T-04-10 mitigation)
        self.pending_response.zeroize();
        self.response_len = 0;
        Ok(n)
    }

    // Tier 1/2/3 3 단계 wire dispatcher (D-07 / D-08 / D-16) 본문
    fn write(&mut self, data: &[u8]) -> Result<usize, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        // Tier 1  oversize / undersize  handle_write 가 BadArg 로 collapse (D-16 Tier 1)
        if data.len() < 16 || data.len() > WIRE_FRAME_MAX {
            return Err(BusError::Internal);
        }
        // D-08 single-flight  response_len != 0 시 pending_response/response_len 모두 미변경
        // (덮어쓰기 차단  frame parse / cap auth / cmd dispatch 어떤 것도 수행 X)
        // handle_write 의 BusError → SyscallError::Internal collapse 로 RAX 매핑 (Pitfall 7)
        if self.response_len != 0 {
            return Err(BusError::Internal);
        }
        // Tier 2  header 수동 parse (Pitfall 1)  postcard varint 함정 우회
        let mut hdr_bytes = [0u8; 16];
        hdr_bytes.copy_from_slice(&data[..16]);
        let hdr = parse_header(&hdr_bytes);

        // Tier 2 invariant 4 종  어느 것이 실패했는지 변별 0 (단일 collapse, D-16 Tier 2)
        // [u8; 4] 는 CtEqOps 미구현  u32 LE 로 평탄화 후 동일 CT 비교
        let magic_u32 = u32::from_le_bytes(hdr.magic);
        let wire_magic_u32 = u32::from_le_bytes(WIRE_MAGIC);
        let magic_ok = CtEqOps::eq(&magic_u32, &wire_magic_u32).unwrap_u8() == 1;
        let version_ok = CtEqOps::eq(&hdr.version, &WIRE_VERSION).unwrap_u8() == 1;
        let len_ok = (hdr.payload_len as usize) + 16 <= data.len()
            && (hdr.payload_len as usize) <= WIRE_PAYLOAD_MAX;
        // Pitfall 6  cmd 가 request 인지 검증  0x8000+ 와 WireCmd::Error 거부
        let cmd_is_request =
            (hdr.cmd & WIRE_CMD_RESPONSE_BIT) == 0 && hdr.cmd != WireCmd::Error as u16;

        if !(magic_ok && version_ok && len_ok && cmd_is_request) {
            return Err(BusError::Internal);
        }

        // Tier 3  cmd dispatch (D-11 — Blake3Hash 단일 실 dispatch, AttestSubmit/Status 는 UnknownCmd)
        let payload = &data[16..16 + hdr.payload_len as usize];
        let resp_frame_len = match hdr.cmd {
            x if x == WireCmd::Ping as u16 => handle_ping(hdr.req_id, &mut self.pending_response),
            x if x == WireCmd::Blake3Hash as u16 => {
                handle_blake3(hdr.req_id, payload, &mut self.pending_response)
            }
            _ => build_error_frame_inplace(
                hdr.req_id,
                WireStatus::UnknownCmd,
                &mut self.pending_response,
            ),
        };
        self.response_len = resp_frame_len as u16;
        Ok(data.len())
    }

    // readable/writable 시그널 (D-10)  response_len 단일 source-of-truth
    fn poll(&mut self) -> Result<BusReady, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        Ok(BusReady {
            readable: self.response_len != 0,
            writable: self.response_len == 0,
            closed: false,
        })
    }

    fn kind(&self) -> BusKind {
        BusKind::Ring3Process
    }
}

impl Zeroize for Ring3ProcessBus {
    fn zeroize(&mut self) {
        // Phase 4 Plan 01 bytes-first 순서 — 민감할 수 있는 응답 페이로드를 먼저 비운 뒤
        // 메타데이터를 reset (PATTERNS SH-3, T-04-04 mitigation)
        self.pending_response.zeroize();
        self.response_len = 0;
        // u16 endpoint id 는 RESEARCH §6 기준 non-secret 이나 INVALID 로 reset 이 cleaner invariant
        self.endpoint = EndpointId::INVALID;
        self.open_state = false;
    }
}

impl Drop for Ring3ProcessBus {
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// BusInstance — enum-dispatch (D-01). 본 enum 자체가 BusDriver 를 구현 (D-03). 5 stub variants 는 zero-sized, _ => NotImplemented 와일드카드로 흡수 (D-04).
//

pub enum BusInstance {
    Empty,
    Software(SoftwareBus),
    Ring3Process(Ring3ProcessBus),
    Usb,
    Spi,
    Serial,
    SmartCard,
    Network,
}

impl BusInstance {
    pub const fn new_empty() -> Self {
        Self::Empty
    }

    pub const fn new(kind: BusKind) -> Self {
        match kind {
            BusKind::Software => Self::Software(SoftwareBus::new()),
            BusKind::Ring3Process => Self::Ring3Process(Ring3ProcessBus::new()),
            BusKind::Usb => Self::Usb,
            BusKind::Spi => Self::Spi,
            BusKind::Serial => Self::Serial,
            BusKind::SmartCard => Self::SmartCard,
            BusKind::Network => Self::Network,
        }
    }
}

impl BusDriver for BusInstance {
    fn open(&mut self, init: &[u8]) -> Result<(), BusError> {
        match self {
            Self::Software(s) => s.open(init),
            Self::Ring3Process(r) => r.open(init),
            Self::Empty => Err(BusError::NotOpen),
            _ => Err(BusError::NotImplemented),
        }
    }

    fn close(&mut self) -> Result<(), BusError> {
        match self {
            Self::Software(s) => s.close(),
            Self::Ring3Process(r) => r.close(),
            Self::Empty => Err(BusError::NotOpen),
            _ => Err(BusError::NotImplemented),
        }
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize, BusError> {
        match self {
            Self::Software(s) => s.read(out),
            Self::Ring3Process(r) => r.read(out),
            Self::Empty => Err(BusError::NotOpen),
            _ => Err(BusError::NotImplemented),
        }
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, BusError> {
        match self {
            Self::Software(s) => s.write(data),
            Self::Ring3Process(r) => r.write(data),
            Self::Empty => Err(BusError::NotOpen),
            _ => Err(BusError::NotImplemented),
        }
    }

    fn poll(&mut self) -> Result<BusReady, BusError> {
        match self {
            Self::Software(s) => s.poll(),
            Self::Ring3Process(r) => r.poll(),
            Self::Empty => Err(BusError::NotOpen),
            _ => Err(BusError::NotImplemented),
        }
    }

    fn kind(&self) -> BusKind {
        match self {
            Self::Software(_) => BusKind::Software,
            Self::Ring3Process(_) => BusKind::Ring3Process,
            // SAFETY-note: Self::Empty 의 kind() 는 Plan 02 가 Attached 슬롯에서만 호출 —
            // Empty 슬롯은 enumerate 에 부재 (D-19 + handle_enumerate 의 state==Attached 가드).
            Self::Empty => BusKind::Software,
            Self::Usb => BusKind::Usb,
            Self::Spi => BusKind::Spi,
            Self::Serial => BusKind::Serial,
            Self::SmartCard => BusKind::SmartCard,
            Self::Network => BusKind::Network,
        }
    }
}

//
// Zeroize cascade (D-11). 활성 variant payload 를 먼저 비우고 (bytes-first), 마지막에 discriminant 를 Empty 로 reset (Phase 1 token-first ordering 일관).
//

impl Zeroize for BusInstance {
    fn zeroize(&mut self) {
        match self {
            Self::Software(s) => s.zeroize(),
            Self::Ring3Process(r) => r.zeroize(),
            _ => {}
        }
        *self = Self::Empty;
    }
}

impl Drop for BusInstance {
    // SAFETY-net: Drop 폴백. 정상 detach 경로 (Plan 02 detach) 가 명시적 zeroize 우선 호출.
    // panic = abort 환경 — Drop 은 SMP 종료 시점 / stack-local 보호 목적.
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// 컴파일-타임 사이즈 핀 (D-02). BusInstance 정의 뒤에 두어 타입 in-scope 보장.
//

const _: () = assert!(core::mem::size_of::<BusKind>() == 1);
const _: () = assert!(core::mem::size_of::<BusInstance>() <= BUS_INSTANCE_MAX);

//
// Phase 3 신규 size pin
//

const _: () = assert!(core::mem::size_of::<SoftHsmRole>() == 1);
const _: () = assert!(SW_BUS_BUF >= BLAKE3_OUT_LEN);
const _: () = assert!(SW_BUS_BUF >= GCM_NONCE_SIZE + GCM_TAG_SIZE);
