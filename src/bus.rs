use crate::capability::EndpointId;
use crate::capability::rand_bytes;
use aes::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
use blake::{BLAKE3_OUT_LEN, Blake3};
use constant_time::traits::CtEqOps;
use mldsa;
use serde::{Deserialize, Serialize};
use zeroize::Secret;
use zeroize::Zeroize;

//
// 상수 / 컴파일-타임 불변식
//

// SoftwareBus 는 role(1) 과 Option<SoftHsmAesGcmState>(약 48) 수용
// Ring3ProcessBus 는 WIRE_FRAME_MAX (4096) + response_len(2) + endpoint(2) + open_state(1) + padding 인라인 보유
// 최대치 4224 로 확장
pub const BUS_INSTANCE_MAX: usize = 4224;
pub const MAX_BUS_INIT_BLOB: usize = 32;
pub const SW_BUS_BUF: usize = 64;

//
// Lumen Wire Contract ABI 표면
//

/// 와이어 프레임 최대 크기
pub const WIRE_FRAME_MAX: usize = 4096;

/// 와이어 페이로드 최대 크기 (= WIRE_FRAME_MAX - 16B 헤더)
pub const WIRE_PAYLOAD_MAX: usize = WIRE_FRAME_MAX - 16;

/// 와이어 프레임 magic 4 bytes
pub const WIRE_MAGIC: [u8; 4] = *b"LWK0";

/// 와이어 프로토콜 버전
pub const WIRE_VERSION: u16 = 0x0001;

/// 응답 프레임을 가리키는 cmd MSB
pub const WIRE_CMD_RESPONSE_BIT: u16 = 0x8000;

/// 16-byte fixed wire frame 헤더
///
/// `#[repr(C)]` 으로 ABI 고정, postcard 의 varint 함정 회피를 위해 모든 정수 필드는
/// `postcard::fixint::le` 어댑터로 little-endian 정수 직렬화를 강제한다
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

/// 와이어 cmd 카탈로그 5 종
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

/// 와이어 status 코드 5 종
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

/// wire AttestSubmit payload 정확 길이 pk 1312 와 bus_kind 1 과 sig 2420 을 이어 3733
///
/// syscall attach 의 ATTEST_EXACT 3732 와 1 옥텟 차이가 나는 이유는
/// wire 가 bus_kind 옥텟을 payload 안에 인라인 포함하기 때문이다
pub const WIRE_ATTEST_LEN: usize = mldsa::MLDSA44::PK_LEN + 1 + mldsa::MLDSA44::SIG_LEN;

// 컴파일-타임 size/align 핀
const _: () = assert!(core::mem::size_of::<WireFrameHeader>() == 16);
const _: () = assert!(core::mem::align_of::<WireFrameHeader>() == 4);
const _: () = assert!(core::mem::size_of::<WireCmd>() == 2);
const _: () = assert!(core::mem::size_of::<WireStatus>() == 2);
const _: () = assert!(WIRE_PAYLOAD_MAX + 16 == WIRE_FRAME_MAX);
const _: () = assert!(WIRE_ATTEST_LEN == 3733);

//
// Wire 헬퍼 6 함수
//
// parse_header / write_header 는 postcard varint 함정을 우회한 수동 byte parse
// build_response_frame / build_error_frame_inplace 는 Ring3ProcessBus::pending_response 적재 진입점
// handle_blake3 / handle_ping 은 Tier 3 cmd dispatch 의 실 본문 (handle_blake3 는 authenticate 와 SoftHsmRole::Blake3 재사용)
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

/// 응답 프레임을 pending_response 슬롯에 적재한다. cmd 필드는 WIRE_CMD_RESPONSE_BIT 을 OR 한다
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

/// 에러 프레임을 적재한다. payload_len = 0 으로 size-side-channel 을 제거한다
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

/// Blake3Hash 디스패치. payload 첫 16B 는 cap_blake3, 이후는 input. authenticate 와 SoftwareBus::write/read 를 재사용한다
fn handle_blake3(req_id: u32, payload: &[u8], out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
    // (1) cap_token slot 미달 시 BadFrame surface, payload_len = 0
    if payload.len() < 16 {
        return build_error_frame_inplace(req_id, WireStatus::BadFrame, out);
    }
    // (2) 위조 cap 도 일단 stack 복사, authenticate CT-AND 가 무력화 책임
    let mut cap = crate::hsm_registry::HsmCapability::invalid();
    // SAFETY: payload[..16] 는 kernel internal 영역 (handle_write 가 RELAY_BUF 로 SMAP 통과 후 진입), cap 16B 정확 복사
    unsafe {
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            &mut cap as *mut crate::hsm_registry::HsmCapability as *mut u8,
            16,
        );
    }
    // (3) CT-AND 5 invariant (token_nonzero & state_ok & token_eq & stored_rights_ok & cap_rights_ok)
    // SAFETY: BSP 단일 코어, syscall 진입은 preempt-disable
    let auth_ok = unsafe {
        crate::hsm_registry::with_registry(|r| {
            r.authenticate(&cap, crate::hsm_registry::HsmRights::USE)
        })
    };
    if !auth_ok {
        cap.zeroize();
        return build_error_frame_inplace(req_id, WireStatus::Denied, out);
    }
    // (4) SoftHsmRole::Blake3 슬롯의 SoftwareBus 가 hash 계산 + 32B ring 저장
    let slot_idx = cap.slot.0 as usize;
    let input = &payload[16..];
    let mut digest = [0u8; 32];
    // SAFETY: with_registry 와 동일 단일 코어 invariant
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
    // (5) cap 회수, 모든 경로에서 zeroize 적용
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

/// Ping 디스패치. 빈 payload 의 Ok 응답 프레임
fn handle_ping(req_id: u32, out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
    build_response_frame(req_id, WireCmd::Ping, WireStatus::Ok, &[], out)
}

/// wire AttestSubmit 디스패치. epoch-rollover 재-attestation
///
/// # Safety
/// 호출자가 Tier 1/2 sanity 통과한 payload 만 전달 data.len ∈ [16, 4096] + magic LWK0 + version 1
///
/// # Errors
/// payload.len() != WIRE_ATTEST_LEN 3733 이면 BadFrame
/// bus_octet ∉ {0, 1} 이면 BadFrame
/// verify_attest Err 이면 Denied audit_enqueue result=6 WireReattestFail
/// 성공 시 Ok audit_enqueue result=5 WireReattestOk slot mutation 0
pub(crate) fn handle_attest_submit(req_id: u32, payload: &[u8], out: &mut [u8; WIRE_FRAME_MAX]) -> usize {
    // (1) payload 길이 정확 3733 옥텟
    if payload.len() != WIRE_ATTEST_LEN {
        return build_error_frame_inplace(req_id, WireStatus::BadFrame, out);
    }
    // (2) split wire layout 고정 offset pk 1312, bus_kind 1, sig 2420
    // SAFETY: payload.len == WIRE_ATTEST_LEN 검증 통과, repr 균등 byte stream
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
    // (4) verify_attest 호출 가드 그대로 재사용 slot mutation 0
    let result = crate::hsm_attest::verify_attest(pk, bus_kind, sig);
    // (5) audit_enqueue wire-side re-attestation event slot=0xFE wire marker
    let prefix = crate::hsm_attest::pk_hash_prefix(pk);
    let (audit_result_code, status) = match result {
        Ok(()) => (5u8, WireStatus::Ok),
        Err(_) => (6u8, WireStatus::Denied),
    };
    crate::hsm_attest::audit_enqueue(0xFE, audit_result_code, bus_octet, prefix);
    // (6) 응답 frame, Ok 는 16B header only, Denied 는 error frame
    match status {
        WireStatus::Ok => {
            build_response_frame(req_id, WireCmd::AttestSubmit, WireStatus::Ok, &[], out)
        }
        _ => build_error_frame_inplace(req_id, WireStatus::Denied, out),
    }
}

/// wire Status 디스패치. audit_snapshot 직렬화
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
    // (3) wire payload 직렬화 manual LE byte-level (transmute 미사용)
    let header_len: usize = 8; // written u16 + total u32 + reserved u16
    let event_bytes = written * core::mem::size_of::<crate::hsm_attest::EnrollEvent>();
    let payload_len = header_len + event_bytes;
    debug_assert!(payload_len <= WIRE_PAYLOAD_MAX);
    // staging = 8 + 32 * 12 = 392 옥텟
    let mut staging = [0u8; 8
        + crate::hsm_attest::AUDIT_RING_CAPACITY
            * core::mem::size_of::<crate::hsm_attest::EnrollEvent>()];
    staging[0..2].copy_from_slice(&(written as u16).to_le_bytes());
    staging[2..6].copy_from_slice(&total.to_le_bytes());
    // staging[6..8] reserved 이미 0 초기화
    for (i, ev) in events_local.iter().enumerate().take(written) {
        let off = 8 + i * core::mem::size_of::<crate::hsm_attest::EnrollEvent>();
        // 명시 byte 조립 transmute 미사용
        staging[off..off + 4].copy_from_slice(&ev.seq.to_le_bytes());
        staging[off + 4] = ev.slot_idx;
        staging[off + 5] = ev.result;
        staging[off + 6] = ev.bus_kind;
        staging[off + 7] = ev._pad;
        staging[off + 8..off + 12].copy_from_slice(&ev.pk_hash_prefix);
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
// BusKind 외부 HSM 트랜스포트 분류, #[non_exhaustive] 으로 후속 variant 추가 시 backward-compat 보장
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
// BusError 는 internal-only, syscall 경계에서 SyscallError::{BadArg, Denied, Internal} 로 collapse
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
// BusReady 는 poll() 결과, 단순 3-bool 구조체
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusReady {
    pub readable: bool,
    pub writable: bool,
    pub closed: bool,
}

//
// BusDriver 6 메서드 표면, caller-provided slice 만 수용, alloc / Vec / Box 부재 grep 검증
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
// SoftHsmRole 는 SoftwareBus 의 mode-aware 디스패치 키, Echo 는 기존 호환, Blake3/AesGcm 는 신규
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
// SoftHsmAesGcmState 는 AesGcm 모드 비밀 상태, key 는 attach 시점 fresh, nonce_counter 는 매 write 단조 증가
//

pub struct SoftHsmAesGcmState {
    pub key: Secret<[u8; 32]>,
    pub nonce_counter: u64,
}

impl Zeroize for SoftHsmAesGcmState {
    // secrets-first, key zeroize 먼저, counter 는 평문 metadata
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.nonce_counter = 0;
    }
}

//
// SoftwareBus 는 64-byte 루프백 echo, 비밀 페이로드 아니지만 일관성 위해 zeroize 명시
//

pub struct SoftwareBus {
    ring: [u8; SW_BUS_BUF],
    write_len: usize,
    read_pos: usize,
    open_state: bool,
    role: SoftHsmRole,                       // active role, backward compat 기본 Echo
    aes_state: Option<SoftHsmAesGcmState>,   // AesGcm 만 Some, Echo/Blake3 는 None
}

impl Default for SoftwareBus {
    fn default() -> Self {
        Self::new()
    }
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
        // init_blob[0] = role discriminant, 빈 슬라이스는 기존 호환 Echo
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
        // init_blob[1..] trailing zeros 강제, forward-reserve (attestation 헤드룸)
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
            // SAFETY: BSP 단일 코어, capability::init_prng 는 부팅 시 완료
            unsafe {
                rand_bytes(&mut key_bytes).map_err(|_| BusError::Internal)?;
            }
            self.aes_state = Some(SoftHsmAesGcmState {
                key: Secret::new(key_bytes),
                nonce_counter: 0,
            });
            // Secret::new 가 소유권을 가져갔어도 스택 슬롯 명시 zeroize
            key_bytes.zeroize();
        } else {
            // Echo / Blake3 는 aes_state 없음, invariant tighten (재-open 방어)
            self.aes_state = None;
        }
        // commit (reset 의미 보존)
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
            // Echo, loopback echo 본문 verbatim 보존, regression 방어
            SoftHsmRole::Echo => {
                // overflow 는 정직한 에러로 surface, silent drop 금지
                if data.len() > SW_BUS_BUF.saturating_sub(self.write_len) {
                    return Err(BusError::BufferTooSmall);
                }
                self.ring[self.write_len..self.write_len + data.len()].copy_from_slice(data);
                self.write_len += data.len();
                Ok(data.len())
            }
            // Blake3, hasher 빌더로 32B digest 생성 후 ring overwrite, digest 는 SecureBuffer Drop 으로 zeroize
            SoftHsmRole::Blake3 => {
                // 컴파일-타임 assert 가 보장하지만 defense-in-depth
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
            // AesGcm, counter 증가 후 encrypt out-param 거쳐 ring 에 nonce||ct||tag 직렬화, stack nonce/tag 명시 zeroize
            SoftHsmRole::AesGcm => {
                let state = self.aes_state.as_mut().ok_or(BusError::Internal)?;
                // fail-stop, counter overflow = (key, nonce) 재사용 차단
                if state.nonce_counter == u64::MAX {
                    return Err(BusError::Internal);
                }
                // ring 용량 검사, 초과 시 정직하게 에러
                let total = data.len() + GCM_NONCE_SIZE + GCM_TAG_SIZE;
                if total > SW_BUS_BUF {
                    return Err(BusError::BufferTooSmall);
                }
                // counter 단조 증가, 위 == u64::MAX 가드로 wrap 미발생
                state.nonce_counter = state.nonce_counter.wrapping_add(1);
                let mut nonce = [0u8; GCM_NONCE_SIZE];
                nonce[..8].copy_from_slice(&state.nonce_counter.to_le_bytes());
                let mut cipher = AES256GCM::default();
                cipher.init(state.key.expose());
                let mut tag = [0u8; GCM_TAG_SIZE];
                cipher
                    .encrypt(
                        &nonce,
                        &[],
                        data,
                        &mut self.ring[GCM_NONCE_SIZE..GCM_NONCE_SIZE + data.len()],
                        &mut tag,
                    )
                    .map_err(|_| BusError::BufferTooSmall)?;
                self.ring[..GCM_NONCE_SIZE].copy_from_slice(&nonce);
                self.ring[GCM_NONCE_SIZE + data.len()..total].copy_from_slice(&tag);
                self.write_len = total;
                self.read_pos = 0;
                // stack-local 명시 zeroize
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

// debug-only 접근자, smoke test 검증용
// release 빌드에서는 두 메서드 모두 부재, 외부 가시 surface 0
#[cfg(debug_assertions)]
impl SoftwareBus {
    pub fn debug_aes_state(&self) -> Option<&SoftHsmAesGcmState> {
        self.aes_state.as_ref()
    }
    pub fn debug_ring(&self) -> &[u8; SW_BUS_BUF] {
        &self.ring
    }
}

// Zeroize cascade, secrets-first, key 부터 discriminant reset, ring, metadata 순서로 소거
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
    // SAFETY-net Drop 폴백, 정상 detach 경로가 우선 호출
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// Ring3ProcessBus, Ring 3 IPC 엔드포인트 바인딩, read/write/poll 는 WireNotReady
//

pub struct Ring3ProcessBus {
    endpoint: EndpointId,
    open_state: bool,
    // single-flight 응답 버퍼
    // raw [u8; N] 사용, Secret::new 가 non-const 라 BusInstance::new const fn 깨짐 회피
    pending_response: [u8; WIRE_FRAME_MAX],
    response_len: u16,
}

impl Default for Ring3ProcessBus {
    fn default() -> Self {
        Self::new()
    }
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
        // (1) init blob 길이 검증, endpoint id 는 2 bytes (u16 LE)
        if init.len() < 2 {
            return Err(BusError::BadInit);
        }
        // (2) decode EndpointId
        let id_raw = u16::from_le_bytes([init[0], init[1]]);
        let endpoint = EndpointId(id_raw);
        // (3) forward-reserve zeros, init_blob[2..] 는 후속 chunk header 헤드룸, 현재는 zero 강제
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
        // (5) endpoint 존재성만 검증, caller 권한 게이트는 후속
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

    // 응답 회수, happy path 직후 pending_response 명시 zeroize, response_len = 0
    fn read(&mut self, out: &mut [u8]) -> Result<usize, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        if self.response_len == 0 {
            return Err(BusError::WireNotReady);
        }
        let n = self.response_len as usize;
        // out 슬롯 부족은 BufferTooSmall 부재로 Internal collapse, BusError variant 보존
        if out.len() < n {
            return Err(BusError::Internal);
        }
        out[..n].copy_from_slice(&self.pending_response[..n]);
        // 회수 직후 stale 자료 cascade 차단
        self.pending_response.zeroize();
        self.response_len = 0;
        Ok(n)
    }

    // Tier 1/2/3 3 단계 wire dispatcher 본문
    fn write(&mut self, data: &[u8]) -> Result<usize, BusError> {
        if !self.open_state {
            return Err(BusError::NotOpen);
        }
        // Tier 1, oversize / undersize 는 handle_write 가 BadArg 로 collapse
        if data.len() < 16 || data.len() > WIRE_FRAME_MAX {
            return Err(BusError::Internal);
        }
        // single-flight, response_len != 0 시 pending_response/response_len 모두 미변경
        // (덮어쓰기 차단, frame parse / cap auth / cmd dispatch 어떤 것도 미수행)
        // handle_write 의 BusError 는 SyscallError::Internal 로 collapse 되어 RAX 매핑
        if self.response_len != 0 {
            return Err(BusError::Internal);
        }
        // Tier 2, header 수동 parse, postcard varint 함정 우회
        let mut hdr_bytes = [0u8; 16];
        hdr_bytes.copy_from_slice(&data[..16]);
        let hdr = parse_header(&hdr_bytes);

        // Tier 2 invariant 4 종, 어느 것이 실패했는지 변별 0, 단일 collapse
        // [u8; 4] 는 CtEqOps 미구현, u32 LE 로 평탄화 후 동일 CT 비교
        let magic_u32 = u32::from_le_bytes(hdr.magic);
        let wire_magic_u32 = u32::from_le_bytes(WIRE_MAGIC);
        let magic_ok = CtEqOps::ct_eq(&magic_u32, &wire_magic_u32).unwrap_u8() == 1;
        let version_ok = CtEqOps::ct_eq(&hdr.version, &WIRE_VERSION).unwrap_u8() == 1;
        let len_ok = (hdr.payload_len as usize) + 16 <= data.len()
            && (hdr.payload_len as usize) <= WIRE_PAYLOAD_MAX;
        // cmd 가 request 인지 검증, 0x8000+ 와 WireCmd::Error 거부
        let cmd_is_request =
            (hdr.cmd & WIRE_CMD_RESPONSE_BIT) == 0 && hdr.cmd != WireCmd::Error as u16;

        if !(magic_ok && version_ok && len_ok && cmd_is_request) {
            return Err(BusError::Internal);
        }

        // Tier 3, cmd dispatch, AttestSubmit/Status 본문 closure
        let payload = &data[16..16 + hdr.payload_len as usize];
        let resp_frame_len = match hdr.cmd {
            x if x == WireCmd::Ping as u16 => handle_ping(hdr.req_id, &mut self.pending_response),
            x if x == WireCmd::Blake3Hash as u16 => {
                handle_blake3(hdr.req_id, payload, &mut self.pending_response)
            }
            // wire AttestSubmit re-attestation dispatch
            x if x == WireCmd::AttestSubmit as u16 => {
                handle_attest_submit(hdr.req_id, payload, &mut self.pending_response)
            }
            // wire Status audit-snapshot dispatch
            x if x == WireCmd::Status as u16 => {
                handle_status(hdr.req_id, payload, &mut self.pending_response)
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

    // readable/writable 시그널, response_len 단일 source-of-truth
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
        // bytes-first 순서, 민감할 수 있는 응답 페이로드를 먼저 비운 뒤
        // 메타데이터 reset
        self.pending_response.zeroize();
        self.response_len = 0;
        // u16 endpoint id 는 non-secret 이나 INVALID 로 reset 이 cleaner invariant
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
// BusInstance enum-dispatch, 본 enum 자체가 BusDriver 구현, 5 stub variants 는 zero-sized, _ => NotImplemented 와일드카드로 흡수
//

// large_enum_variant 억제 근거, Box 로 대형 variant 를 힙에 두는 표준 완화는
// alloc 요구, 본 커널은 동적 할당 금지 (no_std no-alloc) 라 적용 불가
// 슬롯은 정적 고정 풀에 인라인 저장, variant 크기 차이는 설계상 불가피
#[allow(clippy::large_enum_variant)]
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
            // SAFETY-note Self::Empty 의 kind() 는 Attached 슬롯에서만 호출
            // Empty 슬롯은 enumerate 에 부재 (handle_enumerate 의 state==Attached 가드)
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
// Zeroize cascade, 활성 variant payload 를 먼저 비우고 (bytes-first), 마지막에 discriminant 를 Empty 로 reset
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
    // SAFETY-net Drop 폴백, 정상 detach 경로가 명시적 zeroize 우선 호출
    // panic = abort 환경, Drop 은 SMP 종료 시점 / stack-local 보호 목적
    fn drop(&mut self) {
        self.zeroize();
    }
}

//
// 컴파일-타임 사이즈 핀, BusInstance 정의 뒤에 두어 타입 in-scope 보장
//

const _: () = assert!(core::mem::size_of::<BusKind>() == 1);
const _: () = assert!(core::mem::size_of::<BusInstance>() <= BUS_INSTANCE_MAX);

//
// SoftHsm 역할/버퍼 size pin
//

const _: () = assert!(core::mem::size_of::<SoftHsmRole>() == 1);
const _: () = assert!(SW_BUS_BUF >= BLAKE3_OUT_LEN);
const _: () = assert!(SW_BUS_BUF >= GCM_NONCE_SIZE + GCM_TAG_SIZE);
