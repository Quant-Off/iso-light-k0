//! 동기 메시지 패싱 기반 IPC(Inter-Process Communication) 를 수행하는
//! 모듈입니다.
//!
//! CLI 바이너리는 `ipc_call()` 로 capability 검증을 거친 뒤 커널 IPC 코어를
//! 통해 Crypto Service 등 수신자의 `ipc_recv()` 로 메시지를 전달합니다.
//! 수신자가 `ipc_reply()` 로 응답을 게시하면 발신자는 응답을 수신하며
//! 페이로드는 Secret 으로 자동 소거됩니다.
//!
//! 동기 rendezvous 흐름:
//!   1. 발신자: `ipc_send()` 로 엔드포인트에 메시지 게시 후 응답 대기
//!   2. 커널:   capability 검증 후 수신자에게 전달
//!   3. 수신자: `ipc_recv()` 로 수신 후 처리, `ipc_reply()` 로 응답 게시
//!   4. 발신자: 응답 수신, 페이로드 Secret 으로 자동 소거
//!
//! 보안 보장:
//!   - 모든 Capability 검증 후에만 메시지 전달
//!   - 페이로드(민감 데이터)는 Secret 으로 자동 소거
//!   - 페이로드 길이 범위 검사로 버퍼 오버플로 방지
//!   - 메시지 시퀀스 번호로 재생 공격(replay attack) 기초 방어

use crate::capability::{Capability, EP_CRYPTO, EP_SYSTEM, EndpointId, Rights};
use zeroize::volatile::secure_zero;
use zeroize::{Secret, Zeroize};

//
// 상수
//

/// IPC 메시지 페이로드 최대 크기 (bytes).
/// 32바이트 키 + 12바이트 nonce + 데이터를 수용할 수 있는 크기.
pub const IPC_MAX_PAYLOAD: usize = 256;

/// 커널이 관리하는 IPC 엔드포인트 최대 수.
pub const IPC_MAX_ENDPOINTS: usize = 16;

/// 커널 내부 서비스 엔드포인트 식별자 (`ipc_call` 에서 동기 디스패치 경로 결정).
///
/// 사용자 공간 엔드포인트가 아닌, 커널 자체가 제공하는 서비스는 `ipc_call` 내부에서
/// 메시지 게시 직후 해당 서비스 핸들러를 **동일 호출 스택에서 동기적으로 실행**함.
/// 이로써 스케줄러 구현 이전에도 round-trip(call-reply) IPC 가 작동함.
fn is_kernel_service(id: EndpointId) -> bool {
    id == EP_CRYPTO || id == EP_SYSTEM
}

//
// 메시지 타입
//

/// IPC 메시지 종류.
///
/// 시스템 메시지(0x0000~0x0FFF)와 서비스 메시지(0x1000~)로 구분.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum MessageType {
    // 시스템
    Ping = 0x0001,       // 연결 확인
    Pong = 0x0002,       // Ping 응답
    Connect = 0x0003,    // 엔드포인트 연결 요청
    Disconnect = 0x0004, // 연결 해제

    // 암호화 서비스 (EP_CRYPTO)
    /// AES-GCM / ChaCha20-Poly1305 암호화 요청
    EncryptReq = 0x1001,
    /// 암호화 응답 (ciphertext + auth tag)
    EncryptResp = 0x1002,
    /// 복호화 요청
    DecryptReq = 0x1003,
    /// 복호화 응답 (plaintext, 실패 시 Error 반환)
    DecryptResp = 0x1004,
    /// HMAC-SHA256 / BLAKE3 해시 요청
    HashReq = 0x1005,
    /// 해시 응답
    HashResp = 0x1006,
    /// 키 파생 요청 (HKDF 등)
    KeyDeriveReq = 0x1007,
    /// 키 파생 응답
    KeyDeriveResp = 0x1008,

    // 에러
    Error = 0xFFFF,
}

//
// 암호화 알고리즘 식별자
//

/// 지원 암호화 알고리즘 식별자.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum CryptoAlgo {
    /// AES-128-GCM (키 16바이트, nonce 12바이트)
    Aes128Gcm = 0x01,
    /// AES-256-GCM (키 32바이트, nonce 12바이트)
    Aes256Gcm = 0x02,
    /// ChaCha20-Poly1305 (키 32바이트, nonce 12바이트)
    ChaCha20Poly = 0x03,
    /// HMAC-SHA256
    HmacSha256 = 0x10,
    /// BLAKE3
    Blake3 = 0x11,
    /// HKDF-SHA256 (키 파생)
    HkdfSha256 = 0x20,
}

//
// 메시지 헤더
//

/// IPC 메시지 헤더 (8 bytes).
///
/// 헤더는 메타데이터만 포함하며 민감 데이터를 담지 않음.
/// 페이로드 길이는 반드시 검증 후 사용해야 함.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MessageHeader {
    /// 메시지 종류
    pub msg_type: MessageType,
    /// 실제 페이로드 길이 (≤ IPC_MAX_PAYLOAD)
    pub payload_len: u16,
    /// 재생 공격 방지용 단조 증가 시퀀스 번호
    pub sequence: u32,
}

//
// 메시지 페이로드
//

/// 암호화 요청/응답 페이로드 레이아웃.
///
/// 256 bytes:
///   [0]      algo: CryptoAlgo
///   [1]      key_len (bytes, 0 = 키 없음)
///   [2]      nonce_len (bytes, 0 = nonce 없음)
///   [3]      flags (예약)
///   [4..5]   data_len (실제 데이터 길이)
///   [6..7]   예약
///   [8..39]  key (최대 32 bytes)
///   [40..51] nonce (최대 12 bytes)
///   [52..55] 예약
///   [56..255] data (최대 200 bytes)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CryptoPayload {
    pub algo: u8,
    pub key_len: u8,
    pub nonce_len: u8,
    pub flags: u8,
    pub data_len: u16,
    _reserved: u16,
    pub key: [u8; 32],   // 키 (민감 데이터)
    pub nonce: [u8; 12], // nonce
    _pad: [u8; 4],
    pub data: [u8; 200], // 평문 또는 암호문
}

impl CryptoPayload {
    pub const fn zeroed() -> Self {
        Self {
            algo: 0,
            key_len: 0,
            nonce_len: 0,
            flags: 0,
            data_len: 0,
            _reserved: 0,
            key: [0u8; 32],
            nonce: [0u8; 12],
            _pad: [0u8; 4],
            data: [0u8; 200],
        }
    }
}

// 전체 CryptoPayload를 volatile 소거
impl Zeroize for CryptoPayload {
    fn zeroize(&mut self) {
        // SAFETY: self는 유효한 CryptoPayload 참조, 크기 == core::mem::size_of::<Self>()
        unsafe {
            secure_zero(
                self as *mut CryptoPayload as *mut u8,
                core::mem::size_of::<CryptoPayload>(),
            );
        }
    }
}

/// 범용 원시 IPC 페이로드 (256 bytes).
///
/// 구조화된 타입으로 해석하거나 직접 바이트 슬라이스로 사용.
#[repr(C, align(8))]
pub struct RawPayload {
    pub data: [u8; IPC_MAX_PAYLOAD],
}

impl Zeroize for RawPayload {
    fn zeroize(&mut self) {
        // SAFETY: self.data는 IPC_MAX_PAYLOAD 바이트의 유효한 배열
        unsafe { secure_zero(self.data.as_mut_ptr(), IPC_MAX_PAYLOAD) };
    }
}

//
// IPC 메시지
//

/// 완전한 IPC 메시지.
///
/// `payload`는 elib-k0-nt의 `Secret<T>`로 감싸져 있어 `IpcMessage`가 Drop될 때
/// 페이로드의 민감 데이터(키, 평문 등)가 volatile write + 메모리 배리어로 자동 소거됨.
pub struct IpcMessage {
    pub header: MessageHeader,
    /// 민감 데이터 포함 가능 — Drop 시 자동 소거
    pub payload: Secret<RawPayload>,
}

impl IpcMessage {
    /// 빈 메시지 생성.
    pub fn new(msg_type: MessageType, sequence: u32) -> Self {
        Self {
            header: MessageHeader {
                msg_type,
                payload_len: 0,
                sequence,
            },
            payload: Secret::new(RawPayload {
                data: [0u8; IPC_MAX_PAYLOAD],
            }),
        }
    }

    /// 페이로드 데이터를 복사하고 길이를 설정함.
    ///
    /// # Errors
    /// `data.len() > IPC_MAX_PAYLOAD`이면 `IpcError::PayloadTooLarge` 반환.
    pub fn set_payload(&mut self, data: &[u8]) -> Result<(), IpcError> {
        if data.len() > IPC_MAX_PAYLOAD {
            return Err(IpcError::PayloadTooLarge);
        }
        let len = data.len();
        self.payload.data[..len].copy_from_slice(data);
        // 나머지 바이트는 0으로 유지 (정보 유출 방지)
        // SAFETY: 나머지 범위는 IPC_MAX_PAYLOAD 내에 있음
        unsafe {
            secure_zero(self.payload.data[len..].as_mut_ptr(), IPC_MAX_PAYLOAD - len);
        }
        self.header.payload_len = len as u16;
        Ok(())
    }

    /// 유효한 페이로드 슬라이스 반환.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload.data[..self.header.payload_len as usize]
    }
}

//
// IPC 에러
//

#[derive(Debug, PartialEq, Eq)]
pub enum IpcError {
    /// Capability 검증 실패 (권한 부족 또는 잘못된 토큰)
    CapabilityDenied,
    /// 엔드포인트가 이미 메시지를 처리 중 (rendezvous 대기 불가)
    EndpointBusy,
    /// 엔드포인트를 찾을 수 없음
    EndpointNotFound,
    /// 페이로드 길이가 IPC_MAX_PAYLOAD를 초과함
    PayloadTooLarge,
    /// 페이로드 길이가 헤더에 기록된 값과 불일치 (무결성 오류)
    PayloadLenMismatch,
    /// 수신 대기 중인 메시지 없음
    NoMessage,
    /// 엔드포인트 슬롯 부족
    EndpointsFull,
    /// 잘못된 메시지 타입
    InvalidMessageType,
}

//
// IPC 엔드포인트 상태
//

/// IPC 엔드포인트의 현재 상태.
enum EndpointState {
    /// 메시지 없음, 대기 중
    Idle,
    /// 발신자가 메시지를 게시하고 응답 대기 중
    PendingReply(IpcMessage),
    /// 응답 메시지가 준비됨
    ReplyReady(IpcMessage),
}

//
// IPC 엔드포인트
//

/// IPC 엔드포인트.
///
/// 각 엔드포인트는 고유 ID와 필요 권한을 가지며,
/// 한 번에 하나의 메시지만 보유 (rendezvous 모델).
pub struct IpcEndpoint {
    pub id: EndpointId,
    /// 이 엔드포인트에 SEND하려면 반드시 보유해야 하는 권한
    pub required_rights: Rights,
    state: EndpointState,
    /// 단조 증가 시퀀스 카운터 (재생 공격 방지 기초)
    pub sequence: u32,
}

impl IpcEndpoint {
    pub const fn new(id: EndpointId, required_rights: Rights) -> Self {
        Self {
            id,
            required_rights,
            state: EndpointState::Idle,
            sequence: 0,
        }
    }

    /// 새 시퀀스 번호를 발급하고 반환.
    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1);
        self.sequence
    }

    /// Capability를 검증하고 메시지를 게시함 (발신자측).
    ///
    /// 성공 시 엔드포인트 상태가 `PendingReply`로 전환됨.
    fn post(&mut self, cap: &Capability, mut msg: IpcMessage) -> Result<(), IpcError> {
        // 1. Capability 검증
        if !cap.is_valid_for(self.id, self.required_rights) {
            return Err(IpcError::CapabilityDenied);
        }

        // 2. 엔드포인트 가용성 확인
        if matches!(self.state, EndpointState::PendingReply(_)) {
            return Err(IpcError::EndpointBusy);
        }

        // 3. 페이로드 길이 무결성 검사
        if msg.header.payload_len as usize > IPC_MAX_PAYLOAD {
            return Err(IpcError::PayloadLenMismatch);
        }

        // 4. 시퀀스 번호 주입 (재생 공격 방지)
        msg.header.sequence = self.next_sequence();

        self.state = EndpointState::PendingReply(msg);
        Ok(())
    }

    /// 대기 중인 메시지를 수신함 (수신자측).
    ///
    /// 성공 시 엔드포인트 상태가 `Idle`로 전환됨.
    fn take(&mut self) -> Result<IpcMessage, IpcError> {
        let mut state = EndpointState::Idle;
        core::mem::swap(&mut self.state, &mut state);
        match state {
            EndpointState::PendingReply(msg) => Ok(msg),
            other => {
                self.state = other;
                Err(IpcError::NoMessage)
            }
        }
    }

    /// 응답 메시지를 게시함 (서비스측).
    fn post_reply(&mut self, reply: IpcMessage) -> Result<(), IpcError> {
        if matches!(self.state, EndpointState::ReplyReady(_)) {
            return Err(IpcError::EndpointBusy);
        }
        self.state = EndpointState::ReplyReady(reply);
        Ok(())
    }

    /// 응답 메시지를 수신함 (발신자측).
    fn take_reply(&mut self) -> Result<IpcMessage, IpcError> {
        let mut state = EndpointState::Idle;
        core::mem::swap(&mut self.state, &mut state);
        match state {
            EndpointState::ReplyReady(msg) => Ok(msg),
            other => {
                self.state = other;
                Err(IpcError::NoMessage)
            }
        }
    }
}

//
// 전역 IPC 레지스트리
//

/// 커널 전역 IPC 엔드포인트 레지스트리.
pub struct IpcRegistry {
    endpoints: [Option<IpcEndpoint>; IPC_MAX_ENDPOINTS],
    count: usize,
}

impl IpcRegistry {
    pub const fn empty() -> Self {
        // Option<IpcEndpoint>는 Copy가 아니므로 직접 초기화
        Self {
            endpoints: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            count: 0,
        }
    }

    /// 새 엔드포인트를 등록함.
    pub fn register(&mut self, id: EndpointId, required_rights: Rights) -> Result<(), IpcError> {
        if self.count >= IPC_MAX_ENDPOINTS {
            return Err(IpcError::EndpointsFull);
        }
        for slot in self.endpoints.iter_mut() {
            if slot.is_none() {
                *slot = Some(IpcEndpoint::new(id, required_rights));
                self.count += 1;
                return Ok(());
            }
        }
        Err(IpcError::EndpointsFull)
    }

    fn find_mut(&mut self, id: EndpointId) -> Option<&mut IpcEndpoint> {
        self.endpoints
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|ep| ep.id == id)
    }
}

//
// 전역 IPC 레지스트리 인스턴스
//

// SAFETY: 부팅 초기 단일 코어 접근만 허용 (SMP 이후 spinlock 필요)
static mut IPC_REGISTRY: IpcRegistry = IpcRegistry::empty();

//
// 공개 IPC API
//

/// IPC 서브시스템 초기화.
///
/// 커널 내장 서비스 엔드포인트(시스템, 암호화)를 등록함.
///
/// # Safety
/// 부팅 초기 단일 코어에서 한 번만 호출해야 함.
pub unsafe fn init() {
    // SAFETY: 호출자가 단일 코어 초기화를 보장
    let reg = unsafe { &mut *(&raw mut IPC_REGISTRY) };

    // EP_SYSTEM: CALL 권한 필요
    let _ = reg.register(EP_SYSTEM, Rights::CALL);
    // EP_CRYPTO: CALL 권한 필요 (암호화 서비스 진입점)
    let _ = reg.register(EP_CRYPTO, Rights::CALL);
}

/// 메시지를 전송하고 응답을 동기적으로 대기함 (Synchronous Call).
///
/// 발신자는 응답이 게시될 때까지 폴링함 (TODO: 스케줄러 연동 시 실제 블록).
///
/// ## 보안 보장
/// - Capability 검증 후에만 메시지 전달
/// - 응답 페이로드는 `Secret`으로 Drop 시 자동 소거
///
/// # Safety
/// 단일 코어 환경 또는 외부 동기화가 보장된 상태에서만 호출해야 함.
pub unsafe fn ipc_call(
    cap: &Capability,
    msg_type: MessageType,
    payload: &[u8],
) -> Result<IpcMessage, IpcError> {
    let registry = unsafe { &mut *(&raw mut IPC_REGISTRY) };

    // 1. 메시지 구성
    let mut msg = IpcMessage::new(msg_type, 0);
    msg.set_payload(payload)?;

    // 2. 엔드포인트 검색 및 게시
    let ep = registry
        .find_mut(cap.endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;
    ep.post(cap, msg)?;

    // 3. 커널 내부 서비스 동기 디스패치
    // 스케줄러 없는 단일 코어 환경에서 call-reply round-trip 이 교착되지
    // 않도록, 커널이 직접 제공하는 서비스(EP_CRYPTO 등)는 게시 직후 동일
    // 호출 스택에서 핸들러를 실행하여 ReplyReady 상태로 전이시킴
    if is_kernel_service(cap.endpoint_id) {
        match cap.endpoint_id {
            id if id == EP_CRYPTO => {
                // SAFETY: ipc_call 의 호출 조건(단일 코어 / 외부 동기화)을 그대로 상속
                unsafe {
                    crate::crypto_service::dispatch()?;
                }
            }
            // EP_SYSTEM 핸들러는 추후 구현 (시스템 콜 디스패처)
            _ => {}
        }
    }

    // 4. 응답 폴링 (TODO: 스케줄러 yield로 교체)
    // 커널 서비스 엔드포인트는 위 3단계에서 동기적으로 ReplyReady 상태가
    // 되므로 첫 반복에서 take_reply() 가 성공함. 사용자 공간 엔드포인트는
    // 추후 스케줄러가 재개 시점을 관리함
    loop {
        let ep = registry
            .find_mut(cap.endpoint_id)
            .ok_or(IpcError::EndpointNotFound)?;
        if let Ok(reply) = ep.take_reply() {
            return Ok(reply); // 응답 수신 성공 (Secret Drop 적용됨)
        }
        // 안전한 CPU 대기 (인터럽트 발생 시 재확인)
        // SAFETY: hlt는 다음 인터럽트까지 CPU를 일시 정지시키는 안전한 명령
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt", options(nostack, preserves_flags))
        };
    }
}

/// 엔드포인트에서 메시지를 수신함 (서비스측 수신, 비블로킹).
///
/// 대기 중인 메시지가 없으면 `IpcError::NoMessage`를 즉시 반환.
///
/// # Safety
/// 단일 코어 환경 또는 외부 동기화가 보장된 상태에서만 호출해야 함.
pub unsafe fn ipc_recv(endpoint_id: EndpointId) -> Result<IpcMessage, IpcError> {
    let registry = unsafe { &mut *(&raw mut IPC_REGISTRY) };
    let ep = registry
        .find_mut(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;
    ep.take()
}

/// 수신한 메시지에 대한 응답을 게시함 (서비스측 응답).
///
/// `ipc_call()`로 대기 중인 발신자가 응답을 수신할 수 있게 됨.
///
/// # Safety
/// 단일 코어 환경 또는 외부 동기화가 보장된 상태에서만 호출해야 함.
pub unsafe fn ipc_reply(
    endpoint_id: EndpointId,
    reply_type: MessageType,
    payload: &[u8],
) -> Result<(), IpcError> {
    let registry = unsafe { &mut *(&raw mut IPC_REGISTRY) };
    let ep = registry
        .find_mut(endpoint_id)
        .ok_or(IpcError::EndpointNotFound)?;

    let mut reply = IpcMessage::new(reply_type, ep.sequence);
    reply.set_payload(payload)?;
    ep.post_reply(reply)
}

//
// Capability 생성 헬퍼
//

/// 암호화 서비스(EP_CRYPTO)에 대한 CALL Capability를 발급함.
///
/// CLI 바이너리는 이 Capability를 통해서만 암호화 서비스에 접근 가능.
///
/// # Errors
/// `capability::init_prng()` 미호출 / 하드웨어 엔트로피 수집 실패 시
/// `crate::capability::CapError` 반환.
///
/// # Safety
/// 부팅 초기 단일 코어에서 호출해야 함 (DRBG 상태 비원자적 갱신).
pub unsafe fn issue_crypto_capability() -> Result<Capability, crate::capability::CapError> {
    // SAFETY: 호출자가 단일 코어 접근을 보장
    unsafe { crate::capability::generate_capability(EP_CRYPTO, Rights::CALL) }
}

/// 시스템 서비스(EP_SYSTEM)에 대한 CALL Capability를 발급함.
///
/// # Errors
/// [`issue_crypto_capability`] 와 동일.
///
/// # Safety
/// [`issue_crypto_capability`] 와 동일 — 부팅 초기 단일 코어에서 호출해야 함.
pub unsafe fn issue_system_capability() -> Result<Capability, crate::capability::CapError> {
    unsafe { crate::capability::generate_capability(EP_SYSTEM, Rights::CALL) }
}
