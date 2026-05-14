use crate::capability::EndpointId;
use zeroize::Zeroize;

//
// 상수 / 컴파일-타임 불변식
//

pub const BUS_INSTANCE_MAX: usize = 96; // PLANNER CHOICE Plan-01 (RESEARCH §2: SoftwareBus exact fit)
pub const MAX_BUS_INIT_BLOB: usize = 32; // PLANNER CHOICE Plan-01 (RESEARCH §12 #2)
pub const SW_BUS_BUF: usize = 64; // PLANNER CHOICE Plan-01 (RESEARCH §12 #3)

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
// SoftwareBus — 64-byte 루프백 echo (D-10). 비밀 페이로드 아님, 그러나 Phase 1 일관성으로 zeroize 명시.
//

pub struct SoftwareBus {
    ring: [u8; SW_BUS_BUF],
    write_len: usize,
    read_pos: usize,
    open_state: bool,
}

impl SoftwareBus {
    pub const fn new() -> Self {
        Self {
            ring: [0u8; SW_BUS_BUF],
            write_len: 0,
            read_pos: 0,
            open_state: false,
        }
    }
}

impl BusDriver for SoftwareBus {
    fn open(&mut self, _init: &[u8]) -> Result<(), BusError> {
        if self.open_state {
            return Err(BusError::AlreadyOpen);
        }
        // D-10: _init 슬라이스 무시 (loopback echo 는 init 없음).
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
        // Pitfall 6 — overflow 는 정직한 에러로 surface, silent drop 금지.
        if data.len() > SW_BUS_BUF.saturating_sub(self.write_len) {
            return Err(BusError::BufferTooSmall);
        }
        self.ring[self.write_len..self.write_len + data.len()].copy_from_slice(data);
        self.write_len += data.len();
        Ok(data.len())
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

impl Zeroize for SoftwareBus {
    fn zeroize(&mut self) {
        // bytes-first, metadata-last (I-3 token-first ordering 일관)
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
}

impl Ring3ProcessBus {
    pub const fn new() -> Self {
        Self {
            endpoint: EndpointId::INVALID,
            open_state: false,
        }
    }
}

// Plan-01 임시 stub — Plan 02 가 ipc::endpoint_exists(id) 로 교체.
#[inline]
fn endpoint_exists_stub(id: EndpointId) -> bool {
    id != EndpointId::INVALID
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
        if !endpoint_exists_stub(endpoint) {
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

    fn read(&mut self, _out: &mut [u8]) -> Result<usize, BusError> {
        // D-12 / D-14: Phase 4 가 본 메서드 본문을 wire frame decode 로 교체.
        Err(BusError::WireNotReady)
    }

    fn write(&mut self, _data: &[u8]) -> Result<usize, BusError> {
        Err(BusError::WireNotReady)
    }

    fn poll(&mut self) -> Result<BusReady, BusError> {
        Err(BusError::WireNotReady)
    }

    fn kind(&self) -> BusKind {
        BusKind::Ring3Process
    }
}

impl Zeroize for Ring3ProcessBus {
    fn zeroize(&mut self) {
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
