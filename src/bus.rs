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
// SoftwareBus — Task 1 placeholder (Task 2 가 본문 + impls 채움).
//

pub struct SoftwareBus {
    _phantom: (),
}

impl SoftwareBus {
    pub const fn new() -> Self {
        Self { _phantom: () }
    }
}

//
// Ring3ProcessBus — Task 1 placeholder (Task 2 가 endpoint 바인딩 + impls 채움).
//

pub struct Ring3ProcessBus {
    _phantom: (),
}

impl Ring3ProcessBus {
    pub const fn new() -> Self {
        Self { _phantom: () }
    }
}

// 본 stub 은 Task 2 에서 실제 endpoint 디코드 로직과 함께 사용됨.
// Plan 02 가 ipc::endpoint_exists(id) 로 교체.
#[inline]
#[allow(dead_code)]
fn endpoint_exists_stub(id: EndpointId) -> bool {
    id != EndpointId::INVALID
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

// Task 1 의 placeholder 페이로드용 Zeroize impl — Task 2 가 실제 본문에 맞춰 교체.
impl Zeroize for SoftwareBus {
    fn zeroize(&mut self) {
        self._phantom = ();
    }
}

impl Zeroize for Ring3ProcessBus {
    fn zeroize(&mut self) {
        self._phantom = ();
    }
}

// Task 1 placeholder BusDriver impls — Task 2 가 실제 본문에 맞춰 교체.
impl BusDriver for SoftwareBus {
    fn open(&mut self, _init: &[u8]) -> Result<(), BusError> {
        Err(BusError::NotImplemented)
    }
    fn close(&mut self) -> Result<(), BusError> {
        Err(BusError::NotImplemented)
    }
    fn read(&mut self, _out: &mut [u8]) -> Result<usize, BusError> {
        Err(BusError::NotImplemented)
    }
    fn write(&mut self, _data: &[u8]) -> Result<usize, BusError> {
        Err(BusError::NotImplemented)
    }
    fn poll(&mut self) -> Result<BusReady, BusError> {
        Err(BusError::NotImplemented)
    }
    fn kind(&self) -> BusKind {
        BusKind::Software
    }
}

impl BusDriver for Ring3ProcessBus {
    fn open(&mut self, _init: &[u8]) -> Result<(), BusError> {
        Err(BusError::NotImplemented)
    }
    fn close(&mut self) -> Result<(), BusError> {
        Err(BusError::NotImplemented)
    }
    fn read(&mut self, _out: &mut [u8]) -> Result<usize, BusError> {
        Err(BusError::NotImplemented)
    }
    fn write(&mut self, _data: &[u8]) -> Result<usize, BusError> {
        Err(BusError::NotImplemented)
    }
    fn poll(&mut self) -> Result<BusReady, BusError> {
        Err(BusError::NotImplemented)
    }
    fn kind(&self) -> BusKind {
        BusKind::Ring3Process
    }
}

//
// 컴파일-타임 사이즈 핀 (D-02). BusInstance 정의 뒤에 두어 타입 in-scope 보장.
//

const _: () = assert!(core::mem::size_of::<BusKind>() == 1);
const _: () = assert!(core::mem::size_of::<BusInstance>() <= BUS_INSTANCE_MAX);
