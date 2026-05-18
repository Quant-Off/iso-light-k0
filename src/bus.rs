use crate::capability::EndpointId;
use crate::capability::rand_bytes;
use aes::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
use blake::{BLAKE3_OUT_LEN, Blake3};
use zeroize::Secret;
use zeroize::Zeroize;

//
// 상수 / 컴파일-타임 불변식
//

pub const BUS_INSTANCE_MAX: usize = 160; // Phase 3 Plan-01  SoftwareBus + role(1) + Option<SoftHsmAesGcmState>(~48) fit  16B headroom for Phase 5 attestation
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
}

impl Ring3ProcessBus {
    pub const fn new() -> Self {
        Self {
            endpoint: EndpointId::INVALID,
            open_state: false,
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

//
// Phase 3 신규 size pin
//

const _: () = assert!(core::mem::size_of::<SoftHsmRole>() == 1);
const _: () = assert!(SW_BUS_BUF >= BLAKE3_OUT_LEN);
const _: () = assert!(SW_BUS_BUF >= GCM_NONCE_SIZE + GCM_TAG_SIZE);
