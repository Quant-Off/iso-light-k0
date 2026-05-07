use mldsa::MLDSA44;
use zeroize::volatile::secure_zero;
use zeroize::Zeroize;

use crate::capability::EP_SIGN;
use crate::ipc::{
    IPC_MAX_PAYLOAD, IpcError, MessageType, SignPayload, ipc_recv, ipc_reply,
};

//
// 상수
//

/// ML-DSA-44 파라미터 (MLDSA44 impl 에 pub const 로 노출)
const PK_LEN: usize = MLDSA44::PK_LEN;   // 1312
const SK_LEN: usize = MLDSA44::SK_LEN;   // 2560
const SIG_LEN: usize = MLDSA44::SIG_LEN; // 2420

/// 서명 대상 메시지 최대 크기 (keygen seed 포함).
/// `MLDSA44::sign` 내부 m_prime 버퍼 한계(1020B) 고려.
const MSG_BUF_LEN: usize = 1020;

/// keygen 출력 최대 = pk(1312) + sk(2560)
const OUT_BUF_LEN: usize = PK_LEN + SK_LEN; // 3872

/// SignPayload.data 청크 최대 크기
const CHUNK_SIZE: usize = 240;

//
// 세션 상태
//

/// 세션에서 수행할 연산 종류.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Keygen = 1,
    Sign = 2,
    Verify = 3,
}

/// 세션 단계.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    CollectKey,  // key 재료 수집 중
    CollectAux,  // aux 재료 수집 중 (verify: signature)
    CollectMsg,  // 메시지 수집 중
    Ready,       // 실행 대기
    OutputReady, // 출력 준비 완료
}

struct SignSession {
    phase: Phase,
    op: Op,
    // 선언된 크기
    key_total: u32,
    aux_total: u32,
    msg_total: u32,
    // 누적된 크기
    key_recv: u32,
    aux_recv: u32,
    msg_recv: u32,
    // 출력 크기
    out_total: u32,
    // 실행 결과 (Verify)
    verify_ok: bool,
}

impl SignSession {
    const fn idle() -> Self {
        Self {
            phase: Phase::Idle,
            op: Op::Keygen,
            key_total: 0,
            aux_total: 0,
            msg_total: 0,
            key_recv: 0,
            aux_recv: 0,
            msg_recv: 0,
            out_total: 0,
            verify_ok: false,
        }
    }

    fn reset(&mut self) {
        *self = Self::idle();
    }
}

//
// 정적 버퍼 + 세션 상태
//
// SMP 이전 단일 코어 전용. 동시 서명 세션 1개 제한.
//

// key 버퍼: SK_LEN(2560) — Sign 시 sk 또는 Verify 시 pk(1312), Keygen 시 seed(32)
static mut KEY_BUF: [u8; SK_LEN] = [0u8; SK_LEN];
// aux 버퍼: SIG_LEN(2420) — Verify 시 signature
static mut AUX_BUF: [u8; SIG_LEN] = [0u8; SIG_LEN];
// 메시지 버퍼
static mut MSG_BUF: [u8; MSG_BUF_LEN] = [0u8; MSG_BUF_LEN];
// 출력 버퍼: OUT_BUF_LEN(3872)
static mut OUT_BUF: [u8; OUT_BUF_LEN] = [0u8; OUT_BUF_LEN];

static mut SESSION: SignSession = SignSession::idle();

//
// 에러
//

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum SignError {
    InvalidPhase = 1,
    InvalidOp = 2,
    InvalidVariant = 3,
    SizeTooLarge = 4,
    ChunkOverflow = 5,
    ExecFailed = 6,
    VerifyFailed = 7,
    InvalidRequest = 8,
}

//
// SignPayload 파싱
//

fn parse_req(msg: &crate::ipc::IpcMessage) -> Result<SignPayload, SignError> {
    if (msg.header.payload_len as usize) < core::mem::size_of::<SignPayload>() {
        return Err(SignError::InvalidRequest);
    }
    let ptr = msg.payload.data.as_ptr() as *const SignPayload;
    Ok(unsafe { core::ptr::read(ptr) })
}

fn write_sign_reply(
    buf: &mut [u8; IPC_MAX_PAYLOAD],
    phase: u8,
    result: u8,
    offset: u32,
    total: u32,
    data: &[u8],
) {
    let chunk_len = data.len().min(CHUNK_SIZE) as u16;
    let mut sp = SignPayload::zeroed();
    sp.phase = phase;
    sp.result = result;
    sp.offset = offset;
    sp.total = total;
    sp.chunk_len = chunk_len;
    sp.data[..chunk_len as usize].copy_from_slice(&data[..chunk_len as usize]);
    // SAFETY: buf 크기 == size_of::<SignPayload>() == 256
    unsafe {
        core::ptr::write(buf.as_mut_ptr() as *mut SignPayload, sp);
    }
}

//
// 단계별 핸들러
//

fn handle_begin(req: &SignPayload) -> Result<(), SignError> {
    let session = unsafe { &mut *(&raw mut SESSION) };
    if session.phase != Phase::Idle {
        return Err(SignError::InvalidPhase);
    }
    let op = match req.op {
        1 => Op::Keygen,
        2 => Op::Sign,
        3 => Op::Verify,
        _ => return Err(SignError::InvalidOp),
    };
    if req.variant != 1 {
        return Err(SignError::InvalidVariant);
    }
    if req.chunk_len < 12 {
        return Err(SignError::InvalidRequest);
    }
    let key_total = u32::from_le_bytes(req.data[0..4].try_into().unwrap_or([0; 4]));
    let aux_total = u32::from_le_bytes(req.data[4..8].try_into().unwrap_or([0; 4]));
    let msg_total = u32::from_le_bytes(req.data[8..12].try_into().unwrap_or([0; 4]));

    // 크기 상한 검증
    match op {
        Op::Keygen => {
            if key_total > 32 || aux_total != 0 || msg_total != 0 {
                return Err(SignError::SizeTooLarge);
            }
        }
        Op::Sign => {
            if key_total as usize > SK_LEN || aux_total != 0 || msg_total as usize > MSG_BUF_LEN {
                return Err(SignError::SizeTooLarge);
            }
        }
        Op::Verify => {
            if key_total as usize > PK_LEN
                || aux_total as usize > SIG_LEN
                || msg_total as usize > MSG_BUF_LEN
            {
                return Err(SignError::SizeTooLarge);
            }
        }
    }

    session.reset();
    session.phase = if key_total > 0 {
        Phase::CollectKey
    } else if aux_total > 0 {
        Phase::CollectAux
    } else if msg_total > 0 {
        Phase::CollectMsg
    } else {
        Phase::Ready
    };
    session.op = op;
    session.key_total = key_total;
    session.aux_total = aux_total;
    session.msg_total = msg_total;

    // 버퍼 초기화
    // SAFETY: 단일 코어
    unsafe {
        secure_zero((&raw mut KEY_BUF) as *mut u8, SK_LEN);
        secure_zero((&raw mut AUX_BUF) as *mut u8, SIG_LEN);
        secure_zero((&raw mut MSG_BUF) as *mut u8, MSG_BUF_LEN);
        secure_zero((&raw mut OUT_BUF) as *mut u8, OUT_BUF_LEN);
    }
    Ok(())
}

fn handle_in_chunk(req: &SignPayload) -> Result<(), SignError> {
    let session = unsafe { &mut *(&raw mut SESSION) };
    let offset = req.offset as usize;
    let chunk_len = req.chunk_len as usize;
    if chunk_len > CHUNK_SIZE {
        return Err(SignError::ChunkOverflow);
    }

    // 현재 단계에 따라 올바른 버퍼에 쓰기
    match session.phase {
        Phase::CollectKey => {
            let end = offset + chunk_len;
            if end > SK_LEN || end > session.key_total as usize {
                return Err(SignError::ChunkOverflow);
            }
            // SAFETY: 단일 코어
            unsafe {
                let b: &mut [u8; SK_LEN] = &mut *(&raw mut KEY_BUF);
                b[offset..end].copy_from_slice(&req.data[..chunk_len]);
            }
            session.key_recv = end as u32;
            if session.key_recv >= session.key_total {
                session.phase = if session.aux_total > 0 {
                    Phase::CollectAux
                } else if session.msg_total > 0 {
                    Phase::CollectMsg
                } else {
                    Phase::Ready
                };
            }
        }
        Phase::CollectAux => {
            let end = offset + chunk_len;
            if end > SIG_LEN || end > session.aux_total as usize {
                return Err(SignError::ChunkOverflow);
            }
            unsafe {
                let b: &mut [u8; SIG_LEN] = &mut *(&raw mut AUX_BUF);
                b[offset..end].copy_from_slice(&req.data[..chunk_len]);
            }
            session.aux_recv = end as u32;
            if session.aux_recv >= session.aux_total {
                session.phase = if session.msg_total > 0 {
                    Phase::CollectMsg
                } else {
                    Phase::Ready
                };
            }
        }
        Phase::CollectMsg => {
            let end = offset + chunk_len;
            if end > MSG_BUF_LEN || end > session.msg_total as usize {
                return Err(SignError::ChunkOverflow);
            }
            unsafe {
                let b: &mut [u8; MSG_BUF_LEN] = &mut *(&raw mut MSG_BUF);
                b[offset..end].copy_from_slice(&req.data[..chunk_len]);
            }
            session.msg_recv = end as u32;
            if session.msg_recv >= session.msg_total {
                session.phase = Phase::Ready;
            }
        }
        _ => return Err(SignError::InvalidPhase),
    }
    Ok(())
}

fn handle_exec(rnd: &[u8; 32]) -> Result<u32, SignError> {
    let session = unsafe { &mut *(&raw mut SESSION) };
    if session.phase != Phase::Ready {
        return Err(SignError::InvalidPhase);
    }

    let out_total = match session.op {
        Op::Keygen => {
            // seed = KEY_BUF[0..key_total] (또는 전달된 rnd 사용 가능)
            let seed_len = session.key_total as usize;
            let seed: &[u8; 32] = if seed_len == 32 {
                // SAFETY: 단일 코어
                unsafe { &*((&raw const KEY_BUF) as *const [u8; 32]) }
            } else {
                rnd
            };
            let (pk, sk) = MLDSA44::keygen(seed).map_err(|_| SignError::ExecFailed)?;
            // OUT_BUF = pk || sk
            unsafe {
                let b: &mut [u8; OUT_BUF_LEN] = &mut *(&raw mut OUT_BUF);
                b[..PK_LEN].copy_from_slice(&pk);
                b[PK_LEN..PK_LEN + SK_LEN].copy_from_slice(&sk);
            }
            let mut pk_z = pk;
            let mut sk_z = sk;
            pk_z.zeroize();
            sk_z.zeroize();
            (PK_LEN + SK_LEN) as u32
        }
        Op::Sign => {
            let key_len = session.key_total as usize;
            let msg_len = session.msg_total as usize;
            if key_len != SK_LEN {
                return Err(SignError::InvalidRequest);
            }
            let sk: &[u8; SK_LEN] =
                // SAFETY: 단일 코어
                unsafe { &*((&raw const KEY_BUF) as *const [u8; SK_LEN]) };
            let msg: &[u8] = unsafe {
                let b: &[u8; MSG_BUF_LEN] = &*(&raw const MSG_BUF);
                &b[..msg_len]
            };
            let sig = MLDSA44::sign(sk, msg, &[], rnd).map_err(|_| SignError::ExecFailed)?;
            unsafe {
                let b: &mut [u8; OUT_BUF_LEN] = &mut *(&raw mut OUT_BUF);
                b[..SIG_LEN].copy_from_slice(&sig);
            }
            let mut sig_z = sig;
            sig_z.zeroize();
            SIG_LEN as u32
        }
        Op::Verify => {
            let pk_len = session.key_total as usize;
            let sig_len = session.aux_total as usize;
            let msg_len = session.msg_total as usize;
            if pk_len != PK_LEN || sig_len != SIG_LEN {
                return Err(SignError::InvalidRequest);
            }
            let pk: &[u8; PK_LEN] =
                unsafe { &*((&raw const KEY_BUF) as *const [u8; PK_LEN]) };
            let sig: &[u8; SIG_LEN] =
                unsafe { &*((&raw const AUX_BUF) as *const [u8; SIG_LEN]) };
            let msg: &[u8] = unsafe {
                let b: &[u8; MSG_BUF_LEN] = &*(&raw const MSG_BUF);
                &b[..msg_len]
            };
            let ok = MLDSA44::verify(pk, msg, sig, &[]).map_err(|_| SignError::ExecFailed)?;
            session.verify_ok = ok;
            if !ok {
                return Err(SignError::VerifyFailed);
            }
            // 검증 결과: OUT_BUF[0] = 1(성공)
            unsafe {
                let b: &mut [u8; OUT_BUF_LEN] = &mut *(&raw mut OUT_BUF);
                b[0] = 1u8;
            }
            1u32
        }
    };

    // 민감 입력 버퍼 즉시 소거
    unsafe {
        secure_zero((&raw mut KEY_BUF) as *mut u8, SK_LEN);
        secure_zero((&raw mut AUX_BUF) as *mut u8, SIG_LEN);
        secure_zero((&raw mut MSG_BUF) as *mut u8, MSG_BUF_LEN);
    }

    session.out_total = out_total;
    session.phase = Phase::OutputReady;
    Ok(out_total)
}

fn handle_out_chunk(
    req: &SignPayload,
    reply_data: &mut [u8; CHUNK_SIZE],
    chunk_out_len: &mut u16,
) -> Result<(), SignError> {
    let session = unsafe { &mut *(&raw mut SESSION) };
    if session.phase != Phase::OutputReady {
        return Err(SignError::InvalidPhase);
    }
    let offset = req.offset as usize;
    let total = session.out_total as usize;
    if offset >= total {
        *chunk_out_len = 0;
        return Ok(());
    }
    let avail = total - offset;
    let take = avail.min(CHUNK_SIZE);
    // SAFETY: 단일 코어
    unsafe {
        let src: &[u8; OUT_BUF_LEN] = &*(&raw const OUT_BUF);
        reply_data[..take].copy_from_slice(&src[offset..offset + take]);
    }
    *chunk_out_len = take as u16;
    Ok(())
}

fn handle_end() {
    let session = unsafe { &mut *(&raw mut SESSION) };
    // 출력 버퍼 소거 + 세션 리셋
    unsafe {
        secure_zero((&raw mut OUT_BUF) as *mut u8, OUT_BUF_LEN);
        secure_zero((&raw mut KEY_BUF) as *mut u8, SK_LEN);
        secure_zero((&raw mut AUX_BUF) as *mut u8, SIG_LEN);
        secure_zero((&raw mut MSG_BUF) as *mut u8, MSG_BUF_LEN);
    }
    session.reset();
}

//
// 디스패처
//

/// EP_SIGN 엔드포인트의 ML-DSA 청크 프로토콜 요청을 처리함.
///
/// # Safety
/// `ipc::init()` 및 `capability::init_prng()` 호출 이후에만 안전.
/// 단일 코어 또는 외부 동기화 보장 상태에서만 호출.
pub unsafe fn dispatch() -> Result<(), IpcError> {
    // SAFETY: 호출자가 단일 코어 보장
    let msg = unsafe { ipc_recv(EP_SIGN)? };

    let req = match parse_req(&msg) {
        Ok(r) => r,
        Err(_) => {
            let mut reply_buf = [0u8; IPC_MAX_PAYLOAD];
            write_sign_reply(&mut reply_buf, 0, SignError::InvalidRequest as u8, 0, 0, &[]);
            unsafe {
                ipc_reply(EP_SIGN, MessageType::Error, &reply_buf)?;
            }
            return Ok(());
        }
    };

    let (reply_type, result_code, reply_offset, reply_total, reply_data_len, mut chunk_buf): (
        MessageType,
        u8,
        u32,
        u32,
        u16,
        [u8; CHUNK_SIZE],
    ) = match msg.header.msg_type {
        MessageType::SignBeginReq => {
            match handle_begin(&req) {
                Ok(()) => (MessageType::SignBeginResp, 0, 0, 0, 4, {
                    let mut b = [0u8; CHUNK_SIZE];
                    b[0..4].copy_from_slice(&(CHUNK_SIZE as u32).to_le_bytes());
                    b
                }),
                Err(e) => (MessageType::Error, e as u8, 0, 0, 0, [0u8; CHUNK_SIZE]),
            }
        }
        MessageType::SignInChunkReq => match handle_in_chunk(&req) {
            Ok(()) => {
                let session = unsafe { &*(&raw const SESSION) };
                let recv_total = session.key_recv + session.aux_recv + session.msg_recv;
                (
                    MessageType::SignInChunkResp,
                    0,
                    recv_total,
                    0,
                    0,
                    [0u8; CHUNK_SIZE],
                )
            }
            Err(e) => (MessageType::Error, e as u8, 0, 0, 0, [0u8; CHUNK_SIZE]),
        },
        MessageType::SignExecReq => {
            // rnd: 커널 DRBG 에서 32바이트 추출
            let mut rnd = [0u8; 32];
            // SAFETY: 호출자가 단일 코어 보장, init_prng 완료
            let rnd_ok = unsafe { crate::capability::rand_bytes(&mut rnd) };
            let exec_result = if rnd_ok.is_ok() {
                handle_exec(&rnd)
            } else {
                Err(SignError::ExecFailed)
            };
            rnd.zeroize();
            match exec_result {
                Ok(out_total) => (
                    MessageType::SignExecResp,
                    0,
                    0,
                    out_total,
                    0,
                    [0u8; CHUNK_SIZE],
                ),
                Err(e) => (MessageType::Error, e as u8, 0, 0, 0, [0u8; CHUNK_SIZE]),
            }
        }
        MessageType::SignOutChunkReq => {
            let mut out_chunk = [0u8; CHUNK_SIZE];
            let mut out_len: u16 = 0;
            match handle_out_chunk(&req, &mut out_chunk, &mut out_len) {
                Ok(()) => {
                    let session = unsafe { &*(&raw const SESSION) };
                    (
                        MessageType::SignOutChunkResp,
                        0,
                        req.offset,
                        session.out_total,
                        out_len,
                        out_chunk,
                    )
                }
                Err(e) => (MessageType::Error, e as u8, 0, 0, 0, [0u8; CHUNK_SIZE]),
            }
        }
        MessageType::SignEndReq => {
            handle_end();
            (MessageType::SignEndResp, 0, 0, 0, 0, [0u8; CHUNK_SIZE])
        }
        _ => (
            MessageType::Error,
            SignError::InvalidRequest as u8,
            0,
            0,
            0,
            [0u8; CHUNK_SIZE],
        ),
    };

    // 응답 페이로드 조립
    let mut reply_buf = [0u8; IPC_MAX_PAYLOAD];
    write_sign_reply(
        &mut reply_buf,
        req.phase,
        result_code,
        reply_offset,
        reply_total,
        &chunk_buf[..reply_data_len as usize],
    );
    // 출력 청크 버퍼 소거 (민감 데이터 포함 가능)
    // SAFETY: chunk_buf 는 stack 의 CHUNK_SIZE 바이트 유효 메모리
    unsafe {
        secure_zero(chunk_buf.as_mut_ptr(), CHUNK_SIZE);
    }

    // SAFETY: 호출자가 단일 코어 보장, ipc::init 이후
    unsafe {
        ipc_reply(
            EP_SIGN,
            reply_type,
            &reply_buf[..core::mem::size_of::<SignPayload>()],
        )?;
    }
    Ok(())
}
