//! 핸드셰이크 트랜스크립트(RFC 8446 §4.4.1 의 `Transcript-Hash`) 를 관리하는
//! 모듈입니다.
//!
//! 핸드셰이크 메시지를 순서대로 누적한 뒤, 임의 시점에 SHA-256 해시를
//! 계산하여 binder / Finished MAC / 트래픽 키 도출의 입력으로 사용합니다.
//!
//! ## 구현 노트
//! `elib-k0-nt::sha2::SHA256` 의 `finalize()` 가 self 를 소비하므로, 동일
//! 트랜스크립트에 대해 여러 시점의 해시를 얻기 위해 메시지 바이트 자체를
//! `Secret<>` 버퍼에 누적하고 매 호출마다 새 해시를 계산하는 단순 모델을
//! 사용합니다. TLS 1.3 PSK 핸드셰이크의 트랜스크립트는 PQ-hybrid 의 ML-KEM
//! share 까지 포함해도 4 KiB 이하이므로 본 구조로 충분합니다.

use sha2::{SHA2, SHA256};
use zeroize::Secret;
use zeroize::volatile::secure_zero;

use crate::tls::{TLS_HASH_LEN, TRANSCRIPT_BUF_LEN, TlsError};

pub struct Transcript {
    /// 누적 핸드셰이크 바이트.
    /// 메시지 자체는 비밀이 아니지만(공개 채널 송수신), Secret 보호로
    /// Drop 시 메모리 잔존을 차단하여 사이드채널 표면을 줄임.
    buf: Secret<[u8; TRANSCRIPT_BUF_LEN]>,
    len: usize,
}

#[allow(clippy::new_without_default)]
impl Transcript {
    pub fn new() -> Self {
        Self {
            buf: Secret::new([0u8; TRANSCRIPT_BUF_LEN]),
            len: 0,
        }
    }

    /// 메시지 바이트를 누적.
    ///
    /// # Errors
    /// 누적 길이가 `TRANSCRIPT_BUF_LEN` 을 초과하면 `TranscriptOverflow`.
    pub fn update(&mut self, msg: &[u8]) -> Result<(), TlsError> {
        if self.len.saturating_add(msg.len()) > TRANSCRIPT_BUF_LEN {
            return Err(TlsError::TranscriptOverflow);
        }
        let dst = &mut self.buf.expose_mut()[self.len..self.len + msg.len()];
        dst.copy_from_slice(msg);
        self.len += msg.len();
        Ok(())
    }

    /// 현재 누적 상태에 대한 SHA-256 해시 반환 (비파괴 스냅샷).
    pub fn snapshot(&self) -> [u8; TLS_HASH_LEN] {
        let mut h = SHA256::new();
        h.update(&self.buf.expose()[..self.len]);
        let digest = h.finalize();
        let mut out = [0u8; TLS_HASH_LEN];
        out.copy_from_slice(&digest.as_bytes()[..TLS_HASH_LEN]);
        out
    }

    /// 현재 누적 길이 (디버그 / 한계 검사용).
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 트랜스크립트 메시지 + 카운터 즉시 소거.
    pub fn wipe(&mut self) {
        // SAFETY: buf 는 TRANSCRIPT_BUF_LEN 바이트의 유효 메모리
        unsafe {
            secure_zero(self.buf.expose_mut().as_mut_ptr(), TRANSCRIPT_BUF_LEN);
        }
        self.len = 0;
    }
}
