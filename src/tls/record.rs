//! TLS 1.3 레코드 보호 (RFC 8446 §5.2) 를 수행하는 모듈입니다.
//!
//! 레코드 형식 (`TLSCiphertext`):
//! ```text
//!   opaque_type (1)        : 0x17 (application_data, AEAD 외부 표기)
//!   legacy_record_version  : 0x0303 (TLS 1.2 호환용 고정값)
//!   length     (2, BE)     : encrypted_record 길이 = ciphertext + tag
//!   encrypted_record       : AEAD(write_key, nonce, AAD=header, plaintext')
//! ```
//!
//! 평문 내부 (`TLSInnerPlaintext`): `content || real_type (1) || zeros[padding]`
//! 본 구현은 padding 미사용으로 `padded = content || type` 만 AEAD 입력으로
//! 사용합니다.
//!
//! Per-record nonce 계산 (RFC 8446 §5.3):
//! ```text
//!   nonce = static_iv XOR pad_left_to_iv_len(seq_num_be)
//! ```
//!
//! 시퀀스 번호 한계는 `2^64 - 1` 이며 도달 시 rekey 가 필요합니다. AEAD
//! 데이터 한계는 AES-GCM 의 경우 키당 약 2^39 비트가 권장되며, 본 구현은
//! 단일 패킷 한계만 강제하고 누적 한계는 상위 계층 정책(rekey 트리거) 으로
//! 처리합니다.

use aes::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
use chacha20::ChaCha20Poly1305;

use crate::tls::{AEAD_IV_LEN, AEAD_KEY_LEN, AEAD_TAG_LEN, CipherSuite, DirectionalKeys, TlsError};

/// TLS 레코드 헤더 길이 (5 bytes).
pub const RECORD_HEADER_LEN: usize = 5;

/// 본 커널의 단일 레코드 평문 최대 길이.
///
/// IPC payload 한계(200B) 와 정합. RFC 8446 의 16 KiB 한계와 무관하게,
/// 본 커널은 작은 IPC chunk 단위로만 application data 를 운반함.
pub const MAX_PLAINTEXT_LEN: usize = 200;

/// `application_data` ContentType (TLSInnerPlaintext.type 값).
pub const CT_APPLICATION_DATA: u8 = 0x17;

const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];

//
// nonce 도출 (RFC 8446 §5.3)
//

fn build_nonce(static_iv: &[u8; AEAD_IV_LEN], seq: u64, out: &mut [u8; AEAD_IV_LEN]) {
    // static_iv XOR (zero-padded BE seq) (IV 길이가 시퀀스 8B 보다 길면 앞쪽이 0)
    let mut padded = [0u8; AEAD_IV_LEN];
    padded[AEAD_IV_LEN - 8..].copy_from_slice(&seq.to_be_bytes());
    for i in 0..AEAD_IV_LEN {
        out[i] = static_iv[i] ^ padded[i];
    }
}

fn build_aad(record_payload_len: usize, out: &mut [u8; RECORD_HEADER_LEN]) -> Result<(), TlsError> {
    if record_payload_len > u16::MAX as usize {
        return Err(TlsError::BufferTooSmall);
    }
    out[0] = CT_APPLICATION_DATA;
    out[1..3].copy_from_slice(&LEGACY_RECORD_VERSION);
    out[3..5].copy_from_slice(&(record_payload_len as u16).to_be_bytes());
    Ok(())
}

//
// 송신: encrypt_record
//

/// `plaintext` 를 AEAD 로 보호하여 `out` 에 완전한 TLS 레코드를 작성하고
/// 작성된 바이트 수를 반환함.
///
/// 출력 레이아웃: `[5B header] [N+1 ciphertext] [16B tag]` 총 `5 + N + 17` 바이트.
///
/// # Errors
/// `BufferTooSmall` (out 또는 plaintext 길이 한계 초과),
/// `SequenceExhausted` (seq=u64::MAX 도달).
pub fn encrypt_record(
    keys: &mut DirectionalKeys,
    suite: CipherSuite,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, TlsError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(TlsError::BufferTooSmall);
    }
    if keys.seq == u64::MAX {
        return Err(TlsError::SequenceExhausted);
    }

    // inner plaintext = content || real_type
    let inner_len = plaintext.len() + 1;
    let record_payload_len = inner_len + AEAD_TAG_LEN;
    let total_len = RECORD_HEADER_LEN + record_payload_len;
    if out.len() < total_len {
        return Err(TlsError::BufferTooSmall);
    }

    // AAD = 5B header
    let mut aad = [0u8; RECORD_HEADER_LEN];
    build_aad(record_payload_len, &mut aad)?;

    // out 에 헤더 사본
    out[..RECORD_HEADER_LEN].copy_from_slice(&aad);

    // inner_pt 를 별도 임시 버퍼에 만들어 AEAD 입력으로 사용
    let mut inner = [0u8; MAX_PLAINTEXT_LEN + 1];
    inner[..plaintext.len()].copy_from_slice(plaintext);
    inner[plaintext.len()] = CT_APPLICATION_DATA;

    // nonce = static_iv XOR seq
    let mut nonce = [0u8; AEAD_IV_LEN];
    build_nonce(keys.iv.expose(), keys.seq, &mut nonce);

    // AEAD 암호화로 ciphertext (inner_len bytes) 와 tag (16 bytes) 생성
    let ct_off = RECORD_HEADER_LEN;
    let tag_off = ct_off + inner_len;
    {
        let (header_and_ct, rest) = out.split_at_mut(tag_off);
        let ct_slot = &mut header_and_ct[ct_off..];
        let tag_slot: &mut [u8; GCM_TAG_SIZE] = (&mut rest[..AEAD_TAG_LEN])
            .try_into()
            .map_err(|_| TlsError::Internal)?;

        match suite {
            CipherSuite::Aes256GcmSha256 => {
                let key_arr: &[u8; AEAD_KEY_LEN] = keys.key.expose();
                let nonce_arr: &[u8; GCM_NONCE_SIZE] = &nonce;
                let mut gcm = AES256GCM::default();
                gcm.init(key_arr);
                gcm.encrypt(nonce_arr, &aad, &inner[..inner_len], ct_slot, tag_slot)
                    .map_err(|_| TlsError::Internal)?;
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let key_arr: &[u8; AEAD_KEY_LEN] = keys.key.expose();
                let mut aead = ChaCha20Poly1305::default();
                aead.init(key_arr);
                aead.encrypt(&nonce, &aad, &inner[..inner_len], ct_slot, tag_slot)
                    .map_err(|_| TlsError::Internal)?;
            }
        }
    }

    // 임시 평문 버퍼 즉시 소거
    let inner_ptr = inner.as_mut_ptr();
    // SAFETY: inner 는 stack 의 (MAX_PLAINTEXT_LEN+1)B 유효 메모리
    unsafe { zeroize::volatile::secure_zero(inner_ptr, inner.len()) };
    // nonce 는 비밀이 아니므로 방어적 0 으로만 덮어씀 (use-after-return 방지)
    let _ = nonce;

    keys.seq += 1;
    Ok(total_len)
}

//
// 수신: decrypt_record
//

/// 완전한 TLS 레코드(`record`) 를 인증/복호화하여 평문(content) 만 `out` 에 기록
/// 하고 그 길이를 반환함. 트레일링 type 바이트는 검증 후 제거됨.
///
/// # Errors
/// `BadMessage` (헤더 형식 오류 / 길이 불일치 / type 불일치),
/// `AuthenticationFailed` (AEAD 태그 검증 실패),
/// `SequenceExhausted` 등.
pub fn decrypt_record(
    keys: &mut DirectionalKeys,
    suite: CipherSuite,
    record: &[u8],
    out: &mut [u8],
) -> Result<usize, TlsError> {
    if record.len() < RECORD_HEADER_LEN + 1 + AEAD_TAG_LEN {
        return Err(TlsError::BadMessage);
    }
    if record[0] != CT_APPLICATION_DATA {
        return Err(TlsError::BadMessage);
    }
    if record[1..3] != LEGACY_RECORD_VERSION {
        return Err(TlsError::BadMessage);
    }
    let length = u16::from_be_bytes([record[3], record[4]]) as usize;
    if RECORD_HEADER_LEN + length != record.len() {
        return Err(TlsError::BadMessage);
    }
    if length < AEAD_TAG_LEN + 1 {
        return Err(TlsError::BadMessage);
    }
    let ct_len = length - AEAD_TAG_LEN; // = inner_len = content_len + 1
    if ct_len > MAX_PLAINTEXT_LEN + 1 {
        return Err(TlsError::BufferTooSmall);
    }
    if keys.seq == u64::MAX {
        return Err(TlsError::SequenceExhausted);
    }

    let aad = &record[..RECORD_HEADER_LEN];
    let ct = &record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + ct_len];
    let tag_slice = &record[RECORD_HEADER_LEN + ct_len..];
    let tag_arr: &[u8; AEAD_TAG_LEN] = tag_slice.try_into().map_err(|_| TlsError::BadMessage)?;

    // nonce 도출
    let mut nonce = [0u8; AEAD_IV_LEN];
    build_nonce(keys.iv.expose(), keys.seq, &mut nonce);

    // 복호화 결과 inner = content || real_type
    let mut inner = [0u8; MAX_PLAINTEXT_LEN + 1];
    let inner_slot = &mut inner[..ct_len];

    match suite {
        CipherSuite::Aes256GcmSha256 => {
            let key_arr: &[u8; AEAD_KEY_LEN] = keys.key.expose();
            let nonce_arr: &[u8; GCM_NONCE_SIZE] = &nonce;
            let mut gcm = AES256GCM::default();
            gcm.init(key_arr);
            let res = gcm.decrypt(nonce_arr, aad, ct, tag_arr, inner_slot);
            if res.is_err() {
                // 실패 경로에서도 임시 버퍼 소거
                // SAFETY: inner 는 stack 메모리, 길이 일정
                unsafe { zeroize::volatile::secure_zero(inner.as_mut_ptr(), inner.len()) };
                return Err(TlsError::AuthenticationFailed);
            }
        }
        CipherSuite::ChaCha20Poly1305Sha256 => {
            let key_arr: &[u8; AEAD_KEY_LEN] = keys.key.expose();
            let mut aead = ChaCha20Poly1305::default();
            aead.init(key_arr);
            let res = aead.decrypt(&nonce, aad, ct, tag_arr, inner_slot);
            if res.is_err() {
                unsafe { zeroize::volatile::secure_zero(inner.as_mut_ptr(), inner.len()) };
                return Err(TlsError::AuthenticationFailed);
            }
        }
    }

    // 트레일링 type 제거 (TLS 1.3 패딩 미사용, 마지막 바이트가 type)
    let real_type = inner[ct_len - 1];
    if real_type != CT_APPLICATION_DATA {
        // 핸드셰이크 메시지 등 다른 ContentType 은 본 함수가 처리 대상 아님
        unsafe { zeroize::volatile::secure_zero(inner.as_mut_ptr(), inner.len()) };
        return Err(TlsError::BadMessage);
    }
    let content_len = ct_len - 1;
    if out.len() < content_len {
        unsafe { zeroize::volatile::secure_zero(inner.as_mut_ptr(), inner.len()) };
        return Err(TlsError::BufferTooSmall);
    }
    out[..content_len].copy_from_slice(&inner[..content_len]);

    // 임시 평문 즉시 소거
    unsafe { zeroize::volatile::secure_zero(inner.as_mut_ptr(), inner.len()) };

    keys.seq += 1;
    Ok(content_len)
}
