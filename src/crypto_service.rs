//! EP_CRYPTO 엔드포인트의 실제 암호화 서비스를 수행하는 모듈입니다.
//!
//! CLI / 사용자 태스크가 `ipc_call(crypto_cap, EncryptReq, p)` 를 호출하면
//! 커널이 메시지를 게시한 뒤 `dispatch()` 가 동일 호출 스택에서 실행됩니다.
//! 디스패처는 EP_CRYPTO 큐에서 메시지를 꺼내 `Secret<CryptoPayload>` 로
//! 파싱하고, 알고리즘에 따라 AES-256-GCM, ChaCha20-Poly1305, SHA-256/BLAKE3,
//! HKDF-SHA256 분기 중 하나로 분기합니다. 결과는 `Secret<ReplyBuf>` 에 적은
//! 후 `ipc_reply(EP_CRYPTO, ..)` 로 호출자에게 반환됩니다.
//!
//! 보안 불변식은 다음과 같습니다.
//!   1. 모든 키 / 평문 / 중간 버퍼는 `Secret<T>` 로 래핑되어 Drop 시 자동 소거
//!   2. Capability 검증 및 tag 비교는 constant-time
//!   3. 암/복호화 실패 시 결과 버퍼와 내부 상태를 즉시 zeroize
//!   4. 처리 중 발생한 평문이 메시지 응답 외 경로로 유출되지 않음

use aes::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
use blake::Blake3;
use chacha20::ChaCha20Poly1305;
use ed25519::{PublicKey as Ed25519Pk, SecretKey as Ed25519Sk, Signature as Ed25519Sig};
use ed448::{PublicKey as Ed448Pk, SecretKey as Ed448Sk, Signature as Ed448Sig};
use sha2::{SHA2, SHA256};
use sha3::{SHA3, SHA3_256, SHA3_512};
use x448::{PublicKey as X448Pk, SecretKey as X448Sk};
use zeroize::volatile::secure_zero;
use zeroize::{Secret, Zeroize};

use crate::capability::EP_CRYPTO;
use crate::ipc::{
    CRYPTO_DATA_LEN, CRYPTO_DATA_OFFSET, CryptoAlgo, CryptoPayload, IPC_MAX_PAYLOAD, IpcError,
    IpcMessage, MessageType, ipc_recv, ipc_reply,
};

//
// 상수
//

pub(crate) const SHA256_BLOCK_SIZE: usize = 64;
pub(crate) const SHA256_OUTPUT_SIZE: usize = 32;
const SHA3_256_OUTPUT_SIZE: usize = 32;
const SHA3_512_OUTPUT_SIZE: usize = 64;
const BLAKE3_OUTPUT_SIZE: usize = 32;
const AES256_KEY_SIZE: usize = 32;
const CHACHA20_KEY_SIZE: usize = 32;
const ED25519_SK_SIZE: usize = ed25519::SECRET_KEY_LENGTH; // 32
const ED25519_PK_SIZE: usize = ed25519::PUBLIC_KEY_LENGTH; // 32
const ED25519_SIG_SIZE: usize = ed25519::SIGNATURE_LENGTH; // 64
const ED448_SK_SIZE: usize = ed448::SECRET_KEY_LENGTH;     // 57
const ED448_PK_SIZE: usize = ed448::PUBLIC_KEY_LENGTH;     // 57
const ED448_SIG_SIZE: usize = ed448::SIGNATURE_LENGTH;     // 114
const X448_SK_SIZE: usize = 56;
const X448_PK_SIZE: usize = 56;

/// HKDF-Expand 한 번에 허용되는 최대 출력 (RFC 5869 상한은 255×32, 여기선 data 필드 한계).
const HKDF_MAX_OUTPUT: usize = CRYPTO_DATA_LEN; // 168

//
// 서비스 에러
//

/// 암호 서비스 내부 에러.
///
/// 응답 메시지는 항상 성공/실패 표시 바이트를 포함하며, 상세 오류 정보는
/// 사이드채널이 되지 않도록 최소한만 노출됨.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptoError {
    UnknownAlgorithm = 1,
    InvalidKeyLength = 2,
    InvalidNonceLength = 3,
    InvalidDataLength = 4,
    AuthenticationFailed = 5,
    InvalidRequest = 6,
    OutputTooLarge = 7,
    WeakNonce = 8,
}

//
// CryptoPayload 직렬화 헬퍼
//

/// IPC 메시지 페이로드를 `CryptoPayload` 로 파싱함.
///
/// `CryptoPayload`는 `#[repr(C)]` 256바이트, `RawPayload`는 `align(8)` 256바이트
/// 이므로 안전하게 캐스팅 가능. 복사된 결과는 `Secret<T>` 로 감싸 스코프 종료시
/// 자동 소거됨.
fn parse_request(msg: &IpcMessage) -> Result<Secret<CryptoPayload>, CryptoError> {
    if (msg.header.payload_len as usize) < core::mem::size_of::<CryptoPayload>() {
        return Err(CryptoError::InvalidRequest);
    }
    // SAFETY: RawPayload.data 는 align(8), CryptoPayload 도 repr(C) 8-align,
    //         총 256바이트로 레이아웃 일치
    let ptr = msg.payload.data.as_ptr() as *const CryptoPayload;
    let cp = unsafe { core::ptr::read(ptr) };
    Ok(Secret::new(cp))
}

/// 응답용 빈 페이로드.
fn new_reply_buf() -> Secret<[u8; IPC_MAX_PAYLOAD]> {
    Secret::new([0u8; IPC_MAX_PAYLOAD])
}

/// 에러 응답 페이로드를 조립 (1 바이트 에러 코드).
fn write_error_reply(buf: &mut [u8; IPC_MAX_PAYLOAD], err: CryptoError) {
    // 나머지 바이트는 0 유지
    buf[0] = err as u8;
}

/// 성공 응답 페이로드를 조립 — CryptoPayload 레이아웃 재사용.
///
/// - `algo`      : 요청된 알고리즘 식별자 (에코)
/// - `data`      : 결과 바이트 (ciphertext+tag, plaintext, digest, derived key 등)
/// - `data_len`  : 결과 길이
fn write_ok_reply(
    buf: &mut [u8; IPC_MAX_PAYLOAD],
    algo: u8,
    data: &[u8],
) -> Result<(), CryptoError> {
    if data.len() > CRYPTO_DATA_LEN {
        return Err(CryptoError::OutputTooLarge);
    }
    // SAFETY: buf는 align(8) 보장 없음 -> unaligned write 로 CryptoPayload 필드를 채움
    //         fixed offsets 에 직접 기록함 (CRYPTO_DATA_OFFSET = 88)
    buf[0] = algo; // algo
    buf[1] = 0; // key_len (응답엔 키 없음)
    buf[2] = 0; // nonce_len
    buf[3] = 0; // flags (0 = success)
    buf[4..6].copy_from_slice(&(data.len() as u16).to_le_bytes()); // data_len
    // buf[6..8]   reserved
    // buf[8..72]  key[64]  = 0 (이미 Secret::new([0u8;...]) 로 초기화됨)
    // buf[72..84] nonce    = 0
    // buf[84..88] pad      = 0
    buf[CRYPTO_DATA_OFFSET..CRYPTO_DATA_OFFSET + data.len()].copy_from_slice(data);
    Ok(())
}

//
// HMAC-SHA256
//

/// HMAC-SHA256 — RFC 2104.
///
/// `data_chunks` 는 순서대로 연결된 메시지로 간주됨 (HKDF 내부에서 T(i-1) ‖ info ‖ i
/// 를 계산할 때 할당 없이 streaming 연결을 위함).
///
/// 내부 `ipad`/`opad`/`key_block` 은 Secret 로 래핑되어 Drop 시 자동 소거됨.
///
/// # Security Note
/// 이 구현은 HMAC 자체의 상수-시간 속성에 의존하지 않음. HMAC 출력은 태그로
/// 외부와 비교될 때만 CT 비교가 필요하며, 호출자가 `constant_time::CtEqOps`
/// 또는 `blake::ct_eq_slice` 로 직접 수행해야 함.
pub(crate) fn hmac_sha256_multi(
    key: &[u8],
    data_chunks: &[&[u8]],
    out: &mut [u8; SHA256_OUTPUT_SIZE],
) {
    let mut key_block = Secret::new([0u8; SHA256_BLOCK_SIZE]);

    if key.len() > SHA256_BLOCK_SIZE {
        let mut h = SHA256::new();
        h.update(key);
        let d = h.finalize();
        key_block.expose_mut()[..SHA256_OUTPUT_SIZE].copy_from_slice(d.as_bytes());
    } else {
        key_block.expose_mut()[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Secret::new([0x36u8; SHA256_BLOCK_SIZE]);
    let mut opad = Secret::new([0x5cu8; SHA256_BLOCK_SIZE]);
    for i in 0..SHA256_BLOCK_SIZE {
        ipad.expose_mut()[i] ^= key_block.expose()[i];
        opad.expose_mut()[i] ^= key_block.expose()[i];
    }

    // inner = SHA256(ipad || data...)
    let mut inner_h = SHA256::new();
    inner_h.update(ipad.expose());
    for chunk in data_chunks {
        inner_h.update(chunk);
    }
    let inner = inner_h.finalize();

    // outer = SHA256(opad || inner)
    let mut outer_h = SHA256::new();
    outer_h.update(opad.expose());
    outer_h.update(inner.as_bytes());
    let outer = outer_h.finalize();

    out.copy_from_slice(outer.as_bytes());
    // Secret drop 이 key_block/ipad/opad 소거 — 명시적 zeroize 불필요
}

//
// HKDF-SHA256 (RFC 5869)
//

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
pub(crate) fn hkdf_extract(salt: &[u8], ikm: &[u8], prk: &mut [u8; SHA256_OUTPUT_SIZE]) {
    hmac_sha256_multi(salt, &[ikm], prk);
}

/// HKDF-Expand: OKM = T(1) ‖ T(2) ‖ ... ‖ T(N), where
///   T(1) = HMAC(PRK, info ‖ 0x01)
///   T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)
pub(crate) fn hkdf_expand(
    prk: &[u8; SHA256_OUTPUT_SIZE],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    if okm.len() > HKDF_MAX_OUTPUT {
        return Err(CryptoError::OutputTooLarge);
    }
    if okm.len() > 255 * SHA256_OUTPUT_SIZE {
        return Err(CryptoError::OutputTooLarge);
    }

    // t_prev = T(i-1) (빈 시퀀스로 시작), t_curr = T(i) 계산 대상
    // 두 버퍼를 분리해 borrow checker 충돌(동시 immut/mut) 회피
    let mut t_prev = Secret::new([0u8; SHA256_OUTPUT_SIZE]);
    let mut t_curr = Secret::new([0u8; SHA256_OUTPUT_SIZE]);
    let mut prev_len = 0usize; // 0 -> 첫 반복은 T(i-1) 미포함
    let mut produced = 0usize;
    let mut counter: u8 = 1;

    while produced < okm.len() {
        let ctr_bytes = [counter];
        if prev_len == 0 {
            // T(1) = HMAC(PRK, info ‖ 0x01)
            hmac_sha256_multi(prk, &[info, &ctr_bytes], t_curr.expose_mut());
        } else {
            // T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)
            hmac_sha256_multi(
                prk,
                &[&t_prev.expose()[..prev_len], info, &ctr_bytes],
                t_curr.expose_mut(),
            );
        }
        let take = core::cmp::min(SHA256_OUTPUT_SIZE, okm.len() - produced);
        okm[produced..produced + take].copy_from_slice(&t_curr.expose()[..take]);
        produced += take;

        // T(i) -> T(i-1) 슬롯으로 회전 (t_prev = t_curr)
        t_prev.expose_mut().copy_from_slice(t_curr.expose());
        prev_len = SHA256_OUTPUT_SIZE;

        counter = counter.wrapping_add(1);
    }

    Ok(())
}

//
// AEAD 핸들러
//

fn handle_encrypt(
    req: &CryptoPayload,
    reply: &mut [u8; IPC_MAX_PAYLOAD],
) -> Result<(), CryptoError> {
    let algo = parse_algo(req.algo)?;
    let data_len = req.data_len as usize;
    if data_len > CRYPTO_DATA_LEN {
        return Err(CryptoError::InvalidDataLength);
    }

    // 평문 / 키 / nonce 를 Secret 에 복사 (스택 상의 작업 메모리 자동 소거)
    let mut plaintext = Secret::new([0u8; CRYPTO_DATA_LEN]);
    plaintext.expose_mut()[..data_len].copy_from_slice(&req.data[..data_len]);

    let mut ciphertext = Secret::new([0u8; CRYPTO_DATA_LEN]);
    let mut tag = [0u8; GCM_TAG_SIZE]; // GCM_TAG_SIZE == Poly1305 태그 == 16

    let enc_result: Result<usize, CryptoError> = match algo {
        CryptoAlgo::Aes256Gcm => {
            encrypt_aes256gcm(req, &plaintext, data_len, &mut ciphertext, &mut tag)
        }
        CryptoAlgo::ChaCha20Poly => {
            encrypt_chacha20poly(req, &plaintext, data_len, &mut ciphertext, &mut tag)
        }
        _ => Err(CryptoError::UnknownAlgorithm),
    };

    match enc_result {
        Ok(ct_len) => {
            // 응답: ciphertext ‖ tag (ct_len + 16 bytes)
            // ct_len 은 평문 길이와 동일 (AEAD)
            let total = ct_len + GCM_TAG_SIZE;
            if total > CRYPTO_DATA_LEN {
                // 응답 버퍼 초과 — 실패로 전환 및 소거
                ciphertext.expose_mut().zeroize();
                tag.zeroize();
                return Err(CryptoError::OutputTooLarge);
            }
            let mut out = Secret::new([0u8; CRYPTO_DATA_LEN]);
            out.expose_mut()[..ct_len].copy_from_slice(&ciphertext.expose()[..ct_len]);
            out.expose_mut()[ct_len..total].copy_from_slice(&tag);
            let r = write_ok_reply(reply, req.algo, &out.expose()[..total]);
            tag.zeroize();
            r
        }
        Err(e) => {
            // 실패 시 중간 버퍼 즉시 소거
            ciphertext.expose_mut().zeroize();
            tag.zeroize();
            Err(e)
        }
    }
}

fn handle_decrypt(
    req: &CryptoPayload,
    reply: &mut [u8; IPC_MAX_PAYLOAD],
) -> Result<(), CryptoError> {
    let algo = parse_algo(req.algo)?;
    let data_len = req.data_len as usize;
    // data = ciphertext ‖ tag
    if !(GCM_TAG_SIZE..=CRYPTO_DATA_LEN).contains(&data_len) {
        return Err(CryptoError::InvalidDataLength);
    }
    let ct_len = data_len - GCM_TAG_SIZE;

    let mut tag = [0u8; GCM_TAG_SIZE];
    tag.copy_from_slice(&req.data[ct_len..data_len]);

    let mut ciphertext = Secret::new([0u8; CRYPTO_DATA_LEN]);
    ciphertext.expose_mut()[..ct_len].copy_from_slice(&req.data[..ct_len]);

    let mut plaintext = Secret::new([0u8; CRYPTO_DATA_LEN]);

    let dec_result: Result<(), CryptoError> = match algo {
        CryptoAlgo::Aes256Gcm => decrypt_aes256gcm(req, &ciphertext, ct_len, &tag, &mut plaintext),
        CryptoAlgo::ChaCha20Poly => {
            decrypt_chacha20poly(req, &ciphertext, ct_len, &tag, &mut plaintext)
        }
        _ => Err(CryptoError::UnknownAlgorithm),
    };

    match dec_result {
        Ok(()) => {
            let r = write_ok_reply(reply, req.algo, &plaintext.expose()[..ct_len]);
            // plaintext Secret drop 으로 소거되며, explicit 호출 불필요
            r
        }
        Err(e) => {
            // 인증 실패 등으로 plaintext 버퍼(및 tag) 즉시 강제 소거
            plaintext.expose_mut().zeroize();
            tag.zeroize();
            Err(e)
        }
    }
}

fn encrypt_aes256gcm(
    req: &CryptoPayload,
    plaintext: &Secret<[u8; CRYPTO_DATA_LEN]>,
    pt_len: usize,
    ciphertext: &mut Secret<[u8; CRYPTO_DATA_LEN]>,
    tag: &mut [u8; GCM_TAG_SIZE],
) -> Result<usize, CryptoError> {
    if req.key_len as usize != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength);
    }
    if req.nonce_len as usize != GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLength);
    }

    let mut key = Secret::new([0u8; AES256_KEY_SIZE]);
    key.expose_mut()
        .copy_from_slice(&req.key[..AES256_KEY_SIZE]);
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    nonce.copy_from_slice(&req.nonce[..GCM_NONCE_SIZE]);

    // M3 GCM 논스 재사용은 GHASH 키 복원과 보편적 위조로 직결됨
    // 전 유일성 강제는 와이어 계약 변경(커널측 논스 생성) 필요 사항이나
    // 최소한 명백한 오용인 전영(all-zero) 논스는 암호화 시점에 거부함
    if nonce.iter().all(|&b| b == 0) {
        nonce.zeroize();
        key.expose_mut().zeroize();
        return Err(CryptoError::WeakNonce);
    }

    let cipher = AES256GCM::new(key.expose());
    cipher.encrypt(
        &nonce,
        &[], // AAD 없음 (확장 가능)
        &plaintext.expose()[..pt_len],
        &mut ciphertext.expose_mut()[..pt_len],
        tag,
    );
    nonce.zeroize();
    // cipher / key 는 Drop 에서 소거
    Ok(pt_len)
}

fn decrypt_aes256gcm(
    req: &CryptoPayload,
    ciphertext: &Secret<[u8; CRYPTO_DATA_LEN]>,
    ct_len: usize,
    tag: &[u8; GCM_TAG_SIZE],
    plaintext: &mut Secret<[u8; CRYPTO_DATA_LEN]>,
) -> Result<(), CryptoError> {
    if req.key_len as usize != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength);
    }
    if req.nonce_len as usize != GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceLength);
    }

    let mut key = Secret::new([0u8; AES256_KEY_SIZE]);
    key.expose_mut()
        .copy_from_slice(&req.key[..AES256_KEY_SIZE]);
    let mut nonce = [0u8; GCM_NONCE_SIZE];
    nonce.copy_from_slice(&req.nonce[..GCM_NONCE_SIZE]);

    let cipher = AES256GCM::new(key.expose());
    // elib AES256GCM::decrypt 는 내부에서 constant-time 태그 비교 수행
    let ok = cipher.decrypt(
        &nonce,
        &[],
        &ciphertext.expose()[..ct_len],
        tag,
        &mut plaintext.expose_mut()[..ct_len],
    );
    nonce.zeroize();

    if !ok {
        // AEAD 인증 실패 — 평문 버퍼를 호출자에게 반환 전 소거 (업스트림에서 재소거해도 무해)
        plaintext.expose_mut().zeroize();
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

fn encrypt_chacha20poly(
    req: &CryptoPayload,
    plaintext: &Secret<[u8; CRYPTO_DATA_LEN]>,
    pt_len: usize,
    ciphertext: &mut Secret<[u8; CRYPTO_DATA_LEN]>,
    tag: &mut [u8; 16],
) -> Result<usize, CryptoError> {
    if req.key_len as usize != CHACHA20_KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength);
    }
    if req.nonce_len as usize != 12 {
        return Err(CryptoError::InvalidNonceLength);
    }

    let mut key = Secret::new([0u8; CHACHA20_KEY_SIZE]);
    key.expose_mut()
        .copy_from_slice(&req.key[..CHACHA20_KEY_SIZE]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&req.nonce[..12]);

    // M3 ChaCha20-Poly1305 논스 재사용은 키스트림 재사용과 인증 위조로 직결됨
    // 전영(all-zero) 논스는 명백한 오용이므로 암호화 시점에 거부함
    if nonce.iter().all(|&b| b == 0) {
        nonce.zeroize();
        key.expose_mut().zeroize();
        return Err(CryptoError::WeakNonce);
    }

    let aead = ChaCha20Poly1305::new(key.expose());
    aead.encrypt(
        &nonce,
        &[],
        &plaintext.expose()[..pt_len],
        &mut ciphertext.expose_mut()[..pt_len],
        tag,
    )
    .map_err(|_| CryptoError::InvalidDataLength)?;
    nonce.zeroize();
    Ok(pt_len)
}

fn decrypt_chacha20poly(
    req: &CryptoPayload,
    ciphertext: &Secret<[u8; CRYPTO_DATA_LEN]>,
    ct_len: usize,
    tag: &[u8; 16],
    plaintext: &mut Secret<[u8; CRYPTO_DATA_LEN]>,
) -> Result<(), CryptoError> {
    if req.key_len as usize != CHACHA20_KEY_SIZE {
        return Err(CryptoError::InvalidKeyLength);
    }
    if req.nonce_len as usize != 12 {
        return Err(CryptoError::InvalidNonceLength);
    }

    let mut key = Secret::new([0u8; CHACHA20_KEY_SIZE]);
    key.expose_mut()
        .copy_from_slice(&req.key[..CHACHA20_KEY_SIZE]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&req.nonce[..12]);

    let aead = ChaCha20Poly1305::new(key.expose());
    // elib ChaCha20Poly1305::decrypt 는 내부 poly1305_verify 로 CT 태그 비교
    let r = aead.decrypt(
        &nonce,
        &[],
        &ciphertext.expose()[..ct_len],
        tag,
        &mut plaintext.expose_mut()[..ct_len],
    );
    nonce.zeroize();

    match r {
        Ok(()) => Ok(()),
        Err(_) => {
            plaintext.expose_mut().zeroize();
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

//
// 해시 핸들러
//

fn handle_hash(req: &CryptoPayload, reply: &mut [u8; IPC_MAX_PAYLOAD]) -> Result<(), CryptoError> {
    let algo = parse_algo(req.algo)?;
    let data_len = req.data_len as usize;
    if data_len > CRYPTO_DATA_LEN {
        return Err(CryptoError::InvalidDataLength);
    }
    let msg = &req.data[..data_len];

    match algo {
        CryptoAlgo::HmacSha256 => {
            let key_len = req.key_len as usize;
            if key_len > SHA256_BLOCK_SIZE {
                return Err(CryptoError::InvalidKeyLength);
            }
            let key_secret = {
                let mut k = Secret::new([0u8; SHA256_BLOCK_SIZE]);
                k.expose_mut()[..key_len].copy_from_slice(&req.key[..key_len]);
                k
            };
            let mut digest = [0u8; SHA256_OUTPUT_SIZE];
            hmac_sha256_multi(&key_secret.expose()[..key_len], &[msg], &mut digest);
            let r = write_ok_reply(reply, req.algo, &digest);
            digest.zeroize();
            r
        }
        CryptoAlgo::Blake3 => {
            let mut h = Blake3::new();
            h.update(msg);
            let digest = h.finalize().map_err(|_| CryptoError::InvalidRequest)?;
            let mut out = [0u8; BLAKE3_OUTPUT_SIZE];
            out.copy_from_slice(&digest.as_slice()[..BLAKE3_OUTPUT_SIZE]);
            let r = write_ok_reply(reply, req.algo, &out);
            out.zeroize();
            r
        }
        CryptoAlgo::Sha3_256 => {
            let mut h = SHA3_256::new();
            h.update(msg);
            let digest = h.finalize();
            let mut out = [0u8; SHA3_256_OUTPUT_SIZE];
            out.copy_from_slice(&digest.as_bytes()[..SHA3_256_OUTPUT_SIZE]);
            let r = write_ok_reply(reply, req.algo, &out);
            out.zeroize();
            r
        }
        CryptoAlgo::Sha3_512 => {
            let mut h = SHA3_512::new();
            h.update(msg);
            let digest = h.finalize();
            // SHA3-512 출력 64B; CRYPTO_DATA_LEN(168)에 충분히 수용됨
            let mut out = [0u8; SHA3_512_OUTPUT_SIZE];
            out.copy_from_slice(&digest.as_bytes()[..SHA3_512_OUTPUT_SIZE]);
            let r = write_ok_reply(reply, req.algo, &out);
            out.zeroize();
            r
        }
        _ => Err(CryptoError::UnknownAlgorithm),
    }
}

//
// 키 파생 핸들러
//

/// HKDF-SHA256 요청 페이로드 확장 레이아웃 (CryptoPayload 재사용):
///
/// - `algo`     = HkdfSha256
/// - `key_len`  = IKM 길이 (≤ 32)
/// - `key[..]`  = IKM (Input Key Material, Secret)
/// - `nonce_len`= salt 길이 (≤ 12)
/// - `nonce[..]`= salt
/// - `data_len` = info 길이 + 2 (앞 2바이트에 OKM 길이 LE u16 포함)
/// - `data[0..2]` = okm_len (LE u16)
/// - `data[2..data_len]` = info
fn handle_kdf(req: &CryptoPayload, reply: &mut [u8; IPC_MAX_PAYLOAD]) -> Result<(), CryptoError> {
    let algo = parse_algo(req.algo)?;
    if algo != CryptoAlgo::HkdfSha256 {
        return Err(CryptoError::UnknownAlgorithm);
    }

    let key_len = req.key_len as usize;
    let nonce_len = req.nonce_len as usize;
    let data_len = req.data_len as usize;

    if key_len > 32 {
        return Err(CryptoError::InvalidKeyLength);
    }
    if nonce_len > 12 {
        return Err(CryptoError::InvalidNonceLength);
    }
    if !(2..=CRYPTO_DATA_LEN).contains(&data_len) {
        return Err(CryptoError::InvalidDataLength);
    }

    let okm_len = u16::from_le_bytes([req.data[0], req.data[1]]) as usize;
    if okm_len == 0 || okm_len > HKDF_MAX_OUTPUT {
        return Err(CryptoError::OutputTooLarge);
    }
    let info = &req.data[2..data_len];

    let mut ikm = Secret::new([0u8; 32]);
    ikm.expose_mut()[..key_len].copy_from_slice(&req.key[..key_len]);

    let salt = &req.nonce[..nonce_len];

    // Extract -> PRK
    let mut prk = Secret::new([0u8; SHA256_OUTPUT_SIZE]);
    hkdf_extract(salt, &ikm.expose()[..key_len], prk.expose_mut());

    // Expand -> OKM
    let mut okm = Secret::new([0u8; HKDF_MAX_OUTPUT]);
    match hkdf_expand(prk.expose(), info, &mut okm.expose_mut()[..okm_len]) {
        Ok(()) => {
            let r = write_ok_reply(reply, req.algo, &okm.expose()[..okm_len]);
            // okm, prk, ikm 은 Secret Drop 으로 자동 소거
            r
        }
        Err(e) => {
            // 실패 시 명시적 소거
            okm.expose_mut().zeroize();
            prk.expose_mut().zeroize();
            Err(e)
        }
    }
}

//
// 알고리즘 파싱
//

fn parse_algo(byte: u8) -> Result<CryptoAlgo, CryptoError> {
    match byte {
        x if x == CryptoAlgo::Aes128Gcm as u8 => Err(CryptoError::UnknownAlgorithm), // elib 미지원
        x if x == CryptoAlgo::Aes256Gcm as u8 => Ok(CryptoAlgo::Aes256Gcm),
        x if x == CryptoAlgo::ChaCha20Poly as u8 => Ok(CryptoAlgo::ChaCha20Poly),
        x if x == CryptoAlgo::HmacSha256 as u8 => Ok(CryptoAlgo::HmacSha256),
        x if x == CryptoAlgo::Blake3 as u8 => Ok(CryptoAlgo::Blake3),
        x if x == CryptoAlgo::Sha3_256 as u8 => Ok(CryptoAlgo::Sha3_256),
        x if x == CryptoAlgo::Sha3_512 as u8 => Ok(CryptoAlgo::Sha3_512),
        x if x == CryptoAlgo::HkdfSha256 as u8 => Ok(CryptoAlgo::HkdfSha256),
        x if x == CryptoAlgo::Ed25519Sign as u8 => Ok(CryptoAlgo::Ed25519Sign),
        x if x == CryptoAlgo::Ed25519Verify as u8 => Ok(CryptoAlgo::Ed25519Verify),
        x if x == CryptoAlgo::Ed448Sign as u8 => Ok(CryptoAlgo::Ed448Sign),
        x if x == CryptoAlgo::Ed448Verify as u8 => Ok(CryptoAlgo::Ed448Verify),
        x if x == CryptoAlgo::X448Dh as u8 => Ok(CryptoAlgo::X448Dh),
        _ => Err(CryptoError::UnknownAlgorithm),
    }
}

//
// 서명 생성 핸들러
//

fn handle_sign(
    req: &CryptoPayload,
    reply: &mut [u8; IPC_MAX_PAYLOAD],
) -> Result<(), CryptoError> {
    let algo = parse_algo(req.algo)?;
    let data_len = req.data_len as usize;
    if data_len > CRYPTO_DATA_LEN {
        return Err(CryptoError::InvalidDataLength);
    }

    match algo {
        CryptoAlgo::Ed25519Sign => {
            if req.key_len as usize != ED25519_SK_SIZE {
                return Err(CryptoError::InvalidKeyLength);
            }
            let mut raw = Secret::new([0u8; ED25519_SK_SIZE]);
            raw.expose_mut().copy_from_slice(&req.key[..ED25519_SK_SIZE]);
            let sk = Ed25519Sk::from_bytes(raw.expose());
            let sig = ed25519::sign(&req.data[..data_len], &sk);
            write_ok_reply(reply, req.algo, sig.as_bytes())
            // sk, raw 은 Drop 시 자동 소거
        }
        CryptoAlgo::Ed448Sign => {
            if req.key_len as usize != ED448_SK_SIZE {
                return Err(CryptoError::InvalidKeyLength);
            }
            let sk_arr: &[u8; ED448_SK_SIZE] = req.key[..ED448_SK_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            let sk = Ed448Sk::from_bytes(sk_arr);
            let sig = ed448::sign(&req.data[..data_len], &sk);
            write_ok_reply(reply, req.algo, sig.as_bytes())
        }
        _ => Err(CryptoError::UnknownAlgorithm),
    }
}

//
// 서명 검증 핸들러
//

fn handle_verify(
    req: &CryptoPayload,
    reply: &mut [u8; IPC_MAX_PAYLOAD],
) -> Result<(), CryptoError> {
    let algo = parse_algo(req.algo)?;
    let data_len = req.data_len as usize;

    match algo {
        CryptoAlgo::Ed25519Verify => {
            // data = sig(64B) || message
            if req.key_len as usize != ED25519_PK_SIZE {
                return Err(CryptoError::InvalidKeyLength);
            }
            if data_len < ED25519_SIG_SIZE {
                return Err(CryptoError::InvalidDataLength);
            }
            if data_len > CRYPTO_DATA_LEN {
                return Err(CryptoError::InvalidDataLength);
            }
            let pk_arr: &[u8; ED25519_PK_SIZE] = req.key[..ED25519_PK_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            let sig_arr: &[u8; ED25519_SIG_SIZE] = req.data[..ED25519_SIG_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidDataLength)?;
            let pk = Ed25519Pk::from_bytes(pk_arr);
            let sig = Ed25519Sig::from_bytes(sig_arr);
            let msg = &req.data[ED25519_SIG_SIZE..data_len];
            match ed25519::verify(msg, &sig, &pk) {
                Ok(()) => write_ok_reply(reply, req.algo, &[1u8]),
                Err(_) => Err(CryptoError::AuthenticationFailed),
            }
        }
        CryptoAlgo::Ed448Verify => {
            // data = sig(114B) || message (≤54B)
            if req.key_len as usize != ED448_PK_SIZE {
                return Err(CryptoError::InvalidKeyLength);
            }
            if data_len < ED448_SIG_SIZE {
                return Err(CryptoError::InvalidDataLength);
            }
            if data_len > CRYPTO_DATA_LEN {
                return Err(CryptoError::InvalidDataLength);
            }
            let pk_arr: &[u8; ED448_PK_SIZE] = req.key[..ED448_PK_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            let sig_arr: &[u8; ED448_SIG_SIZE] = req.data[..ED448_SIG_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidDataLength)?;
            let pk = Ed448Pk::from_bytes(pk_arr);
            let sig = Ed448Sig::from_bytes(sig_arr);
            let msg = &req.data[ED448_SIG_SIZE..data_len];
            match ed448::verify(msg, &sig, &pk) {
                Ok(()) => write_ok_reply(reply, req.algo, &[1u8]),
                Err(_) => Err(CryptoError::AuthenticationFailed),
            }
        }
        _ => Err(CryptoError::UnknownAlgorithm),
    }
}

//
// Diffie-Hellman 핸들러
//

fn handle_dh(
    req: &CryptoPayload,
    reply: &mut [u8; IPC_MAX_PAYLOAD],
) -> Result<(), CryptoError> {
    let algo = parse_algo(req.algo)?;

    match algo {
        CryptoAlgo::X448Dh => {
            // key[0..56] = 자신의 비밀키, data[0..56] = 상대방 공개키
            if req.key_len as usize != X448_SK_SIZE {
                return Err(CryptoError::InvalidKeyLength);
            }
            if req.data_len as usize != X448_PK_SIZE {
                return Err(CryptoError::InvalidDataLength);
            }
            let mut sk_arr: [u8; X448_SK_SIZE] = req.key[..X448_SK_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            let pk_arr: [u8; X448_PK_SIZE] = req.data[..X448_PK_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidDataLength)?;
            let sk = X448Sk::from_bytes(sk_arr);
            // CRY-02 X448Sk 로 복사(Copy)된 개인키 로컬 원본 잔재를 즉시 소거
            sk_arr.zeroize();
            let peer_pk = X448Pk::from_bytes(pk_arr);
            // 소그룹 공격 방지: 저차수 점(공유비밀 0)은 라이브러리가 Err 로 거부
            let shared = sk
                .diffie_hellman(&peer_pk)
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            write_ok_reply(reply, req.algo, shared.as_bytes())
            // shared: SharedSecret(Secret<[u8;56]>) 은 Drop 시 자동 소거
        }
        _ => Err(CryptoError::UnknownAlgorithm),
    }
}

//
// 디스패처
//

/// 수신된 암호화 요청 하나를 처리하고 응답을 게시함.
///
/// 흐름:
///   1. `ipc_recv(EP_CRYPTO)` 로 PendingReply 상태 메시지 취득
///   2. `CryptoPayload` 파싱 (Secret 래핑)
///   3. msg_type 기반 분기 처리
///   4. 결과를 `ipc_reply()` 로 게시
///
/// # Errors
/// 엔드포인트에 대기 중인 메시지가 없거나, IPC 레지스트리 접근 실패 시
/// `IpcError` 를 반환함. 암호 연산 자체의 실패는 `MessageType::Error`
/// 응답으로 번역되어 성공적으로 리플라이 됨 (IPC 에러 아님).
///
/// # Safety
/// - `ipc::init()` 및 `capability::init_prng()` 호출 이후에만 안전
/// - 단일 코어 혹은 외부 동기화 보장 상태에서만 호출
pub unsafe fn dispatch() -> Result<(), IpcError> {
    // 1. 요청 수신
    // SAFETY: 호출자가 동기화 보장
    let msg = unsafe { ipc_recv(EP_CRYPTO)? };

    // 2. CryptoPayload 파싱 -> Secret
    let req_parse = parse_request(&msg);

    // 3. 응답 버퍼 (Secret 로 감싸 Drop 시 소거)
    let mut reply = new_reply_buf();

    // 4. 처리 분기
    let (reply_type, result): (MessageType, Result<(), CryptoError>) = match req_parse {
        Err(e) => (MessageType::Error, Err(e)),
        Ok(req) => match msg.header.msg_type {
            MessageType::EncryptReq => (
                MessageType::EncryptResp,
                handle_encrypt(req.expose(), reply.expose_mut()),
            ),
            MessageType::DecryptReq => (
                MessageType::DecryptResp,
                handle_decrypt(req.expose(), reply.expose_mut()),
            ),
            MessageType::HashReq => (
                MessageType::HashResp,
                handle_hash(req.expose(), reply.expose_mut()),
            ),
            MessageType::KeyDeriveReq => (
                MessageType::KeyDeriveResp,
                handle_kdf(req.expose(), reply.expose_mut()),
            ),
            MessageType::SignReq => (
                MessageType::SignResp,
                handle_sign(req.expose(), reply.expose_mut()),
            ),
            MessageType::VerifyReq => (
                MessageType::VerifyResp,
                handle_verify(req.expose(), reply.expose_mut()),
            ),
            MessageType::DhReq => (
                MessageType::DhResp,
                handle_dh(req.expose(), reply.expose_mut()),
            ),
            _ => (MessageType::Error, Err(CryptoError::InvalidRequest)),
        },
    };

    // 5. 결과에 따라 응답 조립
    let (final_type, final_len) = match result {
        Ok(()) => {
            // 성공 — reply 는 write_ok_reply 로 이미 작성됨
            let payload_len = core::mem::size_of::<CryptoPayload>();
            (reply_type, payload_len)
        }
        Err(e) => {
            // 에러 응답 — reply 를 다시 작성 (기존 성공-경로 내용 소거 후)
            // SAFETY: reply.expose_mut() 는 [u8; IPC_MAX_PAYLOAD]
            unsafe {
                secure_zero(reply.expose_mut().as_mut_ptr(), IPC_MAX_PAYLOAD);
            }
            write_error_reply(reply.expose_mut(), e);
            (MessageType::Error, 1)
        }
    };

    // 6. 리플라이 게시
    // SAFETY: 호출자가 동기화 보장, ipc::init 이후
    unsafe {
        ipc_reply(EP_CRYPTO, final_type, &reply.expose()[..final_len])?;
    }
    // reply Secret Drop 에서 전체 소거

    Ok(())
}
