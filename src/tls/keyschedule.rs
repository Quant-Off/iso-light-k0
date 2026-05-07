//! TLS 1.3 키 스케줄 (RFC 8446 §7.1, §7.2) 을 수행하는 모듈입니다.
//!
//! 각 단계의 도출 관계는 다음과 같습니다.
//!   - PSK -> HKDF-Extract(0, PSK) -> EarlySecret.
//!     EarlySecret 에서 Derive-Secret(_, "ext binder", "") -> BinderKey,
//!     Derive-Secret(_, "derived", "") -> EarlyDerived 가 도출됨.
//!   - EarlyDerived -> HKDF-Extract(_, ECDHE_SS) -> HandshakeSecret.
//!     HandshakeSecret 에서 "c hs traffic" -> C-HS-TS,
//!     "s hs traffic" -> S-HS-TS, "derived" -> HSDerived 가 도출됨.
//!   - HSDerived -> HKDF-Extract(_, 0) -> MasterSecret.
//!     MasterSecret 에서 "c ap traffic" -> C-AP-TS_0, "s ap traffic" ->
//!     S-AP-TS_0 가 도출됨.
//!   - per-direction:
//!       key          = HKDF-Expand-Label(traffic_secret, "key", "", AEAD_KEY_LEN)
//!       iv           = HKDF-Expand-Label(traffic_secret, "iv",  "", AEAD_IV_LEN)
//!       finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", hash_len)
//!
//! Hybrid 시 ECDHE_SS = X25519_SS ‖ ML-KEM-768_SS (draft-ietf-tls-hybrid),
//! Classical 시 ECDHE_SS = X25519_SS 입니다.

use zeroize::Secret;

use crate::crypto_service::{SHA256_OUTPUT_SIZE, hkdf_expand, hkdf_extract, hmac_sha256_multi};
use crate::tls::{
    AEAD_IV_LEN, AEAD_KEY_LEN, CipherSuite, KexPolicy, TLS_HASH_LEN, TLS_KEM_SS_LEN, TlsError,
};

const ZERO_HASH: [u8; TLS_HASH_LEN] = [0u8; TLS_HASH_LEN];

/// HKDF-Expand-Label per RFC 8446 §7.1.
///
/// `HkdfLabel = uint16(len) || opaque<7..255>("tls13 "+label) || opaque<0..255>(context)`.
///
/// # Errors
/// 라벨 길이 또는 컨텍스트 길이가 8비트 한계 초과 / `out` 크기가
/// HKDF 한계 초과 시.
pub fn hkdf_expand_label(
    secret: &[u8; SHA256_OUTPUT_SIZE],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), TlsError> {
    // "tls13 " 접두사 + label 합산 길이는 1 바이트 length 필드에 들어가야 함
    let prefixed_label_len = 6usize + label.len();
    if prefixed_label_len > 255 || context.len() > 255 {
        return Err(TlsError::Internal);
    }
    if out.len() > u16::MAX as usize {
        return Err(TlsError::Internal);
    }

    // 동적 할당 없이 고정 버퍼에 인코딩 (충분히 큰 상한 사용)
    // 길이: 2 + 1 + 6 + label.len()(≤32) + 1 + context.len()(≤64) ≤ 106
    let mut info = [0u8; 128];
    let mut p = 0usize;

    // uint16 length (big-endian)
    info[p..p + 2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    p += 2;

    // opaque label<7..255>
    info[p] = prefixed_label_len as u8;
    p += 1;
    info[p..p + 6].copy_from_slice(b"tls13 ");
    p += 6;
    info[p..p + label.len()].copy_from_slice(label);
    p += label.len();

    // opaque context<0..255>
    info[p] = context.len() as u8;
    p += 1;
    if p + context.len() > info.len() {
        return Err(TlsError::Internal);
    }
    info[p..p + context.len()].copy_from_slice(context);
    p += context.len();

    hkdf_expand(secret, &info[..p], out).map_err(|_| TlsError::Internal)
}

/// Derive-Secret per RFC 8446 §7.1.
///
/// `Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, H(Messages), Hash.length)`.
pub fn derive_secret(
    prk: &[u8; SHA256_OUTPUT_SIZE],
    label: &[u8],
    transcript_hash: &[u8; TLS_HASH_LEN],
    out: &mut [u8; TLS_HASH_LEN],
) -> Result<(), TlsError> {
    hkdf_expand_label(prk, label, transcript_hash, out)
}

//
// 키 스케줄의 단계별 산출물
//

/// 핸드셰이크 / 애플리케이션 전 단계의 모든 시크릿.
///
/// 모든 필드는 32바이트 HKDF-SHA-256 출력. `Secret<>` 으로 보호되어 Drop 시
/// volatile-write 로 자동 소거.
pub struct ScheduleSecrets {
    pub early: Secret<[u8; TLS_HASH_LEN]>,
    pub handshake: Secret<[u8; TLS_HASH_LEN]>,
    pub master: Secret<[u8; TLS_HASH_LEN]>,
    pub client_handshake_traffic: Secret<[u8; TLS_HASH_LEN]>,
    pub server_handshake_traffic: Secret<[u8; TLS_HASH_LEN]>,
    pub client_application_traffic_0: Secret<[u8; TLS_HASH_LEN]>,
    pub server_application_traffic_0: Secret<[u8; TLS_HASH_LEN]>,
    pub binder_key: Secret<[u8; TLS_HASH_LEN]>,
}

impl ScheduleSecrets {
    pub fn empty() -> Self {
        Self {
            early: Secret::new([0u8; TLS_HASH_LEN]),
            handshake: Secret::new([0u8; TLS_HASH_LEN]),
            master: Secret::new([0u8; TLS_HASH_LEN]),
            client_handshake_traffic: Secret::new([0u8; TLS_HASH_LEN]),
            server_handshake_traffic: Secret::new([0u8; TLS_HASH_LEN]),
            client_application_traffic_0: Secret::new([0u8; TLS_HASH_LEN]),
            server_application_traffic_0: Secret::new([0u8; TLS_HASH_LEN]),
            binder_key: Secret::new([0u8; TLS_HASH_LEN]),
        }
    }
}

/// EarlySecret 과 BinderKey 만 먼저 도출 (binder MAC 계산용).
///
/// `salt = 0`, `IKM = PSK` 로 HSM 또는 SoftKeystore 가 HKDF-Extract 를 수행.
pub fn derive_early_secrets<H: crate::hsm::HsmDriver>(
    hsm: &H,
    psk_id: &crate::hsm::PskId,
    out: &mut ScheduleSecrets,
) -> Result<(), TlsError> {
    // EarlySecret = HKDF-Extract(0, PSK)
    // RFC 8446 §7.1: "If a given secret is not available, then the 0-value
    //                 consisting of a string of Hash.length bytes set to
    //                 zeros is used."
    hsm.psk_hkdf_extract(psk_id, &ZERO_HASH, out.early.expose_mut())?;

    // BinderKey = Derive-Secret(EarlySecret, "ext binder", "")
    // "ext binder" 는 외부(외부 분배) PSK 에 사용. resumption_master_secret 이 아닌 PSK 임을 식별
    let h_empty = sha256_of_empty();
    derive_secret(
        out.early.expose(),
        b"ext binder",
        &h_empty,
        out.binder_key.expose_mut(),
    )?;
    Ok(())
}

/// HandshakeSecret 및 핸드셰이크 트래픽 시크릿 도출.
///
/// `transcript_hash` = H(ClientHello..ServerHello). PQ-hybrid 시 `ecdhe_ss` 는
/// X25519 32B + ML-KEM-768 32B = 64B 의 연결.
pub fn derive_handshake_secrets(
    secrets: &mut ScheduleSecrets,
    ecdhe_ss: &[u8],
    transcript_hash_ch_to_sh: &[u8; TLS_HASH_LEN],
    policy: KexPolicy,
) -> Result<(), TlsError> {
    // 정책 일관성 검증 (caller 의 실수 차단)
    let expected = match policy {
        KexPolicy::Classical => TLS_KEM_SS_LEN,               // 32
        KexPolicy::Hybrid => TLS_KEM_SS_LEN + TLS_KEM_SS_LEN, // 64
    };
    if ecdhe_ss.len() != expected {
        return Err(TlsError::KexPolicyMismatch);
    }

    // EarlyDerived = Derive-Secret(EarlySecret, "derived", "")
    let mut early_derived = Secret::new([0u8; TLS_HASH_LEN]);
    let h_empty = sha256_of_empty();
    derive_secret(
        secrets.early.expose(),
        b"derived",
        &h_empty,
        early_derived.expose_mut(),
    )?;

    // HandshakeSecret = HKDF-Extract(EarlyDerived, ECDHE_SS)
    hkdf_extract(
        early_derived.expose(),
        ecdhe_ss,
        secrets.handshake.expose_mut(),
    );

    // C-HS-TS / S-HS-TS = Derive-Secret(HS, "c|s hs traffic", H(CH..SH))
    derive_secret(
        secrets.handshake.expose(),
        b"c hs traffic",
        transcript_hash_ch_to_sh,
        secrets.client_handshake_traffic.expose_mut(),
    )?;
    derive_secret(
        secrets.handshake.expose(),
        b"s hs traffic",
        transcript_hash_ch_to_sh,
        secrets.server_handshake_traffic.expose_mut(),
    )?;
    Ok(())
}

/// MasterSecret 과 application 트래픽 시크릿 도출.
///
/// `transcript_hash_ch_to_sf` = H(ClientHello..ServerFinished).
pub fn derive_master_and_app_secrets(
    secrets: &mut ScheduleSecrets,
    transcript_hash_ch_to_sf: &[u8; TLS_HASH_LEN],
) -> Result<(), TlsError> {
    let h_empty = sha256_of_empty();

    // HSDerived = Derive-Secret(HandshakeSecret, "derived", "")
    let mut hs_derived = Secret::new([0u8; TLS_HASH_LEN]);
    derive_secret(
        secrets.handshake.expose(),
        b"derived",
        &h_empty,
        hs_derived.expose_mut(),
    )?;

    // MasterSecret = HKDF-Extract(HSDerived, 0)
    hkdf_extract(hs_derived.expose(), &ZERO_HASH, secrets.master.expose_mut());

    // C-AP-TS_0 / S-AP-TS_0
    derive_secret(
        secrets.master.expose(),
        b"c ap traffic",
        transcript_hash_ch_to_sf,
        secrets.client_application_traffic_0.expose_mut(),
    )?;
    derive_secret(
        secrets.master.expose(),
        b"s ap traffic",
        transcript_hash_ch_to_sf,
        secrets.server_application_traffic_0.expose_mut(),
    )?;
    Ok(())
}

//
// 트래픽 키 / IV / Finished Key 도출
//

/// `key` / `iv` 를 traffic_secret 에서 도출.
pub fn derive_traffic_keys(
    traffic_secret: &[u8; TLS_HASH_LEN],
    _suite: CipherSuite,
    key_out: &mut [u8; AEAD_KEY_LEN],
    iv_out: &mut [u8; AEAD_IV_LEN],
) -> Result<(), TlsError> {
    hkdf_expand_label(traffic_secret, b"key", &[], key_out)?;
    hkdf_expand_label(traffic_secret, b"iv", &[], iv_out)?;
    Ok(())
}

/// `finished_key` 를 traffic_secret 에서 도출.
pub fn derive_finished_key(
    traffic_secret: &[u8; TLS_HASH_LEN],
    out: &mut [u8; TLS_HASH_LEN],
) -> Result<(), TlsError> {
    hkdf_expand_label(traffic_secret, b"finished", &[], out)
}

/// `verify_data = HMAC(finished_key, transcript_hash)` per RFC 8446 §4.4.4.
pub fn compute_verify_data(
    finished_key: &[u8; TLS_HASH_LEN],
    transcript_hash: &[u8; TLS_HASH_LEN],
    out: &mut [u8; TLS_HASH_LEN],
) {
    hmac_sha256_multi(finished_key, &[transcript_hash], out);
}

/// PSK binder = HMAC(BinderKey 에서 파생된 finished_key, H(truncated_CH)).
///
/// RFC 8446 §4.2.11.2: "The PSK binder value forms a binding between a PSK
/// and the current handshake."
pub fn compute_binder(
    binder_key: &[u8; TLS_HASH_LEN],
    transcript_hash_truncated_ch: &[u8; TLS_HASH_LEN],
    out: &mut [u8; TLS_HASH_LEN],
) -> Result<(), TlsError> {
    let mut finished_key = Secret::new([0u8; TLS_HASH_LEN]);
    derive_finished_key(binder_key, finished_key.expose_mut())?;
    compute_verify_data(finished_key.expose(), transcript_hash_truncated_ch, out);
    Ok(())
}

//
// 헬퍼
//

fn sha256_of_empty() -> [u8; TLS_HASH_LEN] {
    use sha2::{SHA2, SHA256};
    let h = SHA256::new();
    let digest = h.finalize();
    let mut out = [0u8; TLS_HASH_LEN];
    out.copy_from_slice(&digest.as_bytes()[..TLS_HASH_LEN]);
    out
}

/// Constant-time 바이트 비교.
///
/// Finished MAC / binder MAC 검증 시 `==` 직접 비교는 사이드채널 위험.
/// 본 함수는 길이가 같을 때만 의미 있으며, 다르면 즉시 false 반환.
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
