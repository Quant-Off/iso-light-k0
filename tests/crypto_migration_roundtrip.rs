//! elib-k0-nt 제자리 초기화 API 이관 회귀 테스트 (AEAD 왕복 / DH 합의 / 서명 검증)
//!
//! # Features
//! 커널 crypto_service·tls·iso-user-lumen 이 사용하는 것과 동일한 호출 패턴
//! (`Default` + `init`, `diffie_hellman_into`, `default()` + `sign`/`verify`)으로
//! AES-256-GCM 과 ChaCha20-Poly1305 의 encrypt->decrypt 왕복, x25519·x448 ECDH
//! 양측 합의, Ed25519·Ed448 서명 생성과 검증을 실행해 이관된 call-site 가 런타임에
//! 올바르게 동작함을 검증합니다. arch_parity 가 알고리즘 출력 불변을 고정하고 본
//! 테스트는 왕복·합의 계약을 고정하므로 두 테스트가 이관 정합성을 상호 보완합니다.
//! host 전용이며 `--target $HOST_TRIPLE` 로 실행합니다.
#![cfg(not(target_os = "none"))]

#[test]
fn aes256gcm_roundtrip() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = b"iso-light-k0 aead aad";
    let plaintext = b"aes-256-gcm roundtrip after in-place init migration";

    let mut cipher = aes::AES256GCM::default();
    cipher.init(&key);

    let mut ct = [0u8; 51];
    let mut tag = [0u8; 16];
    assert_eq!(plaintext.len(), ct.len());
    cipher
        .encrypt(&nonce, aad, plaintext, &mut ct, &mut tag)
        .expect("AES-256-GCM encrypt");

    let mut pt = [0u8; 51];
    cipher
        .decrypt(&nonce, aad, &ct, &tag, &mut pt)
        .expect("AES-256-GCM decrypt");
    assert_eq!(&pt, plaintext, "AES-256-GCM 왕복 평문 불일치");

    // 태그 훼손 시 인증 실패로 거부되어야 함 (fail-closed)
    let mut bad_tag = tag;
    bad_tag[0] ^= 0x01;
    let mut pt2 = [0u8; 51];
    assert!(
        cipher.decrypt(&nonce, aad, &ct, &bad_tag, &mut pt2).is_err(),
        "훼손된 태그가 거부되지 않음"
    );
}

#[test]
fn chacha20poly1305_roundtrip() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let aad = b"iso-light-k0 chacha aad";
    let plaintext = b"chacha20-poly1305 roundtrip after migration";

    let mut aead = chacha20::ChaCha20Poly1305::default();
    aead.init(&key);

    let mut ct = [0u8; 43];
    let mut tag = [0u8; 16];
    assert_eq!(plaintext.len(), ct.len());
    aead.encrypt(&nonce, aad, plaintext, &mut ct, &mut tag)
        .expect("ChaCha20-Poly1305 encrypt");

    let mut pt = [0u8; 43];
    aead.decrypt(&nonce, aad, &ct, &tag, &mut pt)
        .expect("ChaCha20-Poly1305 decrypt");
    assert_eq!(&pt, plaintext, "ChaCha20-Poly1305 왕복 평문 불일치");
}

#[test]
fn x25519_dh_agreement() {
    let a_seed = [0xAAu8; 32];
    let b_seed = [0xBBu8; 32];

    let mut a_sk = x25519::SecretKey::default();
    a_sk.init(&a_seed);
    let mut b_sk = x25519::SecretKey::default();
    b_sk.init(&b_seed);
    let a_pk = a_sk.public_key();
    let b_pk = b_sk.public_key();

    let mut ss_ab = x25519::SharedSecret::default();
    let mut ss_ba = x25519::SharedSecret::default();
    a_sk.diffie_hellman_into(&b_pk, &mut ss_ab).expect("x25519 A");
    b_sk.diffie_hellman_into(&a_pk, &mut ss_ba).expect("x25519 B");
    assert_eq!(ss_ab.as_bytes(), ss_ba.as_bytes(), "x25519 공유비밀 불일치");
}

#[test]
fn x448_dh_agreement() {
    let a_seed = [0xCCu8; 56];
    let b_seed = [0xDDu8; 56];

    let mut a_sk = x448::SecretKey::default();
    a_sk.init(&a_seed);
    let mut b_sk = x448::SecretKey::default();
    b_sk.init(&b_seed);
    let a_pk = a_sk.public_key();
    let b_pk = b_sk.public_key();

    let mut ss_ab = x448::SharedSecret::default();
    let mut ss_ba = x448::SharedSecret::default();
    a_sk.diffie_hellman_into(&b_pk, &mut ss_ab).expect("x448 A");
    b_sk.diffie_hellman_into(&a_pk, &mut ss_ba).expect("x448 B");
    assert_eq!(ss_ab.as_bytes(), ss_ba.as_bytes(), "x448 공유비밀 불일치");
}

#[test]
fn ed25519_sign_verify() {
    let seed = [0x42u8; 32];
    let mut sk = ed25519::SecretKey::default();
    sk.init(&seed);
    let pk = ed25519::PublicKey::from(&sk);
    let msg = b"iso-light-k0 ed25519 migration message";

    let sig = ed25519::sign(msg, &sk);
    ed25519::verify(msg, &sig, &pk).expect("Ed25519 유효 서명 검증 실패");

    // 결정성 (RFC 8032): 동일 키/메시지는 동일 서명
    let sig2 = ed25519::sign(msg, &sk);
    assert_eq!(sig.as_bytes(), sig2.as_bytes(), "Ed25519 비결정적 서명");

    // 메시지 변조 시 검증 실패 (fail-closed)
    assert!(
        ed25519::verify(b"tampered", &sig, &pk).is_err(),
        "변조 메시지가 검증됨"
    );
}

#[test]
fn ed448_sign_verify() {
    let seed = [0x57u8; 57];
    let mut sk = ed448::SecretKey::default();
    sk.init(&seed);
    let pk = ed448::PublicKey::from(&sk);
    let msg = b"iso-light-k0 ed448 migration message";

    let sig = ed448::sign(msg, &sk);
    ed448::verify(msg, &sig, &pk).expect("Ed448 유효 서명 검증 실패");

    assert!(
        ed448::verify(b"tampered", &sig, &pk).is_err(),
        "변조 메시지가 검증됨"
    );
}
