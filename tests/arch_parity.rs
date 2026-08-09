//! elib-k0-nt 5 알고리즘 x86_64 <-> aarch64 byte-diff 0 parity host test (ARM-10 T-10F-02)
//!
//! # Features
//! BLAKE3 AES-256 ChaCha20 ML-KEM-768 ML-DSA-44 를 고정 입력으로 계산하고 golden
//! byte vector 와 byte-diff 0 을 assert 합니다. elib-k0-nt 는 NEON 경로가 없어
//! generic Rust little-endian 결정론만 사용하므로 (10-RESEARCH State of the Art)
//! 동일 입력이 x86_64 와 aarch64 에서 동일 출력을 냅니다. golden 은 알고리즘 자체
//! 결정론에 고정되므로 어느 호스트에서 실행하든 동일 벡터로 수렴합니다. host 전용
//! test 라 부팅이 불요하며 `--target $HOST_TRIPLE` 로 실행합니다.
#![cfg(not(target_os = "none"))]

// golden byte vector 는 아키텍처 무관 상수 어느 호스트든 동일 출력으로 수렴
const BLAKE3_GOLDEN: &str = "6876213b83a48cf5e83ee7cf310d21f6e9d8336894d3c516da9e412df937c615";
const AES_GOLDEN: &str = "bfa14695d7e07f022d0fb79af8a34549";
const CHACHA_GOLDEN: &str =
    "3931194383f326c39a573b6a943496babc348b16c0d354c8501ad21b58d0a86f9811e96a917a8fa9eaa2ecb7d74c2bd4a941b221e5519a2d323fa0edf311ac0c";
const MLKEM_GOLDEN: &str = "2db3743d6a3f6b8b5814413ef5f5cb56d28015b8485da94fdf57ffb8da03c225";
const MLDSA_GOLDEN: &str = "52e59cee24e4aa426f8783ef94a205216b6ee585841d052e7755d9cfc65dbda7";

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[test]
fn blake3_byte_diff_zero() {
    let mut h = blake::Blake3::new();
    h.update(b"iso-light-k0 arch parity vector 0123456789");
    let d = h.finalize().unwrap();
    assert_eq!(hexs(&d.as_slice()[..32]), BLAKE3_GOLDEN, "BLAKE3 크로스 아키텍처 diff");
}

#[test]
fn aes256_byte_diff_zero() {
    let key = [0x11u8; 32];
    let block = [0x22u8; 16];
    let mut c = aes::AES256::default();
    c.init(&key);
    let out = c.encrypt(&block);
    assert_eq!(hexs(&out), AES_GOLDEN, "AES-256 크로스 아키텍처 diff");
}

#[test]
fn chacha20_byte_diff_zero() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let mut core = chacha20::ChaCha20Core::default();
    core.init(&key, &nonce);
    let out = core.keystream_block();
    assert_eq!(hexs(&out), CHACHA_GOLDEN, "ChaCha20 크로스 아키텍처 diff");
}

#[test]
fn mlkem768_byte_diff_zero() {
    let d = [0x55u8; 32];
    let z = [0x66u8; 32];
    let mut kp = mlkem::MLKEM768KeyPair::default();
    mlkem::mlkem768_keygen(&d, &z, &mut kp);
    let m = [0x77u8; 32];
    let mut ss = zeroize::Secret::new([0u8; 32]);
    let ct = mlkem::mlkem768_encaps(&kp.ek, &m, &mut ss).unwrap();
    // ek + ct + ss 전량을 BLAKE3 로 압축하여 단일 byte 라도 diff 나면 digest 반전
    let mut h = blake::Blake3::new();
    h.update(&kp.ek);
    h.update(&ct);
    h.update(ss.expose());
    let dig = h.finalize().unwrap();
    assert_eq!(hexs(&dig.as_slice()[..32]), MLKEM_GOLDEN, "ML-KEM-768 크로스 아키텍처 diff");
}

#[test]
fn mldsa44_byte_diff_zero() {
    let xi = [0x88u8; 32];
    let (pk, sk) = mldsa::MLDSA44::keygen(&xi).unwrap();
    let msg = b"iso-light-k0 arch parity mldsa message";
    let ctx: &[u8] = b"";
    let rnd = [0x99u8; 32];
    let sig = mldsa::MLDSA44::sign(&sk, msg, ctx, &rnd).unwrap();
    let mut h = blake::Blake3::new();
    h.update(&pk);
    h.update(&sig);
    let dig = h.finalize().unwrap();
    assert_eq!(hexs(&dig.as_slice()[..32]), MLDSA_GOLDEN, "ML-DSA-44 크로스 아키텍처 diff");
}
