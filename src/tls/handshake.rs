//! TLS 1.3 PSK 핸드셰이크(`psk_dhe_ke` / `psk_pq_hybrid_ke`) 를 수행하는
//! 모듈입니다.
//!
//! 메시지 흐름은 다음 순서로 진행됩니다.
//!   1. Client -> Server: ClientHello(psk_id, random, suite, policy,
//!      ephem_pk[s], binder).
//!   2. 서버측 ECDHE / KEM 처리 후 Server -> Client: ServerHello(random,
//!      suite, ephem_pk[s] / kem_ct). 이 시점부터 양측 handshake_traffic_secrets
//!      이 도출됨.
//!   3. Server -> Client: {Finished_S} (verify_data over CH..ServerHello).
//!   4. Client -> Server: {Finished_C} (verify_data over CH..Finished_S).
//!      이 시점부터 양측 application_traffic_secrets 가 활성화됨.
//!
//! 본 모듈은 v1 한정 in-kernel loopback 핸드셰이크를 제공합니다. 같은 커널
//! 내 두 [`crate::tls::ConnHandle`] 간 대칭 PSK 검증, 트래픽 키 셋업, 종료
//! 후 zeroize 까지의 전체 흐름을 검증하며, 외부 전송 계층 통합은 향후 IPC
//! 스트리밍 인터페이스 도입 시 추가될 예정입니다.
//!
//! 메시지 직렬화는 RFC 8446 의 와이어 포맷을 단순화한 본 커널 내부 인코딩을
//! 사용하나, 암호학적 도출 절차는 RFC 8446 §7.1, §4.2.11.2 와 동일합니다
//! (HKDF-Expand-Label, Derive-Secret, binder/finished MAC).

use mlkem::{MLKEM768KeyPair, mlkem768_decaps, mlkem768_encaps, mlkem768_keygen};
use x25519::SecretKey as X25519Sk;
use zeroize::Secret;

use crate::capability;
use crate::hsm::{HsmDriver, PskId};
use crate::tls::keyschedule::{
    self, ScheduleSecrets, ct_eq_bytes, derive_early_secrets, derive_handshake_secrets,
    derive_master_and_app_secrets, derive_traffic_keys,
};
use crate::tls::transcript::Transcript;
use crate::tls::{
    CipherSuite, ConnHandle, ConnState, KexPolicy, Profile, Side, TLS_HASH_LEN, TLS_KEM_SS_LEN,
    TLS_MLKEM768_CT_LEN, TLS_MLKEM768_PK_LEN, TLS_X25519_PK_LEN, TlsError, alloc_slot, slot,
};

//
// 본 커널 내부 메시지 형식
//
// CH = u8 type(1) || u24 len || PskId(16) || rand(32) || u8 suite || u8 policy
//      || X25519_pk(32) || [if Hybrid: MLKEM_ek(1184)] || u8 binder_len(=32)
//      || binder(32)
// SH = u8 type(2) || u24 len || rand(32) || u8 suite
//      || X25519_pk(32) || [if Hybrid: MLKEM_ct(1088)]
// Fin= u8 type(20) || u24 len(=32) || verify_data(32)

const HS_TYPE_CLIENT_HELLO: u8 = 1;
const HS_TYPE_SERVER_HELLO: u8 = 2;
const HS_TYPE_FINISHED: u8 = 20;

const HS_HEADER_LEN: usize = 4; // u8 type + u24 length

const CH_FIXED_PREFIX_LEN: usize = 16 + 32 + 1 + 1 + TLS_X25519_PK_LEN; // psk_id, random, suite, policy, x25519
const SH_FIXED_LEN: usize = 32 + 1 + TLS_X25519_PK_LEN; // random, suite, x25519
const FIN_LEN: usize = TLS_HASH_LEN;

//
// 메시지 빌드 / 파싱
//

fn write_handshake_header(buf: &mut [u8], hs_type: u8, payload_len: usize) -> Result<(), TlsError> {
    if payload_len > 0x00FF_FFFF {
        return Err(TlsError::Internal);
    }
    if buf.len() < HS_HEADER_LEN {
        return Err(TlsError::BufferTooSmall);
    }
    buf[0] = hs_type;
    buf[1] = ((payload_len >> 16) & 0xFF) as u8;
    buf[2] = ((payload_len >> 8) & 0xFF) as u8;
    buf[3] = (payload_len & 0xFF) as u8;
    Ok(())
}

#[allow(dead_code)]
fn parse_handshake_header(buf: &[u8]) -> Result<(u8, usize), TlsError> {
    if buf.len() < HS_HEADER_LEN {
        return Err(TlsError::BadMessage);
    }
    let hs_type = buf[0];
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
    Ok((hs_type, len))
}

//
// 외부 공개: 풀 슬롯 할당 + 핸드셰이크 실행
//

/// 두 새 슬롯(client / server) 을 할당하여 in-kernel 루프백 핸드셰이크 수행.
///
/// HSM/Keystore 에 동일 PSK 가 등록되어 있어야 함. 성공 시 양 슬롯 모두
/// `Connected` 상태로 application 트래픽 키가 활성화됨.
///
/// # Safety
/// 단일 코어 / 외부 동기화 보장 환경. DRBG / Keystore 전역 상태 변경.
pub unsafe fn run_loopback<H: HsmDriver>(
    hsm: &H,
    profile: Profile,
    policy: KexPolicy,
    suite: CipherSuite,
    psk_id: &PskId,
) -> Result<(ConnHandle, ConnHandle), TlsError> {
    // 외부망 프로파일은 컴파일 게이팅 + 런타임 거부의 이중 확인
    match profile {
        Profile::Closed => {}
        #[cfg(feature = "tls-external")]
        Profile::External => {}
    }

    let client_h = alloc_slot()?;
    // 두 번째 슬롯 할당 시 첫번째 슬롯이 점유되지 않도록 임시 마킹
    let c = slot(client_h)?;
    c.state = ConnState::Handshaking;
    c.side = Side::Client;
    c.profile = profile;
    c.policy = policy;
    c.suite = suite;
    c.psk_id = *psk_id;

    let server_h = match alloc_slot() {
        Ok(h) => h,
        Err(e) => {
            // 첫 슬롯 회수
            c.state = ConnState::Free;
            return Err(e);
        }
    };
    let s = slot(server_h)?;
    s.state = ConnState::Handshaking;
    s.side = Side::Server;
    s.profile = profile;
    s.policy = policy;
    s.suite = suite;
    s.psk_id = *psk_id;

    // 실패 시 양 슬롯 모두 wipe 하기 위한 inner 함수
    let res = unsafe { do_handshake(hsm, client_h, server_h, policy, suite, psk_id) };
    if let Err(e) = res {
        let _ = crate::tls::close(client_h);
        let _ = crate::tls::close(server_h);
        return Err(e);
    }
    Ok((client_h, server_h))
}

unsafe fn do_handshake<H: HsmDriver>(
    hsm: &H,
    client_h: ConnHandle,
    server_h: ConnHandle,
    policy: KexPolicy,
    suite: CipherSuite,
    psk_id: &PskId,
) -> Result<(), TlsError> {
    // SAFETY: identity-mapped VGA, 단일 코어
    //
    // 1. 양측 ephemeral 키쌍 생성
    //
    // X25519: 항상
    let mut c_seed = [0u8; 32];
    let mut s_seed = [0u8; 32];
    // SAFETY: 단일 코어 부팅 초기 / 호출자 보장
    unsafe {
        capability::rand_bytes(&mut c_seed).map_err(|_| TlsError::HsmFailure)?;
        capability::rand_bytes(&mut s_seed).map_err(|_| TlsError::HsmFailure)?;
    }
    let client_x_sk = X25519Sk::from_bytes(c_seed);
    let server_x_sk = X25519Sk::from_bytes(s_seed);
    c_seed.fill(0);
    s_seed.fill(0);
    let client_x_pk = client_x_sk.public_key();
    let server_x_pk = server_x_sk.public_key();

    // ML-KEM-768: hybrid 일 때만
    let mlkem_kp: Option<MLKEM768KeyPair> = match policy {
        KexPolicy::Hybrid => {
            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            unsafe {
                capability::rand_bytes(&mut d).map_err(|_| TlsError::HsmFailure)?;
                capability::rand_bytes(&mut z).map_err(|_| TlsError::HsmFailure)?;
            }
            let kp = mlkem768_keygen(&d, &z);
            d.fill(0);
            z.fill(0);
            Some(kp)
        }
        KexPolicy::Classical => None,
    };

    //
    // 2. PSK 존재성 확인 (양측 동등)
    //
    if hsm.psk_exists(psk_id).unwrap_u8() != 1 {
        return Err(TlsError::UnknownPsk);
    }

    //
    // 3. 양측 trasncript / EarlySecrets / BinderKey
    //
    let mut c_secrets = ScheduleSecrets::empty();
    let mut s_secrets = ScheduleSecrets::empty();
    derive_early_secrets(hsm, psk_id, &mut c_secrets)?;
    derive_early_secrets(hsm, psk_id, &mut s_secrets)?;

    //
    // 4. ClientHello 직렬화 (binder 제외 prefix)
    //
    // 길이 산정
    let kex_extra = match policy {
        KexPolicy::Hybrid => TLS_MLKEM768_PK_LEN,
        KexPolicy::Classical => 0,
    };
    let ch_payload_len = CH_FIXED_PREFIX_LEN + kex_extra + 1 /* binder_len */ + TLS_HASH_LEN;
    let ch_total_len = HS_HEADER_LEN + ch_payload_len;

    // 임시 빌드 버퍼 (스택, 1.4KB 한도)
    let mut ch =
        [0u8; HS_HEADER_LEN + CH_FIXED_PREFIX_LEN + TLS_MLKEM768_PK_LEN + 1 + TLS_HASH_LEN];
    write_handshake_header(&mut ch, HS_TYPE_CLIENT_HELLO, ch_payload_len)?;

    let mut p = HS_HEADER_LEN;
    ch[p..p + 16].copy_from_slice(psk_id.as_bytes());
    p += 16;
    let mut client_random = [0u8; 32];
    unsafe {
        capability::rand_bytes(&mut client_random).map_err(|_| TlsError::HsmFailure)?;
    }
    ch[p..p + 32].copy_from_slice(&client_random);
    p += 32;
    ch[p] = suite as u8;
    p += 1;
    ch[p] = match policy {
        KexPolicy::Hybrid => 1,
        KexPolicy::Classical => 0,
    };
    p += 1;
    ch[p..p + TLS_X25519_PK_LEN].copy_from_slice(client_x_pk.as_bytes());
    p += TLS_X25519_PK_LEN;
    if let Some(ref kp) = mlkem_kp {
        ch[p..p + TLS_MLKEM768_PK_LEN].copy_from_slice(&kp.ek);
        p += TLS_MLKEM768_PK_LEN;
    }
    // binder 위치 직전까지가 "truncated CH"
    let truncated_ch_end = p;
    ch[p] = TLS_HASH_LEN as u8;
    p += 1;
    let binder_pos = p;
    // binder 자리는 일단 0 으로 두고, MAC 계산 후 채움

    // truncated transcript = HS header + truncated_ch_payload
    let mut tc_transcript = Transcript::new();
    tc_transcript.update(&ch[..truncated_ch_end])?;
    let truncated_hash = tc_transcript.snapshot();

    // 클라이언트 binder 계산
    let mut binder = [0u8; TLS_HASH_LEN];
    keyschedule::compute_binder(c_secrets.binder_key.expose(), &truncated_hash, &mut binder)?;
    ch[binder_pos..binder_pos + TLS_HASH_LEN].copy_from_slice(&binder);

    //
    // 5. 서버측 binder 검증 (loopback 동일 코드 경로 구동)
    //
    let mut binder_expected = [0u8; TLS_HASH_LEN];
    keyschedule::compute_binder(
        s_secrets.binder_key.expose(),
        &truncated_hash,
        &mut binder_expected,
    )?;
    if !ct_eq_bytes(&binder, &binder_expected) {
        return Err(TlsError::FinishedMismatch);
    }

    //
    // 6. 양측 트랜스크립트에 CH 누적
    //
    {
        let cs = slot(client_h)?;
        cs.transcript.update(&ch[..ch_total_len])?;
    }
    {
        let ss = slot(server_h)?;
        ss.transcript.update(&ch[..ch_total_len])?;
    }

    //
    // 7. ServerHello 작성
    //
    let sh_kex_extra = match policy {
        KexPolicy::Hybrid => TLS_MLKEM768_CT_LEN,
        KexPolicy::Classical => 0,
    };
    let sh_payload_len = SH_FIXED_LEN + sh_kex_extra;
    let sh_total_len = HS_HEADER_LEN + sh_payload_len;

    let mut sh = [0u8; HS_HEADER_LEN + SH_FIXED_LEN + TLS_MLKEM768_CT_LEN];
    write_handshake_header(&mut sh, HS_TYPE_SERVER_HELLO, sh_payload_len)?;
    let mut q = HS_HEADER_LEN;
    let mut server_random = [0u8; 32];
    unsafe {
        capability::rand_bytes(&mut server_random).map_err(|_| TlsError::HsmFailure)?;
    }
    sh[q..q + 32].copy_from_slice(&server_random);
    q += 32;
    sh[q] = suite as u8;
    q += 1;
    sh[q..q + TLS_X25519_PK_LEN].copy_from_slice(server_x_pk.as_bytes());
    q += TLS_X25519_PK_LEN;

    //
    // 8. KEX 공유비밀 도출
    //
    let client_x_ss = client_x_sk.diffie_hellman(&server_x_pk);
    let server_x_ss = server_x_sk.diffie_hellman(&client_x_pk);
    if client_x_ss.as_bytes() != server_x_ss.as_bytes() {
        return Err(TlsError::Internal);
    }

    let mut hybrid_ss_buf = [0u8; TLS_KEM_SS_LEN + TLS_KEM_SS_LEN];
    let ecdhe_ss_slice: &[u8] = match policy {
        KexPolicy::Hybrid => {
            let kp = mlkem_kp.as_ref().ok_or(TlsError::Internal)?;
            let mut m = [0u8; 32];
            unsafe {
                capability::rand_bytes(&mut m).map_err(|_| TlsError::HsmFailure)?;
            }
            let (kem_ct, kem_ss_server) = mlkem768_encaps(&kp.ek, &m);
            m.fill(0);
            sh[q..q + TLS_MLKEM768_CT_LEN].copy_from_slice(&kem_ct);
            let kem_ss_client = mlkem768_decaps(&kem_ct, kp.dk.expose());
            if kem_ss_client.expose() != kem_ss_server.expose() {
                return Err(TlsError::Internal);
            }

            hybrid_ss_buf[..TLS_KEM_SS_LEN].copy_from_slice(client_x_ss.as_bytes());
            hybrid_ss_buf[TLS_KEM_SS_LEN..].copy_from_slice(kem_ss_client.expose());
            &hybrid_ss_buf[..]
        }
        KexPolicy::Classical => client_x_ss.as_bytes() as &[u8],
    };

    //
    // 9. SH 트랜스크립트 누적 + handshake_secrets 도출
    //
    {
        let cs = slot(client_h)?;
        cs.transcript.update(&sh[..sh_total_len])?;
    }
    {
        let ss = slot(server_h)?;
        ss.transcript.update(&sh[..sh_total_len])?;
    }
    let h_ch_sh = {
        let cs = slot(client_h)?;
        cs.transcript.snapshot()
    };
    derive_handshake_secrets(&mut c_secrets, ecdhe_ss_slice, &h_ch_sh, policy)?;
    derive_handshake_secrets(&mut s_secrets, ecdhe_ss_slice, &h_ch_sh, policy)?;
    // ECDHE 공유비밀 즉시 소거 (volatile-write 로 컴파일러 최적화 회피)
    // SAFETY: hybrid_ss_buf 는 stack 의 64B 유효 메모리
    unsafe {
        zeroize::volatile::secure_zero(hybrid_ss_buf.as_mut_ptr(), hybrid_ss_buf.len());
    }

    //
    // 10. ServerFinished
    //
    let mut s_fin_key = Secret::new([0u8; TLS_HASH_LEN]);
    keyschedule::derive_finished_key(
        s_secrets.server_handshake_traffic.expose(),
        s_fin_key.expose_mut(),
    )?;
    let mut sf_verify = [0u8; TLS_HASH_LEN];
    keyschedule::compute_verify_data(s_fin_key.expose(), &h_ch_sh, &mut sf_verify);

    let mut sf = [0u8; HS_HEADER_LEN + FIN_LEN];
    write_handshake_header(&mut sf, HS_TYPE_FINISHED, FIN_LEN)?;
    sf[HS_HEADER_LEN..HS_HEADER_LEN + FIN_LEN].copy_from_slice(&sf_verify);

    // 클라이언트는 SF 를 수신하여 자기 측 finished_key 로 동일 계산 후 비교
    let mut c_view_s_fin_key = Secret::new([0u8; TLS_HASH_LEN]);
    keyschedule::derive_finished_key(
        c_secrets.server_handshake_traffic.expose(),
        c_view_s_fin_key.expose_mut(),
    )?;
    let mut sf_expected = [0u8; TLS_HASH_LEN];
    keyschedule::compute_verify_data(c_view_s_fin_key.expose(), &h_ch_sh, &mut sf_expected);
    if !ct_eq_bytes(&sf_verify, &sf_expected) {
        return Err(TlsError::FinishedMismatch);
    }

    // SF 를 트랜스크립트에 누적
    {
        let cs = slot(client_h)?;
        cs.transcript.update(&sf)?;
    }
    {
        let ss = slot(server_h)?;
        ss.transcript.update(&sf)?;
    }

    //
    // 11. ClientFinished
    //
    let h_ch_sf = {
        let cs = slot(client_h)?;
        cs.transcript.snapshot()
    };
    let mut c_fin_key = Secret::new([0u8; TLS_HASH_LEN]);
    keyschedule::derive_finished_key(
        c_secrets.client_handshake_traffic.expose(),
        c_fin_key.expose_mut(),
    )?;
    let mut cf_verify = [0u8; TLS_HASH_LEN];
    keyschedule::compute_verify_data(c_fin_key.expose(), &h_ch_sf, &mut cf_verify);

    let mut cf = [0u8; HS_HEADER_LEN + FIN_LEN];
    write_handshake_header(&mut cf, HS_TYPE_FINISHED, FIN_LEN)?;
    cf[HS_HEADER_LEN..HS_HEADER_LEN + FIN_LEN].copy_from_slice(&cf_verify);

    // 서버측 검증
    let mut s_view_c_fin_key = Secret::new([0u8; TLS_HASH_LEN]);
    keyschedule::derive_finished_key(
        s_secrets.client_handshake_traffic.expose(),
        s_view_c_fin_key.expose_mut(),
    )?;
    let mut cf_expected = [0u8; TLS_HASH_LEN];
    keyschedule::compute_verify_data(s_view_c_fin_key.expose(), &h_ch_sf, &mut cf_expected);
    if !ct_eq_bytes(&cf_verify, &cf_expected) {
        return Err(TlsError::FinishedMismatch);
    }

    // CF 를 트랜스크립트에 누적
    {
        let cs = slot(client_h)?;
        cs.transcript.update(&cf)?;
    }
    {
        let ss = slot(server_h)?;
        ss.transcript.update(&cf)?;
    }

    //
    // 12. Application 트래픽 시크릿 도출
    //
    let h_ch_cf = {
        let cs = slot(client_h)?;
        cs.transcript.snapshot()
    };
    derive_master_and_app_secrets(&mut c_secrets, &h_ch_cf)?;
    derive_master_and_app_secrets(&mut s_secrets, &h_ch_cf)?;

    //
    // 13. application key/IV 설치
    //
    // client.write = C-AP-TS, client.read = S-AP-TS
    // server.write = S-AP-TS, server.read = C-AP-TS
    {
        let cs = slot(client_h)?;
        derive_traffic_keys(
            c_secrets.client_application_traffic_0.expose(),
            suite,
            cs.app_write.key.expose_mut(),
            cs.app_write.iv.expose_mut(),
        )?;
        derive_traffic_keys(
            c_secrets.server_application_traffic_0.expose(),
            suite,
            cs.app_read.key.expose_mut(),
            cs.app_read.iv.expose_mut(),
        )?;
        cs.app_write.seq = 0;
        cs.app_read.seq = 0;
        cs.state = ConnState::Connected;
    }
    {
        let ss = slot(server_h)?;
        derive_traffic_keys(
            s_secrets.server_application_traffic_0.expose(),
            suite,
            ss.app_write.key.expose_mut(),
            ss.app_write.iv.expose_mut(),
        )?;
        derive_traffic_keys(
            s_secrets.client_application_traffic_0.expose(),
            suite,
            ss.app_read.key.expose_mut(),
            ss.app_read.iv.expose_mut(),
        )?;
        ss.app_write.seq = 0;
        ss.app_read.seq = 0;
        ss.state = ConnState::Connected;
    }

    // 핸드셰이크 시크릿 / 임시 키는 함수 종료 시 Secret::Drop 으로 자동 소거됨
    // mlkem_kp 의 dk: Secret<[u8; 2400]> 도 동일하게 소거됨
    Ok(())
}

//
// 외부 공개: 단방향 record 송수신 헬퍼 (스모크 테스트용)
//

/// `from` 의 write 키로 평문을 암호화하여 record 를 만든 뒤, 동일 record 를
/// `to` 의 read 키로 복호화하여 평문을 회수. 양측 시퀀스 카운터 모두 증가.
///
/// # Errors
/// `InvalidHandle` / `BufferTooSmall` / `AuthenticationFailed`.
pub fn loopback_send_recv(
    from: ConnHandle,
    to: ConnHandle,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, TlsError> {
    let mut rec_buf = [0u8; 256]; // 한 record 임시 저장 (≤ MAX_PLAINTEXT_LEN+1+5+16)
    let suite = slot(from)?.suite;

    let rec_len = {
        let f = slot(from)?;
        if f.state != ConnState::Connected {
            return Err(TlsError::UnexpectedState);
        }
        crate::tls::record::encrypt_record(&mut f.app_write, suite, plaintext, &mut rec_buf)?
    };
    let pt_len = {
        let t = slot(to)?;
        if t.state != ConnState::Connected {
            return Err(TlsError::UnexpectedState);
        }
        crate::tls::record::decrypt_record(&mut t.app_read, suite, &rec_buf[..rec_len], out)?
    };
    Ok(pt_len)
}
