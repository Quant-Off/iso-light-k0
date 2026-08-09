// iso-light-k0 빌드 스크립트
//
// 사용자 ELF (`crates/iso-user-hello/`, 추후 `crates/iso-user-lumen/`) 를
// `OUT_DIR` 에 복사하고, 그 절대 경로를 `cargo:rustc-env` 로 노출해
// 커널 소스에서 `include_bytes!(env!(...))` 로 임베드 가능
//
// 사용자 ELF 가 아직 빌드되지 않았으면 placeholder(4 바이트 ELF magic) 를
// 대신 임베드해 커널 자체 빌드는 항상 통과시킴 이 placeholder 는 ELF
// 파서(`src/elf.rs::parse`) 가 `BadMagic`/`Truncated` 로 거절하므로 사용자
// 프로세스 spawn 시도가 안전하게 실패
//
// 진짜 ELF 임베드는 `make build` (사용자 빌드 prerequisite) 흐름에서 수행

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");

    embed_user_elf(
        &manifest_dir,
        &out_dir,
        "iso-user-hello",
        "ISO_USER_HELLO_ELF",
    );

    // lumen ELF 가 아직 없으면 placeholder 로 남겨둠
    embed_user_elf(
        &manifest_dir,
        &out_dir,
        "iso-user-lumen",
        "ISO_USER_LUMEN_ELF",
    );

    // 신뢰 루트 dual-path (fail-closed 폴백 + 프로덕션 키스토어 임베드)
    //
    // K0_TRUST_ROOT_KEYSTORE 가 프로덕션 ML-DSA-44 공개키 파일 경로를 가리키면
    // 그 키를 검증 후 임베드해 dev 상수를 완전히 대체하고, 미지정 release
    // 빌드는 dev 결정론 신뢰 루트를 fatal 로 거부
    println!("cargo:rerun-if-env-changed=K0_TRUST_ROOT_KEYSTORE");
    println!("cargo:rerun-if-env-changed=K0_REQUIRE_PROD_TRUST_ROOT");
    println!("cargo:rerun-if-env-changed=K0_ALLOW_DEV_TRUST_ROOT");

    let is_release = env::var("PROFILE").map(|p| p == "release").unwrap_or(false);
    let allow_dev = env_truthy("K0_ALLOW_DEV_TRUST_ROOT");
    let require_prod = env_truthy("K0_REQUIRE_PROD_TRUST_ROOT");

    let keystore_path = env::var("K0_TRUST_ROOT_KEYSTORE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let dev_trust_root_pk = PathBuf::from(&manifest_dir).join("keys/trust_root.pk44");

    match keystore_path {
        // 프로덕션 키스토어 end-to-end 임베드 경로
        Some(path) => provision_prod_trust_root(&path, &out_dir),
        // dev 신뢰 루트 폴백 경로 (release fail-by-default)
        None => embed_dev_trust_root(&dev_trust_root_pk, is_release, allow_dev, require_prod),
    }
}

/// ML-DSA-44 공개키 옥텟 길이.
const MLDSA44_PK_LEN: usize = 1312;

/// 개발용 결정론 신뢰 루트(seed 0xAA*32)의 FNV-1a-64 지문.
///
/// 참고 현재 committed 개발 키 SHA-256
///   ad4aff7ef5aa8895fb4f59c2c211afe55419d0d8709bfa0ee4d8f496e92600a7
const DEV_TRUST_ROOT_FNV1A64: u64 = 0x0c4e_fb6d_d994_ad6d;

/// 프로덕션 ML-DSA-44 신뢰 루트를 검증하고 임베드한다.
///
/// `K0_TRUST_ROOT_KEYSTORE` 가 지정한 외부 공개키 파일을 읽어 포맷과 길이, dev 지문을
/// 검증하고, `OUT_DIR` 로 복사한 뒤 그 경로를 `K0_TRUST_ROOT_KEYSTORE_PATH` 로
/// 노출한다. 소스는 `include_bytes!(env!(...))` 로 이 파일만 임베드하므로 dev 상수는
/// 바이너리에서 완전히 사라진다.
///
/// # Panics
/// 파일 부재, 길이 불일치, all-zero, dev 지문 일치 시 빌드를 fatal 로 중단한다.
fn provision_prod_trust_root(keystore_path: &str, out_dir: &str) {
    let ks = Path::new(keystore_path);
    let bytes = fs::read(ks).unwrap_or_else(|e| {
        panic!(
            "K0_TRUST_ROOT_KEYSTORE '{}' read failed: {e} \
             (must be a production ML-DSA-44 public key file path)",
            ks.display()
        )
    });
    // 포맷과 길이 검증 (ML-DSA-44 PK = 1312 옥텟)
    if bytes.len() != MLDSA44_PK_LEN {
        panic!(
            "K0_TRUST_ROOT_KEYSTORE '{}' length {} != {} (not an ML-DSA-44 public key)",
            ks.display(),
            bytes.len(),
            MLDSA44_PK_LEN
        );
    }
    // all-zero 공개키 거부
    if bytes.iter().all(|&b| b == 0) {
        panic!("K0_TRUST_ROOT_KEYSTORE '{}' is an all-zero public key (invalid)", ks.display());
    }
    // dev 키 laundering 거부 (dev 지문을 keystore 경로로 우회 금지)
    if fnv1a64(&bytes) == DEV_TRUST_ROOT_FNV1A64 {
        panic!(
            "K0_TRUST_ROOT_KEYSTORE '{}' is the deterministic DEV trust root (seed 0xAA*32). \
             Provision a real production key. (C1)",
            ks.display()
        );
    }
    // OUT_DIR 로 복사 후 절대 경로를 rustc-env 로 노출 (include_bytes! 대상)
    let dest = PathBuf::from(out_dir).join("trust_root_prod.pk44");
    fs::write(&dest, &bytes)
        .unwrap_or_else(|e| panic!("failed to stage keystore key {}: {e}", dest.display()));
    println!("cargo:rustc-cfg=k0_trust_root_keystore");
    println!("cargo:rustc-env=K0_TRUST_ROOT_KEYSTORE_PATH={}", dest.display());
    println!("cargo:rerun-if-changed={}", ks.display());
    println!(
        "cargo:warning=production trust root embedded from K0_TRUST_ROOT_KEYSTORE \
         (dev trust root is NOT embedded)"
    );
}

/// dev 신뢰 루트를 폴백 임베드하고 fail-closed 게이트를 집행한다.
///
/// release 프로필은 dev 키를 기본 fatal 로 거부한다 (fail-by-default). debug 프로필은
/// 경고만 출력해 개발 워크플로를 유지한다. `K0_ALLOW_DEV_TRUST_ROOT` 로만 fatal 을
/// 우회할 수 있고, `K0_REQUIRE_PROD_TRUST_ROOT` 는 debug 도 fatal 로 승격한다.
///
/// # Panics
/// dev pk44 부재, 또는 dev 키 감지 + fatal 조건 성립 시 빌드를 중단한다.
fn embed_dev_trust_root(dev_pk: &Path, is_release: bool, allow_dev: bool, require_prod: bool) {
    if !dev_pk.exists() {
        panic!(
            "trust root pk44 missing: {} \
             (run scripts/gen-dev-keys.sh, or set K0_TRUST_ROOT_KEYSTORE=<pk44 path>)",
            dev_pk.display()
        );
    }
    println!("cargo:rerun-if-changed={}", dev_pk.display());
    let pk_bytes =
        fs::read(dev_pk).unwrap_or_else(|e| panic!("failed to read {}: {e}", dev_pk.display()));
    // keys/trust_root.pk44 가 dev 지문이 아니면 (사용자가 프로덕션 키로 교체) 통과
    if fnv1a64(&pk_bytes) != DEV_TRUST_ROOT_FNV1A64 {
        return;
    }
    // dev 신뢰 루트 감지 fail-closed 게이트
    let must_fail = (is_release || require_prod) && !allow_dev;
    if must_fail {
        panic!(
            "keys/trust_root.pk44 is the deterministic DEV trust root (seed 0xAA*32, private key \
             publicly reproducible). Inject a production trust root via \
             K0_TRUST_ROOT_KEYSTORE=<pk44 path>, or set K0_ALLOW_DEV_TRUST_ROOT=1 for local \
             release verification. (C1)"
        );
    }
    println!(
        "cargo:warning=keys/trust_root.pk44 is the DEV trust root (C1): attestation anchor is \
         forgeable. Do NOT ship. Provision K0_TRUST_ROOT_KEYSTORE for release."
    );
}

/// FNV-1a 64-bit 해시. 특정 알려진 아티팩트(개발 신뢰 루트) 식별 전용.
///
/// 암호학적 용도가 아니라 committed 파일 지문 매칭 목적이므로 외부 의존성 없이
/// 자립적으로 구현함(에어갭 빌드 공급망 표면 0 유지).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// 환경변수가 "1" | "true" | "yes" (trim 후) 중 하나면 true.
fn env_truthy(key: &str) -> bool {
    env::var(key)
        .ok()
        .map(|s| matches!(s.trim(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// 사용자 크레이트의 release ELF 를 OUT_DIR 로 복사하고 환경변수로 노출.
///
/// 입력 `crate_name` 은 `crates/<crate_name>/` 디렉토리와 동일한 빌드 산출물
/// 이름이라고 가정함. ELF 가 없으면 4-byte placeholder 를 작성.
fn embed_user_elf(manifest_dir: &str, out_dir: &str, crate_name: &str, env_var: &str) {
    let elf_path = PathBuf::from(manifest_dir)
        .join("crates")
        .join(crate_name)
        .join("target/x86_64-unknown-none/release")
        .join(crate_name);

    let dest_name = format!("{crate_name}.elf");
    let dest = PathBuf::from(out_dir).join(&dest_name);

    if elf_path.exists() {
        fs::copy(&elf_path, &dest)
            .unwrap_or_else(|e| panic!("failed to copy {}: {e}", elf_path.display()));
    } else {
        // 4-byte ELF magic-only placeholder
        fs::write(&dest, b"\x7fELF")
            .unwrap_or_else(|e| panic!("failed to write placeholder {}: {e}", dest.display()));
    }

    // `cargo:rerun-if-changed` 는 단일 경로만 받으므로 ELF 자체 변경을 감시
    // 디렉토리 자체가 없을 수도 있으나(크레이트 미빌드 시), Cargo 는 그 경우
    // 무시하며 사실상 placeholder 모드에선 매 빌드마다 재실행될 수 있음
    println!("cargo:rerun-if-changed={}", elf_path.display());
    println!(
        "cargo:rustc-env={env_var}={path}",
        env_var = env_var,
        path = dest.display()
    );

    // OUT_DIR 자체에도 변경 감시
    let _ = Path::new(out_dir);
}
