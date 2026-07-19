// iso-light-k0 빌드 스크립트
//
// 사용자 ELF (`crates/iso-user-hello/`, 추후 `crates/iso-user-lumen/`) 를
// `OUT_DIR` 에 복사하고, 그 절대 경로를 `cargo:rustc-env` 로 노출하여
// 커널 소스에서 `include_bytes!(env!(...))` 로 임베드할 수 있게 합니다.
//
// 사용자 ELF 가 아직 빌드되지 않았으면 placeholder(4 바이트 ELF magic) 를
// 대신 임베드하여 커널 자체 빌드는 항상 통과시킵니다. placeholder 는 ELF
// 파서(`src/elf.rs::parse`) 가 `BadMagic`/`Truncated` 로 거절하므로 사용자
// 프로세스 spawn 시도가 안전하게 실패합니다.
//
// 진짜 ELF 임베드는 `make build` (사용자 빌드 prerequisite) 흐름에서 수행됩니다.

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

    // Phase D 가 추가하면 활성화. placeholder 로 남겨둠.
    embed_user_elf(
        &manifest_dir,
        &out_dir,
        "iso-user-lumen",
        "ISO_USER_LUMEN_ELF",
    );

    // Phase 5 RESEARCH §4.2 신뢰 루트 pk44 부재 시 빌드 일찍 실패
    // src/hsm_attest.rs 의 include_bytes! 가 의존하므로 명시 가드 + rerun-if-changed
    let trust_root_pk = PathBuf::from(&manifest_dir).join("keys/trust_root.pk44");
    if !trust_root_pk.exists() {
        panic!(
            "Phase 5 trust root pk44 missing: {} (run scripts/gen-dev-keys.sh)",
            trust_root_pk.display()
        );
    }
    println!("cargo:rerun-if-changed={}", trust_root_pk.display());

    // C1 개발용 신뢰 루트 탐지 게이트
    //
    // scripts/gen-dev-keys.sh 는 MLDSA44::keygen(&[0xAA; 32]) 결정론적 시드로
    // trust_root.pk44 를 생성하므로 개인키를 누구나 복원할 수 있음. 이 개발 키가
    // 출하 바이너리에 임베드되면 어테스테이션 신뢰 앵커가 위조 가능해짐(C1)
    //
    // 정책
    //   - 개발 키 지문(FNV-1a-64)이 일치하면 매 빌드 cargo:warning 로 경고
    //   - K0_REQUIRE_PROD_TRUST_ROOT=1|true|yes 설정 시 개발 키면 빌드 fatal
    //     (CI, release 파이프라인이 출하 산출물에 개발 키 유입을 차단하는 게이트)
    //   - K0_ALLOW_DEV_TRUST_ROOT=1|true|yes 는 require 하에서도 개발 키를 명시
    //     허용(로컬 release 검증용 escape hatch)
    //
    // 참고 현재 committed 개발 키 SHA-256
    //   ad4aff7ef5aa8895fb4f59c2c211afe55419d0d8709bfa0ee4d8f496e92600a7
    const DEV_TRUST_ROOT_FNV1A64: u64 = 0x0c4e_fb6d_d994_ad6d;
    println!("cargo:rerun-if-env-changed=K0_REQUIRE_PROD_TRUST_ROOT");
    println!("cargo:rerun-if-env-changed=K0_ALLOW_DEV_TRUST_ROOT");
    let pk_bytes = fs::read(&trust_root_pk)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", trust_root_pk.display()));
    if fnv1a64(&pk_bytes) == DEV_TRUST_ROOT_FNV1A64 {
        let require_prod = env_truthy("K0_REQUIRE_PROD_TRUST_ROOT");
        let allow_dev = env_truthy("K0_ALLOW_DEV_TRUST_ROOT");
        if require_prod && !allow_dev {
            panic!(
                "keys/trust_root.pk44 is the deterministic DEV trust root (seed 0xAA*32, \
                 private key publicly reproducible). Provision a production trust root, or set \
                 K0_ALLOW_DEV_TRUST_ROOT=1 to override. (C1)"
            );
        }
        println!(
            "cargo:warning=keys/trust_root.pk44 is the DEV trust root (C1): attestation anchor is \
             forgeable. Do NOT ship. Set K0_REQUIRE_PROD_TRUST_ROOT=1 to hard-fail release builds."
        );
    }

    // Phase 5.1 D-01 K0_TRUST_ROOT_KEYSTORE env → cargo:rustc-cfg=k0_trust_root_keystore
    //
    // 설정 값이 "1" | "true" | "yes" (trim 후) 중 하나면 cfg 활성 그 외는 비활성 (const 폴백)
    // Pitfall 5 회피 trailing newline trim + 다중 truthy 표현 허용
    println!("cargo:rerun-if-env-changed=K0_TRUST_ROOT_KEYSTORE");
    let keystore_env = std::env::var("K0_TRUST_ROOT_KEYSTORE")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if matches!(keystore_env.as_str(), "1" | "true" | "yes") {
        println!("cargo:rustc-cfg=k0_trust_root_keystore");
    }
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

    // `cargo:rerun-if-changed` 는 단일 경로만 받으므로 ELF 자체 변경을 감시.
    // 디렉토리 자체가 없을 수도 있으나(Phase D 미완 시), Cargo 는 그 경우
    // 무시함 — 사실상 placeholder 모드에선 매 빌드마다 재실행될 수 있음.
    println!("cargo:rerun-if-changed={}", elf_path.display());
    println!(
        "cargo:rustc-env={env_var}={path}",
        env_var = env_var,
        path = dest.display()
    );

    // OUT_DIR 자체에도 변경 감시
    let _ = Path::new(out_dir);
}
