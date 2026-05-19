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
