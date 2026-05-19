#!/usr/bin/env bash
# Phase 5 D-02 / RESEARCH §10.1 dev trust root keygen
# host (Ubuntu 24.04 권장) 측에서 1 회 실행하여 keys/trust_root.pk44 + keys/dev_trust_root.sk44 생성
# 본 스크립트는 elib-k0-nt::mldsa::MLDSA44::keygen(&[0xAA_u8; 32]) 을 호출하는 임시 helper 크레이트를
# 작성 후 cargo run 으로 1 회 실행하고 산출 binary 2 개를 keys/ 디렉터리에 dump

set -euo pipefail

# 경로 결정 — script 위치 기준
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"
ELIB_NT_DIR="${ELIB_NT_DIR:-$REPO_ROOT/../elib-k0-nt}"

if [ ! -d "$ELIB_NT_DIR/mldsa" ]; then
    echo "[gen-dev-keys] FAIL: elib-k0-nt/mldsa 경로 미존재 ($ELIB_NT_DIR)" >&2
    echo "  ELIB_NT_DIR 환경변수로 elib-k0-nt 위치 지정 가능" >&2
    exit 1
fi

OUT_PK="${OUT_PK:-$REPO_ROOT/keys/trust_root.pk44}"
OUT_SK="${OUT_SK:-$REPO_ROOT/keys/dev_trust_root.sk44}"

mkdir -p "$REPO_ROOT/keys"

# 임시 helper 크레이트 작성 (host std 환경)
TMP_HELPER="$(mktemp -d -t phase5-keygen-XXXXXX)"
trap 'rm -rf "$TMP_HELPER"' EXIT

cat > "$TMP_HELPER/Cargo.toml" <<EOF
[package]
name = "phase5-keygen-helper"
version = "0.0.1"
edition = "2024"

[dependencies]
mldsa = { path = "$ELIB_NT_DIR/mldsa" }

[[bin]]
name = "gen"
path = "src/main.rs"
EOF

mkdir -p "$TMP_HELPER/src"
cat > "$TMP_HELPER/src/main.rs" <<'EOF'
use std::env;
use std::fs;
use std::process::ExitCode;
use mldsa::MLDSA44;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: gen <out_pk> <out_sk>");
        return ExitCode::from(2);
    }
    // dev-only deterministic seed (RESEARCH §10.1)
    let seed: [u8; 32] = [0xAA_u8; 32];
    let (pk, sk) = match MLDSA44::keygen(&seed) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("MLDSA44::keygen failed");
            return ExitCode::from(3);
        }
    };
    if pk.len() != 1312 {
        eprintln!("pk len != 1312"); return ExitCode::from(4);
    }
    if sk.len() != 2560 {
        eprintln!("sk len != 2560"); return ExitCode::from(5);
    }
    fs::write(&args[1], &pk).expect("write pk");
    fs::write(&args[2], &sk).expect("write sk");
    println!("OK: wrote pk {} bytes and sk {} bytes", pk.len(), sk.len());
    ExitCode::SUCCESS
}
EOF

# helper build + run
( cd "$TMP_HELPER" && cargo build --release --quiet )
"$TMP_HELPER/target/release/gen" "$OUT_PK" "$OUT_SK"

# 크기 검증
PK_SIZE=$(wc -c < "$OUT_PK" | tr -d ' ')
SK_SIZE=$(wc -c < "$OUT_SK" | tr -d ' ')
if [ "$PK_SIZE" != "1312" ]; then
    echo "[gen-dev-keys] FAIL: pk 크기 $PK_SIZE 옥텟 (기대 1312)" >&2
    exit 1
fi
if [ "$SK_SIZE" != "2560" ]; then
    echo "[gen-dev-keys] FAIL: sk 크기 $SK_SIZE 옥텟 (기대 2560)" >&2
    exit 1
fi

echo "[gen-dev-keys] PASS: pk=$OUT_PK (1312 B) sk=$OUT_SK (2560 B)"
exit 0
