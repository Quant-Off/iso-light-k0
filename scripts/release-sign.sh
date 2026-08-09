#!/usr/bin/env bash
# iso-light-k0 릴리즈 아티팩트 ML-DSA-87 서명/검증 도구
#
# 폐쇄형 위협 모델임에 따라 외부 서명 도구(minisign/cosign)를 사용하지 않고 프로젝트 자체
# elib-k0-nt::mldsa (ML-DSA-87, NIST level 5)로 self-hosted 서명 체인을 구성합니다.
# hash-then-sign 방식 SHA-256(artifact) 32-옥텟 다이제스트를 ML-DSA-87로 서명합니다
# (ML-DSA 메시지 버퍼 한계 회피, 대용량 커널 바이너리 직접 서명 불가).
#
# 서브커맨드
#   keygen                                프로덕션 서명 키쌍 생성 (sk 는 오프라인 보관)
#   sign   <artifact> --sk <sk> [--out <sig>]   아티팩트 서명 -> <artifact>.sig87
#   verify <artifact> --pk <pk> --sig <sig>     서명 검증 (exit 0=OK 1=FAIL)
#
# 예
#   bash scripts/release-sign.sh keygen
#   bash scripts/release-sign.sh sign  target/x86_64-unknown-none/release/iso-light-k0 --sk keys/release_signing.sk87
#   bash scripts/release-sign.sh verify target/x86_64-unknown-none/release/iso-light-k0 --pk keys/release_signing.pk87 --sig target/x86_64-unknown-none/release/iso-light-k0.sig87
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ELIB_NT_DIR="${ELIB_NT_DIR:-$REPO_ROOT/../elib-k0-nt}"

# 서명 컨텍스트 도메인 분리 태그 (ML-DSA ctx, 어테스테이션 태그와 구분)
SIG_CTX="ISO-K0-RELEASE-V1"

die() { echo "[release-sign] FAIL: $*" >&2; exit 1; }

[ -d "$ELIB_NT_DIR/mldsa" ] || die "elib-k0-nt/mldsa 경로를 찾을 수 없음. ($ELIB_NT_DIR) ELIB_NT_DIR로 지정 가능"

# host sha256 도구 폴백
sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum / shasum을 찾을 수 없음"
    fi
}

# ML-DSA-87 helper 크레이트를 1회 빌드하고 경로를 HELPER_BIN에 설정
build_helper() {
    TMP_HELPER="$(mktemp -d -t k0-release-signer-XXXXXX)"
    trap 'rm -rf "$TMP_HELPER"' EXIT
    cat > "$TMP_HELPER/Cargo.toml" <<EOF
[package]
name = "k0-release-signer"
version = "0.0.1"
edition = "2024"

[dependencies]
mldsa = { path = "$ELIB_NT_DIR/mldsa" }

[[bin]]
name = "signer"
path = "src/main.rs"
EOF
    mkdir -p "$TMP_HELPER/src"
    cat > "$TMP_HELPER/src/main.rs" <<'EOF'
use std::env;
use std::fs;
use std::process::ExitCode;
use mldsa::MLDSA87;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let usage = || eprintln!("usage: signer <keygen SEEDHEX OUTPK OUTSK | sign SK DIGESTHEX RNDHEX OUTSIG | verify PK DIGESTHEX SIG>");
    if args.len() < 2 { usage(); return ExitCode::from(2); }
    match args[1].as_str() {
        "keygen" if args.len() == 5 => {
            let seed_v = match hex_decode(&args[2]) { Some(v) if v.len() == 32 => v, _ => { eprintln!("seed must be 32-byte hex"); return ExitCode::from(3); } };
            let mut seed = [0u8; 32]; seed.copy_from_slice(&seed_v);
            let (pk, sk) = match MLDSA87::keygen(&seed) { Ok(v) => v, Err(_) => { eprintln!("keygen failed"); return ExitCode::from(4); } };
            fs::write(&args[3], &pk).expect("write pk");
            fs::write(&args[4], &sk).expect("write sk");
            println!("OK keygen pk={} sk={}", pk.len(), sk.len());
            ExitCode::SUCCESS
        }
        "sign" if args.len() == 6 => {
            let sk_v = fs::read(&args[2]).expect("read sk");
            if sk_v.len() != MLDSA87::SK_LEN { eprintln!("sk len {} != {}", sk_v.len(), MLDSA87::SK_LEN); return ExitCode::from(5); }
            let mut sk = [0u8; MLDSA87::SK_LEN]; sk.copy_from_slice(&sk_v);
            let digest = match hex_decode(&args[3]) { Some(v) => v, None => { eprintln!("bad digest hex"); return ExitCode::from(6); } };
            let rnd_v = match hex_decode(&args[4]) { Some(v) if v.len() == 32 => v, _ => { eprintln!("rnd must be 32-byte hex"); return ExitCode::from(7); } };
            let mut rnd = [0u8; 32]; rnd.copy_from_slice(&rnd_v);
            let sig = match MLDSA87::sign(&sk, &digest, b"ISO-K0-RELEASE-V1", &rnd) { Ok(s) => s, Err(_) => { eprintln!("sign failed"); return ExitCode::from(8); } };
            fs::write(&args[5], &sig).expect("write sig");
            println!("OK sign sig={}", sig.len());
            ExitCode::SUCCESS
        }
        "verify" if args.len() == 5 => {
            let pk_v = fs::read(&args[2]).expect("read pk");
            if pk_v.len() != MLDSA87::PK_LEN { eprintln!("pk len {} != {}", pk_v.len(), MLDSA87::PK_LEN); return ExitCode::from(9); }
            let mut pk = [0u8; MLDSA87::PK_LEN]; pk.copy_from_slice(&pk_v);
            let digest = match hex_decode(&args[3]) { Some(v) => v, None => { eprintln!("bad digest hex"); return ExitCode::from(10); } };
            let sig_v = fs::read(&args[4]).expect("read sig");
            if sig_v.len() != MLDSA87::SIG_LEN { eprintln!("sig len {} != {}", sig_v.len(), MLDSA87::SIG_LEN); return ExitCode::from(11); }
            let mut sig = [0u8; MLDSA87::SIG_LEN]; sig.copy_from_slice(&sig_v);
            match MLDSA87::verify(&pk, &digest, &sig, b"ISO-K0-RELEASE-V1") {
                Ok(true) => { println!("OK verify"); ExitCode::SUCCESS }
                Ok(false) => { eprintln!("verify: signature INVALID"); ExitCode::from(1) }
                Err(_) => { eprintln!("verify error"); ExitCode::from(1) }
            }
        }
        _ => { usage(); ExitCode::from(2) }
    }
}
EOF
    ( cd "$TMP_HELPER" && cargo build --release --quiet ) || die "helper 빌드 실패"
    HELPER_BIN="$TMP_HELPER/target/release/signer"
}

rand_hex32() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cmd_keygen() {
    local out_dir="${OUT_DIR:-$REPO_ROOT/keys}"
    mkdir -p "$out_dir"
    local out_pk="$out_dir/release_signing.pk87"
    local out_sk="$out_dir/release_signing.sk87"
    [ -e "$out_sk" ] && die "$out_sk 이미 존재(덮어쓰기 방지, 수동 제거 필요)"
    build_helper
    # 프로덕션 서명 키 시드는 HW 엔트로피 (dev 0xAA 결정론과 명확히 구분)
    local seed; seed="$(rand_hex32)"
    "$HELPER_BIN" keygen "$seed" "$out_pk" "$out_sk"
    chmod 600 "$out_sk"
    echo "[release-sign] PASS keygen pk=$out_pk sk=$out_sk (sk는 오프라인 보관, keys/*.sk* 이그노어링 대상)"
}

cmd_sign() {
    local artifact="$1"; shift
    local sk="" out=""
    while [ $# -gt 0 ]; do case "$1" in
        --sk) sk="$2"; shift 2;;
        --out) out="$2"; shift 2;;
        *) die "sign 알 수 없는 인자 $1";;
    esac; done
    [ -f "$artifact" ] || die "아티팩트 미존재 $artifact"
    [ -n "$sk" ] && [ -f "$sk" ] || die "--sk <서명 개인키> 필요"
    [ -n "$out" ] || out="$artifact.sig87"
    build_helper
    local digest; digest="$(sha256_hex "$artifact")"
    local rnd; rnd="$(rand_hex32)"
    "$HELPER_BIN" sign "$sk" "$digest" "$rnd" "$out"
    echo "[release-sign] PASS sign artifact=$artifact digest=sha256:$digest sig=$out"
}

cmd_verify() {
    local artifact="$1"; shift
    local pk="" sig=""
    while [ $# -gt 0 ]; do case "$1" in
        --pk) pk="$2"; shift 2;;
        --sig) sig="$2"; shift 2;;
        *) die "verify 알 수 없는 인자 $1";;
    esac; done
    [ -f "$artifact" ] || die "아티팩트 미존재 $artifact"
    [ -n "$pk" ] && [ -f "$pk" ] || die "--pk <서명 공개키> 필요"
    [ -n "$sig" ] && [ -f "$sig" ] || die "--sig <서명 파일> 필요"
    build_helper
    local digest; digest="$(sha256_hex "$artifact")"
    if "$HELPER_BIN" verify "$pk" "$digest" "$sig"; then
        echo "[release-sign] PASS verify artifact=$artifact digest=sha256:$digest (ML-DSA-87 서명 유효)"
        exit 0
    fi
    echo "[release-sign] FAIL verify artifact=$artifact 서명 무효 또는 아티팩트 변조" >&2
    exit 1
}

MODE="${1:-}"; shift || true
case "$MODE" in
    keygen) cmd_keygen "$@";;
    sign)   cmd_sign "$@";;
    verify) cmd_verify "$@";;
    *) echo "usage: $0 <keygen|sign|verify> ..." >&2; exit 2;;
esac
