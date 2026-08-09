#!/usr/bin/env python3
"""k0 CycloneDX SBOM 생성기

Cargo.lock, Cargo.toml 만으로 CycloneDX 1.5 JSON SBOM 산출. 외부 패키지
의존이 0(python3 stdlib tomllib/json/hashlib 만 사용)이므로 폐쇄형 릴리즈
파이프라인에서 그대로 실행 가능합니다.

결정론 보장 컴포넌트를 name,version으로 정렬하고 timestamp를 넣지 않으며
serialNumber를 lockfile 내용 해시에서 유도하여 동일 입력 -> 동일 SBOM 을 보장합니다.

사용
    python3 scripts/gen-sbom.py > sbom.cdx.json
    python3 scripts/gen-sbom.py --output sbom.cdx.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_toml(path: Path) -> dict:
    with path.open("rb") as f:
        return tomllib.load(f)


def deterministic_serial(lock_bytes: bytes) -> str:
    """lockfile 바이트에서 UUID 형태의 결정론 serialNumber를 유도합니다."""
    h = hashlib.sha256(lock_bytes).hexdigest()
    # RFC 4122 형태 (8-4-4-4-12) 로 배치 실제 version/variant 비트는 무의미하나
    # SBOM 소비자가 URN 으로 파싱 가능하도록 형식만 맞춘다
    return f"urn:uuid:{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def purl(name: str, version: str) -> str:
    return f"pkg:cargo/{name}@{version}"


def build_sbom() -> dict:
    cargo_toml = load_toml(REPO_ROOT / "Cargo.toml")
    lock_path = REPO_ROOT / "Cargo.lock"
    lock_bytes = lock_path.read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))

    root_name = cargo_toml["package"]["name"]
    root_version = cargo_toml["package"]["version"]

    packages = lock.get("package", [])
    components = []
    for pkg in sorted(packages, key=lambda p: (p["name"], p["version"])):
        name = pkg["name"]
        version = pkg["version"]
        # 루트 크레이트 자신은 metadata.component 로 별도 기술 컴포넌트 목록에서 제외
        if name == root_name and version == root_version:
            continue
        source = pkg.get("source", "local-path")
        comp = {
            "type": "library",
            "bom-ref": purl(name, version),
            "name": name,
            "version": version,
            "purl": purl(name, version),
            "properties": [{"name": "cargo:source", "value": source}],
        }
        checksum = pkg.get("checksum")
        if checksum:
            comp["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": deterministic_serial(lock_bytes),
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": purl(root_name, root_version),
                "name": root_name,
                "version": root_version,
                "purl": purl(root_name, root_version),
                "description": "no_std zero-trust air-gapped security microkernel",
            },
            "properties": [
                {"name": "sbom:generator", "value": "scripts/gen-sbom.py"},
                {"name": "sbom:deterministic", "value": "true"},
            ],
        },
        "components": components,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="iso-light-k0 CycloneDX SBOM 생성기")
    ap.add_argument("--output", "-o", help="출력 파일 경로 (기본 stdout)")
    args = ap.parse_args()

    sbom = build_sbom()
    # sort_keys 로 키 순서까지 결정론 고정
    text = json.dumps(sbom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        n = len(sbom["components"])
        print(f"[sbom] wrote {args.output} ({n} components)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
