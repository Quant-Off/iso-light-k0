# 릴리즈 엔지니어링

본 문서는 iso-light-k0 프로덕션 릴리즈의 재현 가능한 빌드(P2-3), SBOM 산출(P2-4), 아티팩트 서명·검증(P2-2) 절차를 정의한다. 모든 도구는 외부 패키지 의존이 0 이며(python3 stdlib 와 프로젝트 자체 `elib-k0-nt::mldsa` 만 사용) 에어갭 환경에서 그대로 실행된다.

## 사전 조건

- `../elib-k0-nt` sibling 리포가 기대 경로에 체크아웃되어 있을 것 (`ELIB_NT_DIR` 로 재지정 가능).
- 프로덕션 ML-DSA-44 신뢰 루트 공개키 파일 (C1/M10). `keys/trust_root.pk44` 의 dev 키는 release 에서 거부된다.

## 1. 재현 가능한 빌드 (P2-3)

### 툴체인 고정

로컬 개발은 rolling `nightly` 를 유지해도 되나, 릴리즈 빌드는 날짜 고정 채널을 사용한다. 검증 기준 툴체인은 다음과 같다.

```
rustc 1.98.0-nightly (54333ff07 2026-05-22)
```

통제된 릴리즈 환경에서는 `rust-toolchain.toml` 의 channel 을 고정한다.

```toml
[toolchain]
channel = "nightly-2026-05-22"
```

### 결정론 빌드 플래그

재현성은 다음 조합으로 보장된다.

- `Cargo.lock` 추적 + `--locked` (의존성 버전 고정, P2-1).
- `profile.release` 의 `panic = "abort"`, `lto = true`, `opt-level = "z"` (`Cargo.toml` 고정).
- `code-model = "kernel"` 와 링커 스크립트 `linker.ld` (`.cargo/config.toml` 고정).

### 프로덕션 빌드

프로덕션 신뢰 루트를 주입하여 빌드한다. dev escape hatch 는 사용하지 않으므로 dev 키가 감지되면 fail-closed 된다.

```
K0_TRUST_ROOT_KEYSTORE=/secure/path/prod_trust_root.pk44 make build-prod
```

`build-prod` 는 `cargo build --locked --target x86_64-unknown-none --release` 를 수행한다.

### 빌드 해시 기록

동일 소스 + 동일 툴체인 -> 동일 바이너리 해시를 검증한다.

```
K0_TRUST_ROOT_KEYSTORE=/secure/path/prod_trust_root.pk44 make release-hash
```

`release-hash.txt` 에 프로덕션 바이너리 SHA-256 과 툴체인 버전이 기록된다. 독립 재빌드의 해시가 일치하면 재현성이 확인된다.

## 2. SBOM (P2-4)

`Cargo.lock` 과 `Cargo.toml` 만으로 CycloneDX 1.5 JSON SBOM 을 산출한다.

```
make sbom
```

`sbom.cdx.json` 이 생성된다. 산출물은 결정론적이다 (컴포넌트 name,version 정렬, timestamp 부재, serialNumber 를 lockfile 해시에서 유도). 동일 `Cargo.lock` -> byte-identical SBOM 이므로 재현빌드와 정합한다. registry 의존성은 SHA-256 해시를 포함하고 path 의존성(elib-k0-nt)은 `cargo:source=local-path` 속성으로 표기된다.

## 3. 아티팩트 서명·검증 (P2-2)

에어갭 위협 모델 정합을 위해 외부 서명 도구 대신 프로젝트 자체 ML-DSA-87(NIST level 5) self-hosted 서명 체인을 사용한다. hash-then-sign 방식으로 SHA-256(artifact) 다이제스트를 서명한다.

### 서명 키 생성 (1 회)

```
bash scripts/release-sign.sh keygen
```

`keys/release_signing.pk87` (공개키, 추적·배포 대상) 과 `keys/release_signing.sk87` (개인키, `keys/*.sk*` gitignore 대상, 오프라인 보관 필수) 이 생성된다. 시드는 HW 엔트로피에서 취하므로 dev 결정론 키(0xAA)와 명확히 구분된다.

### 서명

```
make sign-release
# 또는
bash scripts/release-sign.sh sign target/x86_64-unknown-none/release/iso-light-k0 --sk keys/release_signing.sk87
```

`<artifact>.sig87` (ML-DSA-87 서명, 2420+ 옥텟) 이 생성된다.

### 검증

배포처(USB 휴대 포함)에서 공개키와 서명으로 무결성을 확인한다.

```
make verify-release
# 또는
bash scripts/release-sign.sh verify target/x86_64-unknown-none/release/iso-light-k0 \
    --pk keys/release_signing.pk87 --sig target/x86_64-unknown-none/release/iso-light-k0.sig87
```

아티팩트가 1 바이트라도 변조되면 검증이 실패한다 (SHA-256 다이제스트 불일치 -> ML-DSA 검증 거부).

## 4. 릴리즈 체크리스트

정식 태깅 전 `RELEASE-READINESS.md` 의 릴리즈 게이트(Definition of Done)를 모두 충족해야 한다. 본 문서는 그 중 P2-2·P2-3·P2-4 를 다룬다. 잔여 게이트(P0-3/P0-4 W^X 집행, P1 런타임 마커 증명)는 통제된 x86 KVM 또는 실기 환경에서 별도 검증한다.

## 산출물 요약

| 산출물 | 생성 | 추적 |
|---|---|---|
| 프로덕션 커널 바이너리 | `make build-prod` | 릴리즈 아티팩트 |
| `release-hash.txt` | `make release-hash` | 재생성 가능 (gitignore) |
| `sbom.cdx.json` | `make sbom` | 재생성 가능 (gitignore) |
| `keys/release_signing.pk87` | `release-sign.sh keygen` | 추적 (검증용 공개키) |
| `keys/release_signing.sk87` | `release-sign.sh keygen` | 미추적 (오프라인 개인키) |
| `<artifact>.sig87` | `make sign-release` | 재생성 가능 (gitignore) |
