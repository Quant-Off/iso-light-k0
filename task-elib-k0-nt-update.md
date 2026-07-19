# task-elib-k0-nt-update

elib-k0-nt 의존성 업데이트 (1.0.0 -> 1.1.0) 적응 작업 기록. 2026-07-18 수행. 커밋 없음 (사용자 지시).

## 배경

본 업데이트의 참조 기준은 [Quant-Off/elib-k0-nt PR #9](https://github.com/Quant-Off/elib-k0-nt/pull/9) "1.1.0 릴리즈 준비 - 교차 검증 및 문서 업데이트"다. 작업 시점 로컬 체크아웃은 PR head 브랜치 `feature/1.1.0-verify`의 tip 커밋 `8fc8cb3`과 일치하며, PR head 시점 `cross-confirm.md`는 14개 알고리즘 전부 검증 완료 상태였다. PR은 아직 OPEN이므로 병합 후 로컬을 master로 전환하고 커널 빌드를 재확인할 것.

`../elib-k0-nt`는 path 의존성이라 소스는 항상 최신을 참조하지만, 라이브러리 측 보안 강화 커밋으로 API가 파괴적으로 변경되어 커널 빌드가 깨져 있었다. 주요 라이브러리 변경:

- x25519·x448: `diffie_hellman()`이 `Result<SharedSecret, *Error>` 반환. 저차수 점(공유비밀 0)을 라이브러리가 직접 `Err(LowOrderPoint)`로 거부. 스칼라 곱셈 상수시간화
- mlkem: FIPS 203 정합성 수정. `mlkem768_encaps()`가 `Result<..., Error>` 반환 (비정규 캡슐화 키 거부). RFC·KAT 검증 추가
- mldsa: FIPS 204 정확성 수정 (BitPack 부호 규칙 b - w 정정, CoeffFromHalfByte 표준 구현). ACVP keyGen KAT 회귀 테스트 통과. **같은 시드에서 도출되는 키쌍의 비트 출력이 구버전과 달라짐**
- chacha20: 블록 카운터 u64 소진 검사, AEAD 입력 길이 한계, 비밀 임시값 소거
- ed25519·ed448: 상수시간 스칼라 곱셈, 비정규 인코딩 거부, RFC 8032 KAT
- blake: BLAKE3 keyed 키 워드 즉시 Secret 래핑, finalize 잔여 소거

## 커널 측 변경

| 파일 | 내용 |
|---|---|
| `src/crypto_service.rs` | X448 DH 핸들러의 수동 `is_zero()` 검사 제거 -> `diffie_hellman()` `Err`를 `CryptoError::AuthenticationFailed`로 매핑 (fail-closed 유지) |
| `src/tls/handshake.rs` | x25519 loopback 공유비밀 2건을 `map_err(TlsError::Internal)?`로 적응. `mlkem768_encaps` 실패 시에도 난수 `m`이 먼저 소거되도록 순서 보존 후 `Err` 매핑 |
| `crates/iso-user-lumen/src/main.rs` | check_x25519 검증 루틴을 `Result` 매칭으로 적응. 저차수 거부 시 stderr 출력 후 exit(1) |
| `keys/trust_root.pk44` | **재생성** (아래 참조) |
| `keys/dev_trust_root.sk44` | 재생성 (gitignore 대상, 로컬 전용) |

## 신뢰 루트 키 재생성 (중요)

mldsa FIPS 204 수정으로 `MLDSA44::keygen([0xAA; 32])` 산출이 구버전과 달라졌다 (33번째 옥텟부터 상이). 체크인돼 있던 `trust_root.pk44`는 비정합 구현의 산물이므로 `scripts/gen-dev-keys.sh`로 재생성해 교체했다. dev·test 전용 자료이며 결정적 시드라 재현 가능.

**파급**: 구 pk44 기준으로 만들어진 서명·아티팩트는 전부 무효. 리포 내 사전 서명 아티팩트는 없음을 확인했다 (`*.sig*` 부재, isodir는 boot만 존재). 외부 lumen 프로젝트가 구 elib-k0-nt·구 pk44를 쓰고 있다면 재빌드와 재키잉 필요 (와이어 호환은 동일 elib-k0-nt 버전 사용이 전제).

## 검증 결과

- `cargo check --target x86_64-unknown-none`: 통과 (기본, `tls-external,smoke` 전체 feature 모두)
- `cargo build --release --target x86_64-unknown-none`: 통과
- `cargo clippy` (전체 feature): 경고 19건, 전부 기존 코드 소관 (Safety 독스트링 누락·Default 미구현 등). 이번 수정 파일에서 신규 경고 0
- 사용자 크레이트 `iso-user-lumen`·`iso-user-hello`: check 통과. lumen clippy 경고 13건은 기존 코드
- `cargo fmt --check`: 이번 수정 훅에서 디프 0. 리포 전반에 기존 fmt 드리프트 존재 (air_gap.rs, bus.rs, main.rs 등 다수)
- elib-k0-nt 자체 테스트 (`--release --target aarch64-apple-darwin --no-fail-fast`): 커널이 의존하는 암호 크레이트 전부 통과 (aes 20, blake 44, chacha20 24, ed25519 24, ed448 28, mldsa 22, mlkem 14+KAT, rng 8, sha3 13, x25519 11, x448 11, dudect 19 등)

### 라이브러리 측 실패 (이번 업데이트와 무관)

- `constant-time/tests/gap_*.rs` 4개 파일 21건 실패: 전부 `todo!()` RED 스텁 (라이브러리의 Plan 06-02 GREEN fill-in 예정 작업)
- blake `test_blake3_*_zeroize_on_drop` 2건이 워크스페이스 병렬 실행 중 1회 실패 후 재실행·단독 실행에서 전부 통과. 스택 프로브 방식 소거 테스트의 병렬 간섭 플레이크로 판단 (라이브러리 최신 커밋이 constant-time 쪽 동일 문제를 고친 전례 있음)

## 후속 과제 (다음 단계 인계)

- ISO 빌드·QEMU 부팅 검증은 본 호스트(macOS, grub-mkrescue 부재)에서 불가 -> Ubuntu 24.04 환경에서 `make` + `scripts/qemu-test.sh` 수행 필요
- `src/tls/handshake.rs`의 공유비밀 동등성 비교(`as_bytes() !=`, `expose() !=`)가 비상수시간. loopback 자기검증 경로지만 constant-time 크레이트로 교체 검토 대상
- CRITICAL.md 기재 문제들 (C1 dev 신뢰 루트, H1~H6, M1~M12)은 다음 평가·개선 단계에서 처리
- 리포 전반 fmt 드리프트와 clippy 경고 19건 정리
- elib-k0-nt Plan 06-02 스텁이 GREEN 전환되면 전체 스위트 재확인
