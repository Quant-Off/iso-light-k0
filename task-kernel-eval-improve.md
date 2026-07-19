# task-kernel-eval-improve

elib-k0-nt 1.1.0 적응(`task-elib-k0-nt-update.md`) 이후 커널 전체 평가·검증·개선 작업 기록. 2026-07-18 수행. 커밋 없음 (사용자 지시).

## 범위와 방법

기준 문서는 `CRITICAL.md`(2026-06-05 전수 보안 감사, 확정 51건: Critical 1 / High 6 / Medium 12 / Low·Info 32)다. 본 작업은 세 단계로 진행했다.

- 평가: 1.1.0 적응 후 코드 상태를 CRITICAL.md 발견과 대조해 live/latent 재확인
- 검증: 빌드(폐쇄형·tls-external·release), clippy, fmt, C1 게이트 동작 확인
- 개선: 저위험·고가치 항목을 우선 수정. macOS 호스트에서 QEMU 부팅 검증이 불가한 대형 아키텍처 항목(H1/H2/H4 등)은 근거와 함께 후속 인계

호스트 제약상 런타임(부팅) 검증은 불가하므로 개선 항목은 정적(컴파일·린트) 검증까지만 확인했다. 부팅 검증은 Ubuntu 24.04 환경 필요.

## 평가 요약 (1.1.0 이후 상태)

- 폐쇄형 외부 egress 차단, 상수시간 인증, 비밀 소거 규율, 동적 할당 0 등 CRITICAL.md가 "견고" 판정한 강점은 그대로 유지됨
- 1.1.0의 저차수 점 거부(x25519/x448 `diffie_hellman` Err)와 mlkem `encaps` Result는 소그룹 공격 표면을 라이브러리 레벨에서 닫았으나 CRITICAL.md 번호 항목을 직접 종결하진 않음
- `keys/trust_root.pk44`는 1.1.0에서 재생성됐어도 여전히 결정론적 dev 키(seed 0xAA*32)이므로 C1은 유효

## 개선 내역

| 파일 | 발견 | 변경 |
|---|---|---|
| `src/syscall.rs` | M1 | getrandom 디스패치 인자 off-by-one 수정 `sys_getrandom(ctx.rsi, ctx.rdx)` -> `(ctx.rdi, ctx.rsi)` (a0=rdi/a1=rsi ABI 정합) |
| `src/syscall.rs` | SYS-05 / H3 부분 | `is_user_address` 에 NULL 페이지 하한(0x1000) 추가. 미매핑 0 페이지 copy 로 인한 fatal #PF 조기 차단 |
| `src/hsm_attest.rs` | H5/M12 | BOOT_CHALLENGE 생성의 `gen_token_u64().unwrap_or(0)` fail-open 제거. 토큰 실패 시 challenge 소거 후 즉시 panic(fail-closed) |
| `src/main.rs` | H5/M12 | `init_prng()` Err 시 FATAL 출력 후 계속하던 경로를 panic 으로 중단. HW 엔트로피 부재는 무조건 부팅 중단 |
| `src/crypto_service.rs` | M3 부분 | AES-256-GCM / ChaCha20-Poly1305 암호화 경로에 전영(all-zero) 논스 거부 추가(`CryptoError::WeakNonce`). 명백한 논스 오용 차단 |
| `src/crypto_service.rs` | CRY-02 | `handle_dh` 의 X448 개인키 로컬 복사본(`sk_arr`)을 `from_bytes` 직후 zeroize |
| `src/tls/handshake.rs` | TLS-02 | ECDHE·KEM 공유비밀 동등성 비교를 `!=` -> `ct_eq_bytes`(상수시간)로 교체 (2곳) |
| `src/tls/handshake.rs` | TLS-03 | 임시 시드(`c_seed`/`s_seed`/`d`/`z`/`m`) `fill(0)` -> `zeroize()` (DSE 제거 방지) |
| `src/memory_map.rs` | M7 | Multiboot2 mmap 파서에 태그 경계 검증 추가. `tag_phys + tag.size <= info_end` 확인 + `entries_end` 를 info 구조 끝으로 clamp. 손상·악성 부트로더 핸드오프의 물리 OOB read 차단 |
| `build.rs` | C1 | dev 신뢰 루트 지문(FNV-1a-64) 탐지 게이트 신설 (아래 참조) |

### C1 dev 신뢰 루트 탐지 게이트 (build.rs)

`scripts/gen-dev-keys.sh`가 만든 결정론적 dev 키가 출하 바이너리에 임베드되면 어테스테이션 신뢰 앵커가 위조 가능하다(C1). build.rs가 `keys/trust_root.pk44`의 지문을 계산해 알려진 dev 키(`FNV-1a-64 0x0c4efb6dd994ad6d`, `SHA-256 ad4aff...600a7`)와 일치하는지 검사한다.

- 기본: dev 키면 매 빌드 `cargo:warning` 로 경고(빌드는 통과 -> 기존 워크플로 미파괴)
- `K0_REQUIRE_PROD_TRUST_ROOT=1`: dev 키면 빌드 fatal (CI·release 파이프라인이 출하 산출물에 dev 키 유입 차단하는 게이트)
- `K0_ALLOW_DEV_TRUST_ROOT=1`: require 하에서도 dev 키 명시 허용(로컬 release 검증용 escape hatch)

지문 함수는 외부 의존성 없이 자립 구현(에어갭 빌드 공급망 표면 0 유지)했고, 암호 용도가 아니라 특정 committed 아티팩트 식별 전용이다.

## 검증 결과

- `cargo check --target x86_64-unknown-none`: 통과 (기본, `tls-external,smoke` 전체 feature)
- `cargo build --release --target x86_64-unknown-none`: 통과
- `cargo clippy` (기본·전체 feature): 실질 경고 19건으로 기준선과 동일. 이번 수정으로 신규 clippy 경고 0 (build.rs의 C1 경고는 의도된 산출물)
- fmt: 수정 파일의 편집 헐크는 rustfmt 정합(build.rs는 완전 클린). 리포 전반 기존 fmt 드리프트(air_gap.rs, bus.rs, syscall.rs enum 정렬 등)는 손대지 않음(디프 최소화)
- 코드 주석 규칙 준수: 추가 주석에 `·`, `—` 부재 확인
- C1 게이트 동작 실측: `K0_REQUIRE_PROD_TRUST_ROOT=1` -> 빌드 실패(명확한 메시지), `+K0_ALLOW_DEV_TRUST_ROOT=1` -> 통과

## CRITICAL.md 항목별 처리 현황

- 종결/수정: M1, M7, M12, H5, CRY-02, TLS-02, TLS-03
- 부분 완화(추가 후속 필요): C1(build 게이트 신설, 운영 provisioning=M10 미구현), H3(NULL 하한만, user-copy fault-fixup 미구현), M3(전영 논스 거부만, 전 유일성 강제 미구현)
- 후속 인계(본 작업 미수행): H1, H2, H4, H6, M2, M4, M5, M6, M8, M9, M10, M11 및 Low/Info 다수

## 후속 과제 (다음 단계 인계)

- H1(activate 활성화)/H2(선형맵 RO)/H4(커널 스택 고반치)는 고반치 재배치가 선행돼야 하고 QEMU 부팅 검증이 필수라 본 호스트(macOS)에서 미수행. Ubuntu 24.04 + `make` + `scripts/qemu-test.sh` 로 진행
- H3 완전 종결: user-copy fault-fixup(폴트 RIP 태깅 + #PF 시 BadAddress 복귀) 또는 복사 전 페이지테이블 walk 도입
- H6: `with_registry_mut` 재진입 제거(버스 드라이버 구조 재편) + host Miri 검증
- M3 완전 종결: 커널측 논스 생성(응답 반환) 또는 키별 단조 카운터로 와이어 계약 확장
- M10: `provision_trust_root_pk` 실 구현 또는 슬롯 미공급 시 boot fail-stop(dev const 폴백 금지). 완료 시 C1 게이트를 release 기본 fatal 로 승격 가능
- M11: Cargo.lock un-gitignore + 커밋, postcard/serde 정확 버전 고정, CI `--locked` 게이트
- ISO 빌드·QEMU 부팅 회귀 검증(부팅 시 신규 panic 경로 H5/M12 포함) 및 elib-k0-nt Plan 06-02 스텁 GREEN 전환 후 전체 스위트 재확인
