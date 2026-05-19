# keys 디렉터리

본 디렉터리는 iso-light-k0 의 ML-DSA-44 신뢰 루트 키 자료를 담는다 (Phase 5 attach/enrollment/attestation 게이트의 컴파일-타임 임베드 source)

## 자료

- `trust_root.pk44` (1312 B) repo commit 대상 ML-DSA-44 공개 신뢰 루트 dev/test 전용
- `dev_trust_root.sk44` (2560 B) .gitignore 로 추적 제외 ML-DSA-44 비밀 키 kernel-side smoke (feature `smoke`) 전용 closed 프로필 빌드 산출물에 절대 포함 금지

## 생성

두 자료는 host 측에서 1 회 생성한다

```
bash scripts/gen-dev-keys.sh
```

본 스크립트는 deterministic seed `[0xAA_u8; 32]` 로 `elib-k0-nt::mldsa::MLDSA44::keygen` 을 호출하여 두 자료를 dump 한다 (RESEARCH §10.1) seed 는 dev 자료에만 한정된 결정론적 값이며 production 환경에서는 절대로 사용 금지

## 운영 환경 절대 사용 금지

본 디렉터리의 키 자료는 **dev 와 test 전용**이며 production 신뢰 루트로 절대 채택 금지 production trust root 는 별도 out-of-band keystore provisioning 절차를 통해 별도 키쌍으로 부팅 시점에 주입한다 (CONTEXT D-02, D-03 명시) `.gitignore` 의 `keys/*.sk*` 규칙은 sk 자료의 실수 commit 만 막을 뿐 dev 키 자체가 production 환경에 잔존하는 위험은 운영자가 직접 통제해야 한다 (RESEARCH §14.3 잔존 위험)

## CI 게이트

closed 프로필 빌드 산출물에 dev sk 자료가 leak 되지 않음을 `scripts/check-no-dev-sk.sh` 가 검증한다 (Phase 5 D-19) 본 검증은 Makefile `ci-phase5` 의 한 leg 으로 동작한다
