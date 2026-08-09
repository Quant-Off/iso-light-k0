# keys 디렉토리

해당 디렉토리는 iso-light-k0의 ML-DSA-44 신뢰 루트 키 자료를 담고 있습니다.

## 자료

- `trust_root.pk44` (1312 B) - 저장소 커밋용 (ML-DSA-44, dev/test 전용)
- `dev_trust_root.sk44` (2560 B) - `.gitignore`로 추적 제외 (ML-DSA-44)

## 생성

키 페어(쌍)는 호스트 머신에서 다음 명령을 통해 1회 생성합니다.

```
bash scripts/gen-dev-keys.sh
```

해당 스크립트는 결정론적 시드 `[0xAA_u8; 32]`로 `elib-k0-nt`의 `MLDSA44::keygen`을 호출하여 키 페어를 덤프합니다. 시드값은 dev 키 페어에만 한정된 결정론적 값입니다.

> [!IMPORTANT]
> 절대로 해당 키 페어를 프로덕션(운영) 환경에서 사용하지 마세요.
> 
> 프로덕션의 Trust Root는 별도 out-of-band(독립 경로)의 키스토어 공급 과정에서 별도 키 페이로 부팅 시점에 주입됩니다.
> 
> 단, `dev` 키 페어가 프로뎍선 환경에 잔존하는 위험에 대해서 당신이 직접 통제해야 합니다.

## CI 게이트

CI 과정에서 `scripts/check-no-dev-sk.sh` 스크립트를 통해 빌드 산출물에 dev 비밀 키가 누출되지 않음을 검증할 수 있습니다. 해당 검증은 Makefile 내 `ci-phase5`에 포함되어 있습니다.
