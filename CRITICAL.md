# CRITICAL 보안 감사 보고서 (iso-light-k0)

본 문서는 iso-light-k0 마이크로커널(no_std, x86_64-unknown-none, panic=abort)의 소스 코드 전수 보안 감사 결과를 종합한다. 외부 웹 조사가 아니라 실제 커널 코드(src/ 30개 파일 약 14,583줄 + crates/iso-user-* + build.rs + scripts/)를 대상으로 했다.

- 감사 일자: 2026-06-05
- 대상 커밋 기준: master (cc3ef38 이후 작업트리)
- 방법론: 13개 도메인 병렬 정적 분석 에이전트 + 폐쇄형 데이터플로 추적 + 교차모듈 권한상승 체인 헌터, 그 후 모든 후보를 적대적 검증 에이전트가 실제 코드 재확인으로 확정/기각. 핵심 발견(C1, H1, H3, M1)은 감사자가 직접 코드를 재독해 검증함.
- 통계: 원시 후보 65건 -> 확정 51건, 기각 14건. 확정 분포 Critical 1 · High 6 · Medium 12(중복 병합 후) · Low/Info 32.

커밋은 수행하지 않았다(작업트리에 본 파일만 신규 생성).

---

## 0. 빌드 프로필과 현재 상태 (중요 맥락)

발견의 심각도와 실현 가능성은 두 가지 사실에 크게 좌우되므로 먼저 명시한다.

- 폐쇄형(closed) 프로필: 기본 빌드. `tls-external` feature 없음. 외부망 표면 0 을 목표로 함.
- 외부(tls-external) 프로필: 빌드 feature + 런타임 capability 이중 게이트가 있어야만 외부 통신 허용.

현재 커널 상태 (live 와 latent 구분의 근거):

1. `mmu_init.activate(kernel_space)` 가 `src/main.rs:441` 에서 주석 처리되어 있다. 커널은 boot_stub 의 평면 4 GiB identity map(RWX) 위에서 영구 실행된다. 즉 W^X / NX / U-S 분리가 런타임에 집행되지 않는다. 이것은 지금 무조건 live 다.
2. Ring 3 사용자 프로세스 spawn 경로(`try_spawn_user`, `src/main.rs:627/651`)는 `#[cfg(debug_assertions)]` 게이트 뒤에 있어 release/closed 바이너리에서는 비활성이다. `enter_ring3` 도 `-> !` 단일 프로세스 모델이다.
3. IPC 계열 syscall(IpcCall/IpcRecv/IpcReply/CapRequest)은 `src/syscall.rs:355-361` 에서 즉시 `Unknown` 을 반환하는 스텁이다.

따라서 신뢰되지 않는 Ring 3 프로세스가 release 에서 실제로 구동되지 않는 현 시점에는, Ring3 -> Ring0 공격(아래 H3 H4 H6, M1 M3 M5 등 다수)이 latent(잠재) 상태다. 이들은 Phase E 에서 사용자 spawn 이 활성화되고 `activate()` 가 켜지는 순간 live 로 전환된다. 반면 신뢰 앵커 위조(C1)와 W^X 미집행(H1)은 지금 출하 가능한 바이너리에서 바로 성립한다.

이 보고서는 각 항목에 [live] 또는 [latent] 또는 [완화됨] 태그를 붙여 정직하게 구분한다.

---

## 1. CRITICAL

### C1. 출하 빌드에 개발용 신뢰 루트가 박혀 있고 그 개인키가 공개적으로 재현 가능 [live]

- 분류: supply-chain / capability-auth
- 위치: `scripts/gen-dev-keys.sh`, `src/hsm_attest.rs:26-27,153-177`, `build.rs:39-46,52-59`, `keys/trust_root.pk44`
- 연계: M10(USE-02 override 스텁)이 본 결함의 유일한 탈출구를 막아 Critical 을 고착시킴

문제. HSM 부착을 승인하는 ML-DSA-44 어테스테이션 신뢰 루트가 `keys/trust_root.pk44`(1312 옥텟)로 커밋되어 있고, `src/hsm_attest.rs:26` 의 `include_bytes!` 로 모든 빌드 바이너리에 직접 임베드된다. 그런데 `scripts/gen-dev-keys.sh` 는 이 키쌍을 `MLDSA44::keygen(&[0xAA_u8; 32])`, 즉 하드코딩된 결정론적 공개 시드(0xAA 32바이트)로 생성한다. 따라서 누구나 동일 시드로 keygen 을 돌려 대응 개인키 `dev_trust_root.sk44` 를 그대로 복원할 수 있다.

기본 경로(`K0_TRUST_ROOT_KEYSTORE` 미설정)는 `HSM_TRUST_ROOT_PK_CONST`(곧 이 개발 키)를 `ACTIVE_TRUST_ROOT_PK` 로 복사한다(`hsm_attest.rs:176-177`). 운영용 교체 경로는 M10 에서 보듯 비기능 스텁이라 사실상 모든 빌드가 이 개발 키를 신뢰한다.

영향. 신뢰 루트는 zero-trust 모델의 핵심 닻이다. 개인키를 아는 공격자는 임의의 악성 HSM 공개키에 대해 유효한 어테스테이션을 위조해 부착 게이트(`verify_attest`, `hsm_attest.rs:280-334`)를 통과시킬 수 있다. 이는 "신뢰 가능한 HSM 만 부착" 이라는 제품의 본질 가치를 폐쇄형에서도 무력화한다.

공격 경로. (1) 리포에서 시드 0xAA*32 확인 -> 개인키 복원. (2) 부팅 후 `BOOT_CHALLENGE` 관찰(audit 또는 wire status 경로). (3) 사전상 `attacker_pk(1312) || bus_kind(1) || BOOT_CHALLENGE(32)` 구성 -> BLAKE3 32옥텟 -> context `b"ISO-K0-ENROLL-V1"` 로 서명. (4) Ring3 어테스트 제출 경로로 (pk, sig) 전달 -> `verify_attest` 통과 -> 악성 HSM 부착.

권고.
- release/closed 프로필에서 개발 키 사용을 빌드 fatal 로 만든다. `build.rs` 가 `trust_root.pk44` 의 지문을 계산해 알려진 개발 키와 같으면 빌드 실패시키거나, 명시적 운영 키 경로가 없으면 출하 빌드를 거부한다.
- 개발 키는 결정론적 시드가 아니라 난수 시드로 생성한다.
- `scripts/check-no-dev-sk.sh` 를 확장해 개발용 공개 루트도 release 산출물에서 거부한다.
- M10(override 경로)을 실제 구현하거나, 키스토어 슬롯이 비면 부팅 fail-stop 한다.

---

## 2. HIGH

### H1. activate() 미호출로 커널이 평면 RWX identity map 위에서 영구 실행 (W^X 미집행) [live, 무조건]

- 분류: hardening / memory-safety
- 위치: `src/main.rs:354-403,417-441`, `src/boot_stub.rs:184-186`

문제. `kernel_main` 이 9단계(`main.rs:354-403`)에서 섹션별 W^X/NX/U-S 페이지테이블을 `KERNEL_ADDR_SPACE` 에 정확히 구축하지만, 11단계(`main.rs:441`)의 `mmu_init.activate(kernel_space)` 가 주석 처리되어 있다. 그 결과 CR3 는 boot_stub 가 적재한 평면 4 GiB identity map(PDPT 엔트리 0x83 = P|W|PS, NX=0)을 그대로 유지한다(`boot_stub.rs:184-186`). 인코드 TODO 가 "0x100000 에 phys==virt 링크되어 있어 고반치 재배치 전에는 activate 불가" 라고 명시한다.

영향. 커널 전 영역에서 W^X 와 NX 와 하드웨어 스택 가드가 집행되지 않는다. .text/.rodata 가 쓰기 가능하고 데이터/스택이 실행 가능하다. 향후 또는 기존의 임의 커널 쓰기 프리미티브(예: wire/IPC 파서 결함)가 .text 를 덮어쓰고 즉시 실행할 수 있어, 데이터 손상이 코드 실행으로 직결된다. 단독 RCE 는 아니나 제품이 표방하는 메모리 안전 핵심 보증을 무효화하는 완화우회 인에이블러다. debug/release, closed/tls-external 전 프로필에서 무조건 성립한다.

권고. 인코드 TODO 의 옵션 A(고반치 재배치) 후 `activate()` 를 켜서 W^X/NX/가드 매핑을 실제 CR3 로 만든다. 그 전까지 `main.rs` 의 "W^X + IST Guards" 마커 출력을 중단해 허위 보증 표기를 없앤다. `activate()` 활성화 시 `main.rs:367/375/385/394` 의 `let _ = map_page(...)` 무시를 제거해 보안 핵심 매핑 실패가 fail-stop 되게 한다.

### H2. 직접 선형 매핑이 커널 .text/.rodata 를 쓰기 가능으로 alias (W^X 물리맵 우회) [latent, activate() 활성화 시]

- 분류: hardening
- 위치: `src/mmu.rs:613-645`
- 연계: H1 과 한 쌍. H1 을 고쳐 activate() 를 켜도 본 항목 때문에 W^X 가 복원되지 않음

문제. `build_linear_map` 이 모든 물리 프레임을 `PHYS_MAP_OFFSET` 기준 선형 영역에 WRITABLE 로 매핑하는데, 여기에 커널 이미지(.text/.rodata) 물리 범위도 포함된다. 즉 섹션별 W^X 매핑과 별개로, 선형맵 가상주소를 통해 실행 코드가 쓰기 가능하게 노출된다.

영향. activate() 가 켜지는 순간 커널 코드/로데이터를 선형맵 alias 로 수정할 수 있어 코드 주입/권한상승이 가능. W^X 기둥을 형해화한다.

권고. `build_linear_map` 에서 커널 이미지 물리 범위(`_text_start.._rodata_end` 링커 심볼의 물리 주소)를 쓰기 가능 선형맵에서 제외하거나 read-only 로 매핑한다. 일반적으로 실행 가능 물리 영역의 직접맵은 RO 로 둔다.

### H3. 사용자 포인터 검증이 범위만 확인하고 매핑 여부 미확인 -> 미매핑 포인터가 무조건 fatal_halt = 커널 전체 DoS [latent -> Phase E live]

- 분류: dos-fault-handling
- 위치: `src/syscall.rs:408-435,444-465,484-486`, `src/idt.rs:461-496`
- 병합: SYS-01(High) + SYS-01(Medium, dos) + SYS-02(Low, idt) 동일 근본 원인

문제. 모든 사용자 메모리 복사 syscall(`sys_write`, `sys_getrandom`, 그리고 `air_gap` 의 `take_*_cap`/`handle_status`, `hsm_registry` 핸들러)이 `is_user_address` 로 canonical 하반(`va < 0x0000_8000_0000_0000`)인지 범위만 검사하고, 해당 페이지가 실제 present/writable 인지는 검사하지 않는다. 이후 `stac()` 윈도우 안에서 `copy_nonoverlapping` 을 수행한다. 페이지폴트 핸들러(`idt.rs:461-496`)는 모든 #PF 에 대해 fixup 없이 `fatal_halt`(CLI+HLT 무한루프)를 호출한다.

영향. Ring 3 프로세스가 `write(2, 0x0, 1)` 또는 미매핑 하반 주소로의 `getrandom` 한 번이면 커널 전체를 영구 정지시킨다. 에어갭 엣지 게이트웨이/데이터 다이오드에서 가용성 거부이자, "결함/적대적 사용자 태스크가 Ring 0 을 다운시키지 못한다" 는 격리 보증의 위반이다. 현재는 사용자 spawn 이 debug 게이트라 latent 이며, Phase E 에서 무신뢰 Ring 3 가 켜지면 즉시 live 다.

권고. (a) user-copy fault-fixup 도입: copy 사이트를 태깅하고, #PF 시 폴트 RIP 가 등록된 user-copy 루틴이며 CR2 가 사용자 주소면 `fatal_halt` 대신 `SyscallError::BadAddress` 로 복귀. 또는 (b) 복사 전 사용자 페이지테이블을 walk 해 present + user(+쓰기 시 writable)를 확인. 더불어 `is_user_address` 에 0(null) 하한을 추가한다.

### H4. Ring 0 syscall 스택이 저주소 사용자 영역에 identity map 되어 Ring 3 가 커널 스택을 read/write [latent, 현재 debug 전용]

- 분류: privilege-escalation
- 위치: `src/syscall.rs:439-473,483-486`, `src/process.rs:202-213`, `src/main.rs:223-227`

문제. 커널 부트 스택(= syscall 진입 RSP0)이 저주소(예 0x115000)에 identity map 되어 있고, `is_user_address(0x115000)` 가 true 를 돌려준다. 따라서 사용자 포인터 검증이 커널 스택 VA 를 사용자 주소로 받아들인다. H1(평면 identity map)과 결합되어 supervisor 페이지에 대한 #PF 없는 접근이 가능하다.

영향. Ring 3 가 `sys_getrandom(kernel_stack_va, len)` 으로 라이브 `SyscallContext`(저장된 커널 레지스터, 복귀주소)를 덮어쓰거나 `sys_write(2, kernel_stack_va, n)` 으로 유출할 수 있다. Ring3 -> Ring0 권한상승 겸 커널 메모리 안전 붕괴로 SMEP/SMAP/W^X 격리를 무력화한다. 현재 트리거 경로는 debug 빌드 한정(`#[cfg(debug_assertions)]`).

권고. 커널 스택을 사용자 범위와 겹치지 않는 고반치(`KERNEL_VMA_BASE`) 영역에 둔다. 그리고 사용자 포인터 검증을 단순 수치 범위가 아니라 활성 페이지테이블 walk(접근 페이지마다 USER_ACCESSIBLE=1 AND PRESENT 요구)로 강화한다. `is_user_address` 에 null 페이지 거부 하한 추가.

### H5. 엔트로피 실패 시 BOOT_CHALLENGE 가 0 으로 fail-open -> 어테스테이션 신선도 무효 [완화됨, gap_self_check 백스톱]

- 분류: crypto-misuse
- 위치: `src/hsm_attest.rs:185-198`, `src/main.rs:450-462`
- 연계: M12(DRBG init fail-open)와 동일 뿌리

문제. `init_trust_root` 가 `BOOT_CHALLENGE` 32옥텟을 `gen_token_u64().unwrap_or(0)` 4회 연쇄로 채운다(`hsm_attest.rs:187-190`). DRBG 가 미시드/실패면 토큰이 모두 Err 가 되어 챌린지가 전부 0 이 된다. 또한 `main.rs:457-461` 은 `init_prng()` 실패 시 FATAL 만 출력하고 멈추지 않는다.

완화. DRBG 가 완전 실패하면 같은 이유로 `AUDIT_READ_CAP.token` 도 0 이 되며, `gap_self_check`(`air_gap.rs:188-192`)가 메인 루프와 Ring3 진입 전에 token==0 을 탐지해 panic(abort)한다. 따라서 "0 챌린지로 부팅 후 리플레이" 시나리오는 실제로는 fail-stop 으로 차단된다.

잔여 위험과 권고. `unwrap_or(0)` 자체가 fail-open 코딩 패턴이며 fail-stop 이 간접/지연 의존이다. `gen_token_u64` 오류를 전파(`unwrap_or(0)` 제거)하고 챌린지 생성 불가 시 즉시 panic 한다. `init_prng()` 가 Err 면 그 지점에서 바로 halt(fail-stop)한다.

### H6. wire 디스패치가 살아있는 &mut REGISTRY 위에서 전역 REGISTRY 를 재진입 (aliasing UB), Ring3 도달 가능 [latent -> Phase E live]

- 분류: memory-safety
- 위치: `src/bus.rs:174-215(특히 191-215),759-779`, 도달 경로 `src/hsm_registry.rs:887-919,901-902`
- 병합: BUS-01(High) + SYS-02(Medium, hsm_registry)

문제. `handle_write -> with_registry_mut(닫힘) -> slot_bus_mut -> BusInstance::write -> Ring3ProcessBus::write -> handle_blake3` 경로에서, 이미 `with_registry_mut` 로 잡힌 `&mut REGISTRY` 가 살아있는 상태에서 `handle_blake3` 가 다시 `with_registry`(공유 `&`, UB #1)와 `with_registry_mut`(두 번째 `&mut`, UB #2)로 전역 REGISTRY 를 재진입한다. 첫 aliasing 은 임베디드 cap 인증 이전에 발생하므로 트리거 문턱이 낮다(구문상 유효한 Blake3Hash wire 프레임이면 됨, cmd=0x0010/0x0003, payload_len>=16).

영향. Ring 0 의 미정의 동작. release LTO + opt-level=z 하에서 오컴파일, 레지스트리 상태 혼동, 옵티마이저 기인 메모리 손상 가능. 최악의 경우 레지스트리가 강제하는 capability/attestation 불변식을 훼손한다. 양 프로필(closed 포함)에서 도달 가능.

권고. 버스 드라이버 메서드가 레지스트리가 이미 빌린 상태에서 REGISTRY 를 재진입하지 않도록 재구조화한다. `handle_write` 에서 임베디드 cap 인증과 대상 SoftwareBus 참조 획득을 `Ring3ProcessBus::write` 진입 전에 끝내거나, Ring3 슬롯과 soft-HSM 슬롯을 분리해 단일 `&mut` 로 덮는다. 최소한 `with_registry_mut` 에 재진입 가드(AtomicBool)를 둔다. host 가능 환경에서 Miri 로 검증한다.

---

## 3. MEDIUM

### M1. getrandom 이 잘못된 인자 레지스터로 디스패치 (off-by-one) -> RNG 전달 실패 + 미초기화 버퍼 위험 [live, 정합성 결함]

- 위치: `src/syscall.rs:337-338,439`
- 사용자 ABI 는 a0=rdi, a1=rsi, a2=rdx(`crates/iso-user-lumen/src/main.rs:61-71`). `sys_write` 는 `(rdi,rsi,rdx)` 로 올바르나 `sys_getrandom(ctx.rsi, ctx.rdx)` 는 rdi 를 건너뛴다. 규약대로 buf 를 rdi, len 을 rsi 에 둔 호출자는 buf 에 난수를 못 받고, 부주의한 소비자가 미초기화/예측가능 버퍼를 키/논스로 쓰면 약한 엔트로피로 직결.
- 권고. `sys_getrandom(ctx.rdi, ctx.rsi)` 로 수정하고 알려진 레지스터 입력에 대한 버퍼 채움/반환값 smoke 테스트 추가.

### M2. ML-DSA 키 자료가 비-Secret, 미소거 스택 버퍼에 잔류 [latent, EP_SIGN 활성 시]

- 위치: `src/sign_service.rs:128-134,143-156,442-452,543-565` (SIGN-01 + SIGN-02 병합)
- keygen 출력(`reply_buf`, `sp`)과 인바운드 비밀키/시드(`parse_req` 의 `SignPayload`)가 `crypto_service` 의 `Secret<T>` 규율과 달리 평문으로 스택에 남아 소거되지 않는다. syscall 반환 후 청크당 최대 240바이트의 ML-DSA-44 sk 조각이 커널 스택 사장 영역에 잔류. 2차 스택 노출 프리미티브나 콜드부트로 키 복원 위험.
- 권고. `reply_buf` 를 `Secret` 로 감싸거나 `ipc_reply` 직후 `secure_zero`, `sp` 와 `req`(`SignPayload::zeroize`)를 drop 전 소거. 키 자료를 운반하는 모든 SignPayload 를 Secret 로 취급.

### M3. AES-256-GCM / ChaCha20-Poly1305 논스가 전적으로 호출자 제공, 유일성 미강제 [latent -> 폐쇄형에서도 도달]

- 위치: `src/crypto_service.rs:351-382,423-454`
- 버그/악성 Ring3 클라이언트가 동일 key+nonce 로 두 번 호출하면 GCM 논스 재사용이 발생해 GHASH 키 복원과 보편적 위조가 가능. 커널 측 안전장치 부재.
- 권고. 커널 측 논스 생성(암호화 시 `capability::rand_bytes` 로 뽑아 응답에 반환) 또는 키별 단조 카운터. 최소한 와이어 계약에 유일성 의무를 명시하고 0/명백한 재사용 논스를 거부.

### M4. 네트워크 부착 런타임 게이트가 상태 전용 (caller 의 NETWORK_ATTACH_CAP 보유를 확인하지 않음) [latent, tls-external 다중프로세스]

- 위치: `src/hsm_registry.rs:562-577`, `src/air_gap.rs:207-254`
- `handle_attach` 의 Network 분기가 전역 `NETWORK_CAP_STATE==Taken` 래치만 보고 진행한다. 다른 프로세스가 세운 Taken 래치에 편승하거나 cap-take 를 레이스하면, 네트워크 cap 토큰을 받은 적 없는 프로세스가 외부 통신(Network HSM 부착)을 열 수 있다. 최고가치 권한에 대한 프로세스별 capability 격리가 깨진다.
- 권고. Network 부착 분기가 호출자 제공 NETWORK_ATTACH 토큰을 상수시간 비교(`handle_status` 의 `CtEqOps::eq` + non-zero 가드 미러)하도록 한다. cap 을 spawn 프로세스 신원에 바인딩해 first-caller-wins 탈취를 막는다.

### M5. wire Status opcode 가 AUDIT_READ_CAP 게이트 없이 감사 이벤트 링을 유출 [latent, Ring3 wire 활성 시]

- 위치: `src/bus.rs:287-325,769-771` (BUS-02 + CAP-02 병합) vs `src/air_gap.rs:314-337`
- 동일 감사 스냅샷이 두 개의 불균등 게이트 뒤에 있다. syscall `handle_status` 는 AUDIT_READ_CAP 토큰을 상수시간 검증하지만, wire `Status`(cmd=0x0080) 경로는 버스 USE capability 만으로 `audit_snapshot` 을 직렬화해 돌려준다. attested Ring3 클라이언트가 USE cap 만으로 어테스테이션 감사 이력(seq, 슬롯 인덱스, 결과 코드, bus_kind, 공개키 BLAKE3 4바이트 프리픽스)을 탈취 가능. 유출 필드는 공개키 파생 메타데이터라 기밀 영향은 제한적이나 capability 모델 불일치다.
- 권고. wire Status 핸들러도 audit-read capability 를 검증하게 하거나, 의도적 비권한 self-status 표면임을 명시하고 두 게이트를 일치시킨다.

### M6. TLS run_loopback 의 &'static mut aliasing + 오류 경로 슬롯 누수 [latent, tls-external]

- 위치: `src/tls/handshake.rs:112-129`, `src/tls/mod.rs:273-295`
- `alloc_slot()` 결과 참조를 들고 다른 `alloc_slot()` 을 호출해 동일 static 을 두 개의 라이브 `&mut` 로 alias(release LTO 에서 오컴파일 위험). 또한 풀 만석 오류 경로가 stale 참조로 상태를 바꿔 `TLS_POOL[idx]` 가 `Some` 으로 남아 4슬롯 풀이 영구 고갈(DoS)된다.
- 권고. `slot()` 참조를 다른 alloc 호출 너머로 보유하지 않는다. 실패 시 `crate::tls::close(client_h)` 경유로 슬롯 회수. 장기적으로 lifetime-laundering `&'static mut` API 를 인덱스 기반 + 단명 borrow(또는 스핀락 셀)로 교체.

### M7. Multiboot2 mmap 파서가 무경계 tag.size 를 신뢰 -> 물리 OOB read / 부팅 DoS [live, 부트로더 핸드오프]

- 위치: `src/memory_map.rs:199-234`
- type-6(mmap) 태그의 `size` 에 상한 검사 없이 `entries_end = tag_phys + tag.size`(L207)를 잡고 그 끝까지 원시 물리 포인터를 역참조(L210). 악성/손상 GRUB 핸드오프가 큰 size 를 주면 MB2 구조 밖을 임의 거리까지 읽어 미매핑/MMIO 폴트(행/DoS), 디바이스 MMIO 부작용, 공격자 영향 바이트 흡수 가능. 부트로더 핸드오프의 zero-trust 위반.
- 권고. `16 <= tag.size` 와 `tag_phys + tag.size <= info_addr + total_size` 검증, `entries_end` 를 info 구조 끝으로 clamp, `entry_size % 8 == 0` 거부.

### M8. RO 세그먼트가 실행 가능으로 매핑 [latent, ELF spawn 활성 시]

- 위치: `src/process.rs:450-457`, `src/mmu.rs:308-324`
- PF_R 전용(PF_W/PF_X 없음) PT_LOAD 세그먼트(.rodata 등)가 `map_user_page(.., writable=false)` 로 매핑될 때 NO_EXECUTE 비트가 설정되지 않아 Ring 3 에서 실행 가능. DEP/NX 정책 약화.
- 권고. `!PF_X` 면 NX, `PF_W` 일 때만 WRITABLE 로 매핑.

### M9. 주 커널/syscall 스택(RSP0 = 부트 스택)의 가드 페이지 미집행 [live 부분, H1 종속]

- 위치: `src/main.rs:223-226,388-397`
- IST 스택은 가드를 누리지만 주 부트 스택 가드는 W^X 패스의 매핑 제외 집합에 없고 `activate()` 미적용으로도 강제되지 않는다. 깊은 ML-DSA/ML-KEM/SHAKE-256 XOF 호출 + 중첩 인터럽트가 스택을 넘으면 #PF 대신 인접 매핑 메모리를 조용히 덮는다.
- 권고. `stack::boot_guard_range()` 를 W^X 패스의 매핑 제외에 추가(또는 명시적 unmap), IST 가드 처리 미러. fault 진입 시 `validate_canaries()` 호출 고려.

### M10. 운영 신뢰 루트 override(K0_TRUST_ROOT_KEYSTORE dual-path)가 비기능 스텁 [live]

- 위치: `build.rs:52-59`, `src/keystore.rs:47-77`, `src/hsm_attest.rs:162-177`
- `K0_TRUST_ROOT_KEYSTORE=1` 로 빌드해도 `keystore::read_trust_root_pk()` 가 읽는 `TRUST_ROOT_PK_SLOT` 은 항상 `None`(`provision_trust_root_pk` 호출자 0). None 분기가 결국 개발용 `HSM_TRUST_ROOT_PK_CONST` 로 폴백한다. C1 을 수용 가능하게 만들 설계상 구제책이 작동하지 않아 C1 을 고착시킨다.
- 권고. `provision_trust_root_pk` 를 부팅 시 실제 out-of-band 소스로 구현/호출하거나, 슬롯이 비면 boot fail-stop(개발 const 폴백 금지).

### M11. Cargo.lock 이 gitignore 되어 외부 postcard/serde 의존성이 미고정 [live]

- 위치: `.gitignore`, `Cargo.toml:58-59`
- 에어갭 보안 커널인데 wire 역직렬화 경로의 외부 의존성이 미고정이다. clone+build 시 postcard/serde 가 최신 1.x 패치로 해소되어 재현 불가 빌드와 조용한 의존성 드리프트를 허용. 감사성 저하.
- 권고. Cargo.lock 커밋(바이너리 크레이트), postcard/serde 정확 버전 고정, 에어갭 빌드용 vendoring + 해시 검증, CI 에 `cargo --locked/--frozen` 게이트.

### M12. DRBG/PRNG init 실패가 FATAL 로깅 후 탐지 지점에서 멈추지 않고 계속 [완화됨, gap_self_check]

- 위치: `src/main.rs:450-495,608-615` (MAI-02 + INIT-01 + SYS-03(main) 병합), H5 와 동일 뿌리
- `init_prng()` Err 시 FATAL 출력 후 진행해 전부-0 BOOT_CHALLENGE 와 0 capability 토큰을 transient 하게 만든 뒤에야 `gap_self_check` 가 token==0 panic 으로 abort. 실질 악용성은 낮으나(0 토큰은 fail-closed 로 무효 처리됨) 설계 계약상 cap/DRBG init 은 탐지 지점에서 fail-stop 해야 한다. 현 구조는 fragile(폴백이 비-0 약토큰이면 우회).
- 권고. `init_prng()` Err 시 `init_trust_root`/`init_audit_read_cap`/`ipc::init` 호출 전에 즉시 halt. "HW 엔트로피 없음" 을 무조건 부팅 중단으로 취급.

---

## 4. LOW / INFO (요약)

전부 확정 항목이다. 다수가 단일 프로세스 모델 또는 `gap_self_check` 백스톱으로 현재 완화되나, Phase E/activate() 이후 재평가가 필요하다.

| id | sev | 위치 | 요지 | 상태 |
|----|-----|------|------|------|
| SYS-03 | Low | syscall.rs:287-302 | naked syscall 스텁이 dispatch 호출 시 스택 정렬 위반(SysV ABI) | live |
| IPC-02 | Low | ipc.rs:626-663 | 비커널 엔드포인트에 `ipc_call` 이 영구 hlt 폴링 | latent |
| CAP-02/04 | Low | capability.rs:151-161,518-552 | `derive` 가 부모 토큰을 복사 -> 권한축소 단조성/독립 폐기 깨짐 | dead code |
| HSM-02 | Low | hsm_registry.rs:487-512 | ENUMERATE 가 cap 범위 밖 전 슬롯 메타데이터 유출 | latent |
| CRY-02 | Low | crypto_service.rs:775-783 | `handle_dh` 가 X448 개인키 by-value 복사본을 미소거 | latent |
| AIR-02 | Low | air_gap.rs:220-224,273-277,332-336 | 거부된 air-gap syscall 반복으로 32엔트리 감사링 flooding(anti-forensics) | latent |
| AIR-03/CAP-01 | Low | air_gap.rs:327-336 | `handle_status` 토큰 비교에 독립 non-zero 가드 부재(gap_self_check 의존) | 완화됨 |
| TLS-02 | Low | tls/handshake.rs:316,332 | 비밀 ECDHE/ML-KEM 공유비밀 비상수시간 비교 | latent(tls-external) |
| TLS-03 | Low | tls/handshake.rs:170-186,329 | 임시 키 시드를 plain `fill(0)` 소거(DSE 제거 위험) | latent(tls-external) |
| TLS-04 | Low | tls/keyschedule.rs:62-72 | 고정 128B HKDF info 버퍼에 무검사 label write -> panic/abort | latent(tls-external) |
| MEM-03 | Low | memory_map.rs:302-310 | KASLR offset 정렬+비0 만 검사(canonical/overflow 경계 없음) | live |
| MEM-04 | Low | memory_map.rs:50-52 | `end()/total_usable_bytes` 정수 오버플로(release wrap) | live |
| MEM-05 | Low | allocator.rs:225-227 | alloc 프레임 0화가 identity(phys==virt) 하드코딩, 선형맵 walk 와 불일치 | latent |
| MEM-07 | Low | mmu.rs:492-496 | 중간 페이지테이블 엔트리가 USER/NX 강제 -> 사용자 leaf 사용불가(fail-closed) | latent |
| MEM-09 | Low | memory_map.rs:85-93 | `add_region` 가 64개 초과 영역을 조용히 폐기(가용 RAM 유실) | live |
| BOO-01 | Low | boot_stub.rs:124-126,234-243 | Multiboot2 매직 미검증 | live |
| INT-01 | Low | stack.rs:44,139-179 | SW 스택 카나리 탐지가 dead code 이고 고정 공지값 사용 | live |
| INT-03 | Low | cpu.rs:378-391,434-458 | SMEP/SMAP/UMIP 기회적 활성, fail-stop 없음, stac/clac 가 조용히 NOP 강등 | live |
| CAP-03 | Low | air_gap.rs:207-307 | one-shot cap 인도가 first-caller-wins, 호출자 신원 바인딩 없음 | 완화됨(단일프로세스) |
| HSM-04 | Info | hsm_registry.rs:303-317 | `attach` 가 bus.open 실패 시 생성 토큰을 스택에 미소거 | latent |
| PROC-01 | Info | process.rs:491-507 | `enter_ring3` 가 Loaded 상태 검사 생략 | latent |
| INT-04 | Info | cpu.rs:33-50 | `cpuid()` 인라인 asm 이 push/pop rbx 하면서 `options(nostack)` 선언 | live |
| MAI-03 | Info | vga.rs:247-288 | debug 예외 화면이 RIP/CS/RSP/RFLAGS 원시 출력(커널주소/KASLR 노출) | debug only |
| SYS-05 | Info | syscall.rs:483-486 | `is_user_address` 하한 없음(NULL/0 페이지 허용) | live(H3/H4 종속) |

---

## 5. 폐쇄형 / 에어갭 안전성 종합 판정

질문: "각 기능이 폐쇄형에서 정상적으로 안전하게 작동하는가?"

견고하게 성립하는 것 (감사로 확인).
- 외부 egress 차단. 폐쇄형 빌드에 외부망 I/O 표면이 없다. 디스패처가 `NetworkCapTake` 를 `#[cfg(feature="tls-external")]` 로 게이트해 syscall 14 가 closed 에서 `Unknown` 으로 fail-closed(`syscall.rs:350-351`). `AttestFixtureExport` 는 `#[cfg(feature="smoke")]`. `handle_attach` 의 Network 분기는 closed 에서 `Denied` 로 fail-stop(`hsm_registry.rs:578-584`).
- 빌드타임 + 컴파일타임 이중 확인. `gap_self_check` 가 closed 에서 `const _: () = assert!(!NETWORK_SYM_PRESENT)` 로 네트워크 심볼 부재를 컴파일타임 fold(`air_gap.rs:182-185`).
- 상수시간 인증. `Capability::is_valid_for`, `ct_token_eq`, `find_by_token`, `handle_status` 토큰 비교가 조기종료 없는 분기로 구현됨(타이밍 채널 차단). 직접 재독해 확인.
- 비밀 소거 규율. `crypto_service`/`keystore` 가 `Secret<T>` 와 명시 zeroize, AEAD 태그 실패 시 평문 소거 + 인증실패 반환, 서명 verify 결과 실제 확인, X448 전영(全零) 공유비밀 거부.
- fail-stop 의 진정성. `fatal_halt` = CLI+HLT 무한루프. 의도된 fail-stop 패닉들은 fail-open 이 아니라 fail-closed.
- 동적 할당 0. 본체에 `alloc` 사용 없음(정적/스택 버퍼).

폐쇄형에서도 "안전하게" 를 충족하지 못하는 것.
- 신뢰 무결성 (C1). 부착 신뢰 게이트가 위조 가능. 개발 신뢰 루트가 closed 빌드에도 그대로 박힌다. 이것이 폐쇄형 안전성의 가장 큰 구멍이다.
- 메모리 안전 기둥 (H1, H2). W^X/NX 가 closed 에서도 런타임 미집행.
- 가용성/격리 (H3, H4, H6). Phase E 에서 무신뢰 Ring 3 가 켜지면 closed 에서도 단발 syscall 로 커널 정지(H3) 및 커널 스택 R/W(H4), wire UB(H6)가 성립.
- 부팅 핸드오프 신뢰 (M7). 악성 부트로더 mmap 핸드오프가 부팅 OOB.

결론. 폐쇄형의 외부 egress 차단 보증은 견고하다. 그러나 zero-trust 의 두 기둥인 (1) 신뢰 앵커 무결성과 (2) 메모리 안전(W^X) 이 현재 출하 가능 상태에서 깨져 있으므로, "각 기능이 폐쇄형에서 안전하게 작동" 은 조건부다. C1 과 H1 을 먼저 닫고, Phase E 사용자 spawn 활성화 전에 H3/H4/H6 을 닫아야 한다.

---

## 6. 검증 후 기각된 후보 (위양성 방지 기록)

적대적 검증으로 14건이 기각되었다. 주요 사례.

- IPC-01 / BUS-03: payload 무경계 panic 우려 -> 모든 쓰기가 `set_payload`(`<= IPC_MAX_PAYLOAD` 검증) 경유, 호출자 구조적 경계로 도달 불가.
- CAP-01(is_valid_for tautology), HSM-01(슬롯 고갈), AIR-04(first-caller 미인증), MEM-06/MEM-08(map_user 검증): 현재 IPC syscall 스텁 + 단일 프로세스 모델 + debug 게이트 spawn 으로 도달 불가(단, Phase E 에서 재평가 필요).
- HSM-03(`slot_bus_mut` pub 우회): 바이너리 크레이트의 `pub` == `pub(crate)`, 외부 소비자 부재 + 모든 production 호출자가 `authenticate()` 선행.
- TLS-05/TLS-06: closed 에서 `Profile::External` 자체가 cfg-gate 로 부재, `run_loopback` 은 어느 프로필에서도 외부 I/O 없음.
- BUS-04 / SYS-04(close 후 AES 키 미소거): 유일 호출자가 다음 줄에서 `slot.zeroize()` 로 즉시 소거.
- ELF-LDR-02(entry vs 실행세그먼트): 데이터 페이지 무조건 NX 로 잘못된 entry 가 #PF 로 fail-closed.

---

## 7. 권고 우선순위

1. 즉시(출하 차단): C1(개발 신뢰 루트 빌드 fatal + 난수 시드) 와 M10(override 실구현/실패stop). 둘은 한 묶음이다.
2. 다음 마일스톤(메모리 안전 기둥 복원): H1(activate 활성화 또는 마커 중단) + H2(선형맵 RO). 둘은 한 묶음이다.
3. Phase E(사용자 spawn) 활성화 전 필수: H3(user-copy fault-fixup), H4(커널 스택 고반치 + PTE walk 검증), H6(REGISTRY 재진입 제거).
4. 암호/엔트로피 위생: H5+M12(엔트로피 fail-stop), M1(getrandom 레지스터), M2(서명 키 소거), M3(논스 유일성).
5. capability 일관성: M4(네트워크 cap 바인딩), M5(wire Status 게이트 일치).
6. 부팅/공급망 견고화: M7(mmap 경계), M11(Cargo.lock 고정), M8/M9 및 Low/Info.

---

## 8. 감사 메타

- 오케스트레이션: 13개 도메인/교차 분석 에이전트 -> 후보 65건 -> 적대적 검증 에이전트가 건별 실제 코드 재확인. 총 서브에이전트 78개, tool 호출 약 1,274회.
- 감사자 직접 재검증 항목: C1(gen-dev-keys 0xAA 시드 + include_bytes), H1(activate 주석 + boot_stub 0x83 맵), H3(idt fatal_halt + is_user_address), M1(lumen syscall3 규약 vs dispatch), 그리고 상수시간/에어갭 강점.
- 한계: elib-k0-nt 암호 라이브러리 자체는 신뢰 의존성으로 간주(커널의 오용만 감사). 동적 실행/QEMU 런타임 검증 미수행(정적 분석 기반). Phase E/activate() 이후 latent 항목 전수 재평가 필요.
