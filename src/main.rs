#![no_std]
#![no_main]
// x86-interrupt 호출 규약: extern "x86-interrupt" 핸들러 작성에 필요 (x86 전용)
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]
// `static mut` 접근은 Rust 2024 의 `static_mut_refs`lint를 회피하기 위해
// `*(&raw const|mut X)` 패턴을 사용함. clippy의 `deref_addrof`는 이 패턴을
// `X` 직접 접근과 동치로 보고 경고하지만, 직접 접근은 다시 `static_mut_refs`
// 를 유발하므로 커널 전역에서 본 lint를 명시적으로 허용함
#![allow(clippy::deref_addrof)]

pub mod allocator;
pub mod arch; // arch 디렉토리 골격 + entropy 서브트리
// ISA 의존 모듈은 src/arch/x86_64/ 로 이동하고 명시 목록 re-export 로 본체 경로 보존
// x86 전용 gdt/idt/tss/vga 소비처(_kernel_start)를 src/arch/x86_64/ 로 이관하여
// 본체는 arch 중립 공통 서브셋만 cfg 없이 재노출
// (crate::arch::active 가 이미 cfg-alias 이므로 항목별 arch cfg는 불필요)
pub use crate::arch::active::{boot_stub, cpu, mmu, syscall};
// vga 는 debug 빌드 스모크 테스트만 소비하므로 debug_assertions 게이트로 유지
#[cfg(all(target_arch = "x86_64", debug_assertions))]
pub use crate::arch::active::vga;
// 펌웨어-중립 boot 계층 (BootInfo + multiboot2/uefi 어댑터)
pub mod boot;
// 중립 메모리맵 타입은 boot 계층에 있으며 crate::memory_map 경로는 별칭으로 보존
pub use crate::boot::memory_map;
pub mod capability; // Capability-based Access Control
pub mod crypto_service; // EP_CRYPTO 엔드포인트 암호화 서비스 디스패처
pub mod sign_service;   // EP_SIGN 엔드포인트 ML-DSA PQ 서명 서비스
pub mod elf; // ELF64 정적 실행 파일 파서
pub mod hsm; // HSM 추상 트레이트 + NullHsm
pub mod hsm_registry; // HSM 멀티 슬롯 레지스트리 (capability-backed)
pub mod hsm_attest; // ML-DSA-44 attest verifier + AUDIT_RING + ATTEST_BUF
pub mod air_gap; // air-gap 이중 게이트 + sys_hsm_status + 2 층 self-check
pub mod bus; // 외부 버스 드라이버 추상화 (BusDriver trait + enum-dispatch)
pub mod ipc; // IPC 메시지 패싱 (동기 rendezvous)
pub mod keystore; // 소프트 PSK 키 저장소 (HSM 폴백)
mod panic;
pub mod process; // 정적 프로세스 슬롯 + Ring 3 진입
pub mod stack; // 커널 스택 + 가드 페이지 레이아웃
pub mod tls; // TLS 1.3 PSK (psk_dhe_ke / psk_pq_hybrid_ke)
// 보안 메모리 소거는 외부 `zeroize` 크레이트(elib-k0-nt) 사용

// AddressSpace 는 debug 전용 try_spawn_user 스캐폴딩만 소비함
// KERNEL_ADDR_SPACE static 은 src/arch/x86_64/kernel_start.rs 로 이관됨
#[cfg(all(target_arch = "x86_64", debug_assertions))]
use mmu::AddressSpace;
// KERNEL_VMA_BASE/Mmu/PageTableFlags/Uninitialized 는 x86 _kernel_start 전용 소비였으며
// 해당 import 도 src/arch/x86_64/kernel_start.rs 로 함께 이동됨

// 사용자 ELF 페이로드 (build.rs 가 OUT_DIR 로 복사한 후 환경변수로 노출)
//
// 사용자 크레이트가 빌드되어 있지 않으면 build.rs 가 4-byte
// ELF magic placeholder 만 임베드함 그 경우 elf::parse() 가 `Truncated` /
// `BadMagic` 으로 거절하여 spawn 시도가 안전하게 fail-stop 됨
//
// _kernel_start 가 spawn_elf 와 enter_ring3 를 호출하면 dead_code 경고가 해소되며
// 그 전까지 일시 허용함
#[allow(dead_code)]
const USER_HELLO_ELF: &[u8] = include_bytes!(env!("ISO_USER_HELLO_ELF"));
#[allow(dead_code)]
const USER_LUMEN_ELF: &[u8] = include_bytes!(env!("ISO_USER_LUMEN_ELF"));


/// 임베드된 사용자 ELF 를 spawn 하고 성공 시 Ring 3 으로 진입함.
///
/// `elf` 가 placeholder (4-byte ELF magic) 이거나 손상된 경우 elf::parse 가
/// 거절하며, 본 함수는 단순히 반환되어 호출자가 다음 ELF 를 시도하거나
/// 메인 루프로 진입하도록 함.
///
/// # Safety
/// 부팅 단계 16 의 모든 사전 조건이 충족된 상태에서만 호출.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn try_spawn_user(elf: &[u8], label: &[u8], kernel_space: &AddressSpace) {
    // 4-byte placeholder 는 ELF 헤더 64 바이트 미만이므로 parse 가 Truncated 로 거절함
    // 그러나 길이 컷오프로 빠르게 판별하여 vga 메시지 노이즈를 줄임
    if elf.len() < 64 {
        return;
    }

    // SAFETY: 부팅 단계 16 의 사전조건, spawn_elf 내부에서 ELF 검증 + 페이지 매핑
    match unsafe { process::spawn_elf(kernel_space, elf) } {
        Ok(pid) => {
            // SAFETY: VGA 직접 접근은 debug 빌드 한정 단일 코어 부팅 경로
            unsafe {
                vga::print(b"[iso-light-k0] spawned ", vga::Color::LightGray);
                vga::print(label, vga::Color::White);
                vga::println(b", entering Ring 3...", vga::Color::Green);
            }
            // SAFETY: 본 함수에서 spawn 직후 즉시 진입, 다른 코드 끼지 않음
            //         enter_ring3 는 ! 반환
            unsafe {
                process::enter_ring3(pid);
            }
        }
        Err(_) => {
            // SAFETY: VGA 직접 접근은 debug 빌드 한정 단일 코어 부팅 경로
            unsafe {
                vga::print(b"[iso-light-k0] spawn rejected ", vga::Color::DarkGray);
                vga::println(label, vga::Color::DarkGray);
            }
        }
    }
}

/// EP_CRYPTO 라운드트립 검증용 스모크 테스트 (debug 전용).
///
/// CryptoPayload 레이아웃을 in-place 로 작성하여 BLAKE3 해시 요청을 한 번
/// 수행하고, 응답 페이로드의 형식이 `crypto_service::write_ok_reply` 가 기록한
/// 패턴(algo 에코, data_len ≥ 32, 비-에러 응답 타입)과 일치하는지 확인한다.
///
/// # Safety
/// `init_prng()` 와 `ipc::init()` 완료 후 단일 코어에서만 호출.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn crypto_smoke_test() {
    use ipc::{CryptoAlgo, CryptoPayload, MessageType};

    // 1. Capability 발급
    // SAFETY: init_prng / ipc::init 완료 가정
    let cap = match unsafe { ipc::issue_crypto_capability() } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
            unsafe {
                vga::println(
                    b"[iso-light-k0] crypto smoke: capability issue FAILED",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // 2. CryptoPayload 작성: BLAKE3("iso-light-k0")
    let mut req = CryptoPayload::zeroed();
    req.algo = CryptoAlgo::Blake3 as u8;
    let msg = b"iso-light-k0";
    req.data_len = msg.len() as u16;
    req.data[..msg.len()].copy_from_slice(msg);

    // CryptoPayload 자체를 바이트열로 직렬화하여 ipc_call 페이로드에 주입
    let req_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&req as *const CryptoPayload) as *const u8,
            core::mem::size_of::<CryptoPayload>(),
        )
    };

    // 3. 동기 IPC 호출
    // SAFETY: 단일 코어 부팅 초기, IPC 레지스트리 초기화 완료
    let reply = match unsafe { ipc::ipc_call(&cap, MessageType::HashReq, req_bytes) } {
        Ok(m) => m,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
            unsafe {
                vga::println(
                    b"[iso-light-k0] crypto smoke: ipc_call FAILED",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // 4. 응답 형식 검증: HashResp, algo 에코, 32바이트 다이제스트
    let payload = reply.payload_bytes();
    let ok = reply.header.msg_type == MessageType::HashResp
        && payload.len() >= ipc::CRYPTO_DATA_OFFSET
        && payload[0] == CryptoAlgo::Blake3 as u8
        && u16::from_le_bytes([payload[4], payload[5]]) as usize == 32;

    // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
    if ok {
        unsafe {
            vga::println(
                b"[iso-light-k0] crypto smoke: BLAKE3 round-trip OK",
                vga::Color::Green,
            );
        }
    } else {
        unsafe {
            vga::println(
                b"[iso-light-k0] crypto smoke: response shape MISMATCH",
                vga::Color::Red,
            );
        }
    }
    // reply 의 Secret<RawPayload> 는 Drop 시 평문 자동 소거
}

/// TLS 1.3 PSK 라운드트립 스모크 테스트, 디버그 빌드 전용.
///
/// 절차:
///   1. SoftKeystore 에 32B 임시 PSK 를 등록.
///   2. PSK-PQ-Hybrid (Closed 프로필) 로 in-kernel 루프백 핸드셰이크.
///   3. application_data 평문 라운드트립 (양방향 AEAD 검증).
///   4. PSK-Classical (X25519 단독) 로 동일 검증 (레거시 호환 경로).
///   5. 모든 슬롯 + 키 자료 zeroize.
///
/// 실패 시 VGA 로 빨간 메시지 출력. 정상 시 녹색 메시지 출력.
///
/// # Safety
/// `init_prng()` 와 `ipc::init()` 완료 후 단일 코어에서만 호출.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn tls_smoke_test() {
    use crate::hsm::PskId;
    use crate::tls::{CipherSuite, KexPolicy, Profile};

    // SAFETY: identity-mapped VGA 버퍼(0xB8000), 단일 코어
    unsafe {
        vga::println(b"[tls] === TLS 1.3 PSK smoke test ===", vga::Color::Green);
    }

    //
    // 1. PSK 등록
    //
    let psk_id = PskId::from_bytes(*b"iso-k0-tls-psk01");
    let psk_material = [0xA5u8; 32];
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: keystore init...",
            vga::Color::Green,
        );
    }
    // SAFETY: 단일 코어 부팅 초기
    let ks = unsafe { crate::keystore::global_mut() };
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: keystore ready",
            vga::Color::Green,
        );
    }
    if ks.provision(psk_id, &psk_material).is_err() {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: PSK provisioning FAILED",
                vga::Color::Red,
            );
        }
        return;
    }

    // 핸드셰이크는 SoftKeystore 가 HsmDriver 를 제공
    // SAFETY: 이미 동일 단일 코어 가정
    let ks_ref = unsafe { crate::keystore::global() };

    //
    // 2. PSK-Classical (X25519 단독, 레거시 호환) 을 먼저 실행
    //
    // 본 테스트는 ML-KEM 을 거치지 않아 TCG 환경에서도 빠르게 완결되어야 함
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: Classical handshake...",
            vga::Color::Green,
        );
    }
    // 본 스모크 테스트는 ChaCha20-Poly1305 슈트로 검증
    // AES-256-GCM 슈트도 동일 키 스케줄을 거치므로 코드 경로는 검증되나,
    // SHA-NI / AES-NI 미지원 TCG 환경에서는 GHash u128 GF 곱이 매우 느려
    // 부팅 스모크 시간 한도 내 완료가 어려움. KVM 환경에서는 정상 동작
    let classical = unsafe {
        tls::handshake::run_loopback(
            ks_ref,
            Profile::Closed,
            KexPolicy::Classical,
            CipherSuite::ChaCha20Poly1305Sha256,
            &psk_id,
        )
    };
    let (c2, s2) = match classical {
        Ok(p) => p,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] tls smoke: classical handshake FAILED",
                    vga::Color::Red,
                );
            }
            let ks2 = unsafe { crate::keystore::global_mut() };
            ks2.wipe_all();
            return;
        }
    };
    let msg = b"legacy-compat hello";
    let mut buf = [0u8; 32];
    let r3 = tls::handshake::loopback_send_recv(c2, s2, msg, &mut buf);
    let ok3 = matches!(r3, Ok(n) if n == msg.len() && &buf[..n] == msg);
    let _ = tls::close(c2);
    let _ = tls::close(s2);

    if ok3 {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: Classical (X25519) OK",
                vga::Color::Green,
            );
        }
    } else {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: Classical AEAD round-trip FAILED",
                vga::Color::Red,
            );
        }
    }

    //
    // 3. PSK-PQ-Hybrid 시나리오
    //
    // ML-KEM-768 keygen + encaps + decaps 는 SHAKE 다중 호출을 포함하여
    // SHA-NI 미지원 TCG 환경에서 수십 초 단위로 느릴 수 있음
    unsafe {
        vga::println(
            b"[iso-light-k0] tls smoke: PQ-Hybrid handshake (slow in TCG)...",
            vga::Color::Green,
        );
    }
    let hybrid = unsafe {
        tls::handshake::run_loopback(
            ks_ref,
            Profile::Closed,
            KexPolicy::Hybrid,
            CipherSuite::ChaCha20Poly1305Sha256,
            &psk_id,
        )
    };
    let (c_h, s_h) = match hybrid {
        Ok(p) => p,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] tls smoke: hybrid handshake FAILED",
                    vga::Color::Red,
                );
            }
            let ks2 = unsafe { crate::keystore::global_mut() };
            ks2.wipe_all();
            return;
        }
    };

    let msg_c2s = b"closed-net hello (c->s)";
    let mut recv_buf = [0u8; 64];
    let r1 = tls::handshake::loopback_send_recv(c_h, s_h, msg_c2s, &mut recv_buf);
    let ok_c2s = matches!(r1, Ok(n) if n == msg_c2s.len() && &recv_buf[..n] == msg_c2s);

    let msg_s2c = b"closed-net hello (s->c)";
    let mut recv_buf2 = [0u8; 64];
    let r2 = tls::handshake::loopback_send_recv(s_h, c_h, msg_s2c, &mut recv_buf2);
    let ok_s2c = matches!(r2, Ok(n) if n == msg_s2c.len() && &recv_buf2[..n] == msg_s2c);

    let _ = tls::close(c_h);
    let _ = tls::close(s_h);

    if ok_c2s && ok_s2c {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: PQ-Hybrid (X25519+MLKEM768) OK",
                vga::Color::Green,
            );
        }
    } else {
        unsafe {
            vga::println(
                b"[iso-light-k0] tls smoke: PQ-Hybrid AEAD round-trip FAILED",
                vga::Color::Red,
            );
        }
    }

    //
    // 4. 키저장소 + 풀 강제 소거
    //
    let ks2 = unsafe { crate::keystore::global_mut() };
    ks2.wipe_all();
    unsafe {
        crate::tls::wipe_all();
        vga::println(
            b"[iso-light-k0] tls smoke: keystore + pool wiped",
            vga::Color::Green,
        );
    }
}

#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn hsm_registry_smoke_test() {
    use crate::bus::BusKind;
    use hsm_registry::{
        HSM_MAX_SLOTS, HsmCapability, HsmRights, HsmSlotIdx, HsmSlotInfo, attach_kernel_side,
        with_registry, with_registry_mut,
    };

    // Step 1: 초기 상태 확인, attached_count == 0
    // SAFETY: BSP 단일 코어 부팅 시퀀스 + REGISTRY 정적 인스턴스 온라인
    let initial_count = unsafe { with_registry(|r| r.attached_count()) };
    if initial_count != 0 {
        // SAFETY: identity-mapped VGA 버퍼(0xB8000), CLI 상태
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (initial count != 0)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 2: attach 하여 capability 발급 (실제 Hash-DRBG-SHA256 토큰)
    // SAFETY: capability::init_prng() 완료, BSP 단일 코어
    let cap = match unsafe {
        attach_kernel_side(BusKind::Software, &[], HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE)
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (attach error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // Step 3: is_valid_for 양성/음성 (CT 단일 분기)
    if !cap.is_valid_for(cap.slot, HsmRights::USE) {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (valid cap rejected)",
                vga::Color::Red,
            );
        }
        return;
    }
    let wrong_slot = HsmSlotIdx(if cap.slot.0 == 0 { 1 } else { 0 });
    if cap.is_valid_for(wrong_slot, HsmRights::USE) {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (wrong-slot accepted)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 4: enumerate (cap 보유), 정확히 1개 슬롯 노출
    let mut info_buf: [HsmSlotInfo; HSM_MAX_SLOTS] = [HsmSlotInfo::empty(); HSM_MAX_SLOTS];
    // SAFETY: BSP 단일 코어 + REGISTRY 정적 인스턴스 온라인
    let written = unsafe { with_registry(|r| r.enumerate(&mut info_buf)) };
    if written != 1 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (enumerate count != 1)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 5: detach 거부 경로 정직 검증 (post-attach CAP-02 정신)
    //   - 위조된 cap (token=0xDEAD_BEEF_DEAD_BEEF, 동일 slot) 으로 detach 호출 시 실패 기대
    //   - 슬롯 상태는 Attached 유지 (변경 없음)
    let forged = HsmCapability::with_forged_token(0xDEAD_BEEF_DEAD_BEEF, cap.slot, HsmRights::REVOKE);
    // SAFETY: BSP 단일 코어; detach 진입 가능 시점
    let forged_result = unsafe { with_registry_mut(|r| r.detach(&forged, HsmRights::REVOKE)) };
    if forged_result.is_ok() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (forged cap accepted by detach)",
                vga::Color::Red,
            );
        }
        return;
    }
    // SAFETY: BSP 단일 코어; with_registry 의 invariant 동일
    let still_attached = unsafe { with_registry(|r| !r.slot_is_empty(cap.slot)) };
    if !still_attached {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (slot changed despite forged-cap rejection)",
                vga::Color::Red,
            );
        }
        return;
    }
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] HSM_DETACH_NO_CAP_DENIED marker (forged cap rejected, slot unchanged)",
            vga::Color::Green,
        );
    }

    // Step 6: 합법 cap 으로 detach 하여 슬롯 Empty 복귀 + zeroize 트리거
    // SAFETY: BSP 단일 코어
    let detach_result = unsafe { with_registry_mut(|r| r.detach(&cap, HsmRights::REVOKE)) };
    if detach_result.is_err() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (legitimate detach error)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 7: 슬롯 Empty + attached_count == 0 검증 (zeroize 효과 가시화)
    // SAFETY: BSP 단일 코어
    let is_empty = unsafe { with_registry(|r| r.slot_is_empty(cap.slot)) };
    // SAFETY: BSP 단일 코어
    let post_count = unsafe { with_registry(|r| r.attached_count()) };
    if !is_empty || post_count != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: HsmRegistry smoke FAILED (slot not zeroized post-detach)",
                vga::Color::Red,
            );
        }
        return;
    }

    // 성공 마커 출력
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] HSM_ATTACH_DETACH_ROUNDTRIP_OK marker",
            vga::Color::Green,
        );
        vga::println(
            b"[iso-light-k0] HsmRegistry smoke: attach -> verify -> detach -> zeroize OK",
            vga::Color::Green,
        );
    }
}

#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn bus_phase2_smoke_test() {
    use crate::bus::{BusDriver, BusInstance, BusKind};
    use hsm_registry::{HsmRights, attach_kernel_side, with_registry, with_registry_mut};

    // Step 1+2: SoftHSM bus_kind 로 attach 하여 capability 발급
    // SAFETY: capability::init_prng() 완료, BSP 단일 코어
    let cap = match unsafe {
        attach_kernel_side(
            BusKind::Software,
            &[],
            HsmRights::USE | HsmRights::ENUMERATE | HsmRights::REVOKE,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (attach error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let slot_idx = cap.slot.0 as usize;

    // 테스트 페이로드 (16 bytes), 스택-로컬 alloc 없음
    let pattern: [u8; 16] = [
        0xA5, 0x5A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    ];

    // Step 3: SoftwareBus 에 write
    // SAFETY: BSP 단일 코어; with_registry_mut 의 invariant 동일
    let write_result: Result<usize, crate::bus::BusError> = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => bus.write(&pattern),
            None => Err(crate::bus::BusError::NotOpen),
        })
    };
    let written = match write_result {
        Ok(n) => n,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (bus.write error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    if written != pattern.len() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (write short)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 4: SoftwareBus 에서 read-back (루프백 echo)
    let mut readback: [u8; 16] = [0u8; 16];
    // SAFETY: BSP 단일 코어
    let read_result: Result<usize, crate::bus::BusError> = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => bus.read(&mut readback),
            None => Err(crate::bus::BusError::NotOpen),
        })
    };
    let read_n = match read_result {
        Ok(n) => n,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (bus.read error)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    if read_n != pattern.len() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (read short)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 5: 루프백 동치성 검증, 16바이트 XOR-OR fold (early-return 없는 단일 분기)
    // CtEqOps 가 [u8] 슬라이스에 미구현 (스칼라 + SecureBuffer 만 지원) 이므로 동일 의미의
    // O(N) OR-누산 패턴을 직접 작성하며 데이터-의존 분기는 발생하지 않음
    let mut diff: u8 = 0;
    let mut i: usize = 0;
    while i < pattern.len() {
        diff |= pattern[i] ^ readback[i];
        i += 1;
    }
    if diff != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (loopback ct_eq mismatch)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 6: 합법 cap detach 하여 close-before-zeroize cascade 트리거
    // SAFETY: BSP 단일 코어
    let detach_result = unsafe { with_registry_mut(|r| r.detach(&cap, HsmRights::REVOKE)) };
    if detach_result.is_err() {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (legitimate detach error)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 7: observability, detach 후 slot.bus 의 raw 96바이트가 전부 0 인지 검사
    // SoftwareBus::zeroize 가 payload 를 비우고 BusInstance::zeroize 가 *self = Self::Empty
    // (discriminant 0) 로 reset 한 결과를 가시화
    // SAFETY: BSP 단일 코어; slot_bus_mut 는 idx<HSM_MAX_SLOTS 일 때 항상 Some 반환
    let raw_all_zero: bool = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(slot_idx) {
            Some(bus) => {
                let p: *const u8 = bus as *const BusInstance as *const u8;
                let n: usize = core::mem::size_of::<BusInstance>();
                // SAFETY: bus 는 유효한 &mut BusInstance, 동일 메모리 영역을 u8 슬라이스로 재해석
                let slice = core::slice::from_raw_parts(p, n);
                slice.iter().all(|&b| b == 0)
            }
            None => false,
        })
    };
    if !raw_all_zero {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (slot.bus raw bytes nonzero after detach)",
                vga::Color::Red,
            );
        }
        return;
    }

    // 추가 보강: registry 카운트 0 + 슬롯 Empty (앞선 detach cascade 와 동일)
    // SAFETY: BSP 단일 코어
    let post_count = unsafe { with_registry(|r| r.attached_count()) };
    if post_count != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: bus_phase2 smoke FAILED (attached_count != 0 post-detach)",
                vga::Color::Red,
            );
        }
        return;
    }

    // Step 8: 성공 마커 (qemu-test.sh 가 grep 으로 게이트)
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] BUS_PHASE2_OK marker (SoftwareBus loopback + detach cascade)",
            vga::Color::Green,
        );
    }
}

// chan_phase3_smoke_test  in-kernel relay 라운드트립 검증  marker CHAN_PHASE3_OK
#[cfg(all(target_arch = "x86_64", debug_assertions))]
unsafe fn chan_phase3_smoke_test() {
    use crate::bus::{BusDriver, BusInstance, BusKind, SoftHsmRole};
    use aes::{AES256GCM, GCM_NONCE_SIZE, GCM_TAG_SIZE};
    use blake::{BLAKE3_OUT_LEN, Blake3};
    use hsm_registry::{HsmRights, attach_kernel_side, with_registry, with_registry_mut, with_relay_buf};

    // (1) Blake3 src 슬롯 attach  rights = USE | REVOKE | RELAY_SRC
    // SAFETY: capability::init_prng / REGISTRY static 모두 온라인  BSP 단일 코어
    let cap_src = match unsafe {
        attach_kernel_side(
            BusKind::Software,
            &[SoftHsmRole::Blake3 as u8],
            HsmRights::USE | HsmRights::REVOKE | HsmRights::RELAY_SRC,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (attach Blake3 src)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let src_slot = cap_src.slot.0 as usize;

    // (2) AesGcm dst 슬롯 attach  rights = USE | REVOKE | RELAY_DST
    // SAFETY: 앞선 src 슬롯 attach 와 동일 invariant
    let cap_dst = match unsafe {
        attach_kernel_side(
            BusKind::Software,
            &[SoftHsmRole::AesGcm as u8],
            HsmRights::USE | HsmRights::REVOKE | HsmRights::RELAY_DST,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (attach AesGcm dst)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let dst_slot = cap_dst.slot.0 as usize;

    // (3) src.write(b"PHASE3_INPUT") 시 Role::Blake3 가 src.ring 에 32B digest 저장
    let write_input: &[u8; 12] = b"PHASE3_INPUT";
    // SAFETY: BSP 단일 코어; with_registry_mut 의 invariant 동일
    let write_ok = unsafe {
        with_registry_mut(|r| match r.slot_bus_mut(src_slot) {
            Some(bus) => bus.write(write_input).is_ok(),
            None => false,
        })
    };
    if !write_ok {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (src.write)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (4) kernel-side relay  with_relay_buf 안에서 src.read 32B 후 dst.write 32B
    // syscall ABI 우회  with_relay_buf direct 진입  RELAY_BUF entry+exit zeroize 보장
    // SAFETY: BSP single-core; with_relay_buf + with_registry_mut 는 disjoint static borrow
    let relay_ok = unsafe {
        with_relay_buf(|buf| {
            let read_n = with_registry_mut(|r| match r.slot_bus_mut(src_slot) {
                Some(bus) => bus.read(&mut buf[..BLAKE3_OUT_LEN]).unwrap_or(0),
                None => 0,
            });
            if read_n != BLAKE3_OUT_LEN {
                return false;
            }
            let write_n = with_registry_mut(|r| match r.slot_bus_mut(dst_slot) {
                Some(bus) => bus.write(&buf[..BLAKE3_OUT_LEN]).unwrap_or(0),
                None => 0,
            });
            // dst.write 의 AesGcm arm 은 32B input + 28B overhead = 60B 반환
            write_n == BLAKE3_OUT_LEN + GCM_NONCE_SIZE + GCM_TAG_SIZE
        })
    };
    if !relay_ok {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (relay)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (5) in-kernel 재계산 + slice ct_eq  dst.ring[..60] == AES256GCM(key, nonce_1, BLAKE3(input))
    // debug_aes_state / debug_ring 는 #[cfg(debug_assertions)] 노출  release 빌드 부재
    // 5a BLAKE3(b"PHASE3_INPUT") 직접 호출
    let mut hasher = Blake3::new();
    hasher.update(write_input);
    let digest = match hasher.finalize() {
        Ok(d) => d,
        Err(_) => {
            // SAFETY: identity-mapped VGA 버퍼
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (blake3 recompute)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let mut blake3_out = [0u8; BLAKE3_OUT_LEN];
    blake3_out.copy_from_slice(&digest.as_slice()[..BLAKE3_OUT_LEN]);

    // 5b dst 의 fresh key + counter==1 직접 노출 + expected ciphertext 합성 + dst.ring 와 비교
    let mut expected: [u8; 60] = [0u8; 60]; // nonce(12) || ct(32) || tag(16)
    let mut got: [u8; 60] = [0u8; 60];
    // SAFETY: BSP 단일 코어; debug_assertions 만 진입 가능
    let mismatch: u8 = unsafe {
        with_registry_mut(|r| -> u8 {
            let bus = match r.slot_bus_mut(dst_slot) {
                Some(b) => b,
                None => return 1,
            };
            // BusInstance::Software 케이스 직접 매치  enum-dispatch 일관
            let sw = match bus {
                BusInstance::Software(sw) => sw,
                _ => return 1,
            };
            let state = match sw.debug_aes_state() {
                Some(s) => s,
                None => return 1,
            };
            // nonce 직렬화 (counter == 1)
            let mut nonce = [0u8; GCM_NONCE_SIZE];
            nonce[..8].copy_from_slice(&state.nonce_counter.to_le_bytes());
            // expected: encrypt(key, nonce, blake3_out)
            let mut cipher = AES256GCM::default();
            cipher.init(state.key.expose());
            let mut tag = [0u8; GCM_TAG_SIZE];
            expected[..GCM_NONCE_SIZE].copy_from_slice(&nonce);
            if cipher
                .encrypt(
                    &nonce,
                    &[],
                    &blake3_out,
                    &mut expected[GCM_NONCE_SIZE..GCM_NONCE_SIZE + BLAKE3_OUT_LEN],
                    &mut tag,
                )
                .is_err()
            {
                return 1;
            }
            expected[GCM_NONCE_SIZE + BLAKE3_OUT_LEN..].copy_from_slice(&tag);
            // got: dst.ring[..60]
            got.copy_from_slice(&sw.debug_ring()[..60]);
            // slice CT-eq via XOR-OR fold
            let mut diff: u8 = 0;
            let mut i = 0;
            while i < 60 {
                diff |= expected[i] ^ got[i];
                i += 1;
            }
            diff
        })
    };
    if mismatch != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (ciphertext mismatch)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (6) 성공 마커  qemu-test.sh CHAN_PHASE3_OK 게이트
    // SAFETY: identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] CHAN_PHASE3_OK marker (Blake3 src -> AesGcm dst relay)",
            vga::Color::Green,
        );
    }

    // (7) detach 두 슬롯  registry 정리 후 다음 부팅 invariant 보존
    // SAFETY: BSP 단일 코어
    let _ = unsafe { with_registry_mut(|r| r.detach(&cap_src, HsmRights::REVOKE)) };
    let _ = unsafe { with_registry_mut(|r| r.detach(&cap_dst, HsmRights::REVOKE)) };
    let n_attached = unsafe { with_registry(|r| r.attached_count()) };
    if n_attached != 0 {
        // SAFETY: identity-mapped VGA 버퍼
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: chan_phase3 smoke FAILED (detach cascade)",
                vga::Color::Red,
            );
        }
    }
}

//
// attest_phase5_smoke_test  attach with attestation gate 2-leg 검증  marker ATTEST_PHASE5_OK
//
// Leg 1 valid sig 흐름  dev sk 로 BLAKE3(pk||bus||BOOT_CHALLENGE) 서명 후
//                       attach_kernel_side_with_attest Ok(cap) 슬롯 1 개 부착
// Leg 2 mutated sig 흐름  sig[0] ^= 0xFF 후 동일 호출 Err(AttestFailed)
//                         attached_count 변동 0 atomicity 회귀 가드
//
// 본 smoke 는 feature smoke 게이트 아래에서만 컴파일 closed 프로필 dev sk leak 0 보장
#[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
unsafe fn attest_phase5_smoke_test() {
    use crate::bus::BusKind;
    use blake::Blake3;
    use hsm_attest::{ACTIVE_TRUST_ROOT_PK, BOOT_CHALLENGE};
    use hsm_registry::{HsmRights, attach_kernel_side_with_attest, with_registry, with_registry_mut};
    use mldsa::MLDSA44;

    // dev sk 자료는 feature smoke 한정 include_bytes 로만 임베드
    // closed 프로필 빌드는 본 함수 자체가 cfg-out 되어 sk44 자료 leak 0
    const DEV_SK: &[u8; MLDSA44::SK_LEN] = include_bytes!("../keys/dev_trust_root.sk44");

    // (1) BOOT_CHALLENGE 와 ACTIVE_TRUST_ROOT_PK 스냅샷  init_trust_root 가 부팅 시 이미 채움
    // SAFETY BSP single-core 부팅 후 두 BSS static 의 단일 진입 read
    let pk: [u8; MLDSA44::PK_LEN] = unsafe { *(&raw const ACTIVE_TRUST_ROOT_PK) };
    let challenge: [u8; 32] = unsafe { *(&raw const BOOT_CHALLENGE) };

    // (2) Pre-image 재구성  hsm_attest 의 verify_attest body 와 byte-exact mirror
    // layout pk(1312) || bus_kind_octet(1) || BOOT_CHALLENGE(32) = 1345 옥텟
    let bus_kind = BusKind::Software;
    let mut pre = [0u8; MLDSA44::PK_LEN + 1 + 32];
    pre[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    pre[MLDSA44::PK_LEN] = bus_kind as u8;
    pre[MLDSA44::PK_LEN + 1..].copy_from_slice(&challenge);

    // (3) BLAKE3 digest  서명 평문은 32 옥텟 digest
    let mut hasher = Blake3::new();
    hasher.update(&pre);
    let digest_buf = match hasher.finalize() {
        Ok(d) => d,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (blake3 digest)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&digest_buf.as_slice()[..32]);

    // (4) ML-DSA-44 sign  ctx b"ISO-K0-ENROLL-V1" 16 옥텟 도메인 분리 verify_attest 와 동일 ctx
    // rnd 인자는 결정적 smoke 회귀 일관성을 위해 고정 nonce [0xBB;32] 사용
    let rnd = [0xBB_u8; 32];
    let sig: [u8; MLDSA44::SIG_LEN] = match MLDSA44::sign(DEV_SK, &digest, b"ISO-K0-ENROLL-V1", &rnd) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (mldsa44 sign)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // (5) attest_payload 직렬화  pk(1312) || sig(2420) = 3732 옥텟 ATTEST_EXACT
    const ATTEST_LEN: usize = MLDSA44::PK_LEN + MLDSA44::SIG_LEN;
    let mut attest_payload = [0u8; ATTEST_LEN];
    attest_payload[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    attest_payload[MLDSA44::PK_LEN..].copy_from_slice(&sig);

    // (6) Leg 1 valid sig  attach 성공 Ok(cap) 슬롯 1 개 부착
    let baseline_attached = unsafe { with_registry(|r| r.attached_count()) };
    // SAFETY BSP single-core attach_kernel_side_with_attest 가 verify gate 활성
    let cap_leg1 = match unsafe {
        attach_kernel_side_with_attest(
            BusKind::Software,
            &[crate::bus::SoftHsmRole::Blake3 as u8],
            &attest_payload,
            HsmRights::USE | HsmRights::REVOKE,
        )
    } {
        Ok(c) => c,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 1 attach rejected)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let after_leg1_attached = unsafe { with_registry(|r| r.attached_count()) };
    if after_leg1_attached != baseline_attached + 1 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 1 slot count delta != 1)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (7) Leg 2 mutated sig  sig[0] ^= 0xFF 후 attach 실패 슬롯 변동 0 atomicity 회귀
    let mut tampered_payload = attest_payload;
    tampered_payload[MLDSA44::PK_LEN] ^= 0xFF;
    let before_leg2_attached = unsafe { with_registry(|r| r.attached_count()) };
    let leg2_result = unsafe {
        attach_kernel_side_with_attest(
            BusKind::Software,
            &[crate::bus::SoftHsmRole::Blake3 as u8],
            &tampered_payload,
            HsmRights::USE | HsmRights::REVOKE,
        )
    };
    if leg2_result.is_ok() {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 2 mutated sig accepted)",
                vga::Color::Red,
            );
        }
        return;
    }
    let after_leg2_attached = unsafe { with_registry(|r| r.attached_count()) };
    if after_leg2_attached != before_leg2_attached {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5 smoke FAILED (Leg 2 slot count changed)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (8) 성공 마커  qemu-test.sh ATTEST_PHASE5_OK 게이트
    // SAFETY identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] ATTEST_PHASE5_OK marker (Leg 1 valid sig + Leg 2 mutated reject)",
            vga::Color::Green,
        );
    }

    // (9) Leg 1 슬롯 detach  registry 정리 다음 smoke 또는 Ring 3 spawn invariant 보존
    // SAFETY BSP 단일 코어
    let _ = unsafe { with_registry_mut(|r| r.detach(&cap_leg1, HsmRights::REVOKE)) };
}

//
// wire AttestSubmit fixture 정적 슬롯
//
// kernel 의 attest_phase5_1_wire_smoke_test 가 채우고
// lumen 의 SyscallNum AttestFixtureExport(13) 가 사용자 공간으로 복사
// feature smoke 한정 closed 빌드 BSS leak 0
//
// gate 정합  syscall variant / dispatch arm / handler 모두 #[cfg(feature = "smoke")]
//           smoke test 함수만 추가로 debug_assertions 게이트 release+smoke
//           빌드 시 fixture 는 BSS 슬롯으로 존재 (0 초기화), 채움 없음
#[used]
#[cfg(feature = "smoke")]
static mut WIRE_ATTEST_FIXTURE: [u8; 3733] = [0u8; 3733];

//
// attest_phase5_1_wire_smoke_test  wire AttestSubmit / Status round-trip 9-step
//                                  marker ATTEST_PHASE5_1_OK
//
// (1) BOOT_CHALLENGE 와 ACTIVE_TRUST_ROOT_PK 스냅샷 mirror
// (2) Pre-image (pk || bus_kind || challenge) 재구성 + BLAKE3 digest
// (3) ML-DSA-44 sign  ctx b"ISO-K0-ENROLL-V1"  rnd 결정적 [0xCC; 32]
// (4) wire AttestSubmit payload 3733 옥텟 조립 (pk || bus_kind || sig)
// (5) WIRE_ATTEST_FIXTURE 적재  lumen 의 sys_attest_fixture_export 수령 슬롯
// (6) Leg 1 valid  kernel-direct handle_attest_submit  resp status = Ok 응답 16B
// (7) Leg 2 mutated sig (sig 첫 옥텟 flip) handle_attest_submit  resp cmd 0xFFFF status 3
// (8) audit_ring delta == 2 후행 검증 (5 WireReattestOk + 6 WireReattestFail)
// (9) ATTEST_PHASE5_1_OK marker emit (substring 충돌 0)
#[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
unsafe fn attest_phase5_1_wire_smoke_test() {
    use crate::bus::{BusKind, WIRE_FRAME_MAX, handle_attest_submit};
    use blake::Blake3;
    use hsm_attest::{ACTIVE_TRUST_ROOT_PK, BOOT_CHALLENGE};
    use mldsa::MLDSA44;
    use zeroize::Zeroize;

    // dev sk 자료는 feature smoke 한정 include_bytes 로만 임베드  closed 빌드 leak 0
    const DEV_SK: &[u8; MLDSA44::SK_LEN] = include_bytes!("../keys/dev_trust_root.sk44");

    // (1) BOOT_CHALLENGE 와 ACTIVE_TRUST_ROOT_PK 스냅샷
    // SAFETY BSP single-core 부팅 후 두 BSS static 의 단일 진입 read
    let pk: [u8; MLDSA44::PK_LEN] = unsafe { *(&raw const ACTIVE_TRUST_ROOT_PK) };
    let challenge: [u8; 32] = unsafe { *(&raw const BOOT_CHALLENGE) };
    let bus_kind = BusKind::Software;

    // (2) Pre-image 재구성  hsm_attest verify_attest body 와 byte-exact mirror
    let mut pre = [0u8; MLDSA44::PK_LEN + 1 + 32];
    pre[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    pre[MLDSA44::PK_LEN] = bus_kind as u8;
    pre[MLDSA44::PK_LEN + 1..].copy_from_slice(&challenge);

    let mut hasher = Blake3::new();
    hasher.update(&pre);
    let digest_buf = match hasher.finalize() {
        Ok(d) => d,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (blake3 digest)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&digest_buf.as_slice()[..32]);

    // (3) ML-DSA-44 sign  ctx b"ISO-K0-ENROLL-V1" 16 옥텟 도메인 분리
    // rnd 인자 결정적 smoke 회귀 일관성 위해 고정 nonce [0xCC; 32] 사용 (앞선 0xBB 와 분리)
    let rnd = [0xCC_u8; 32];
    let sig: [u8; MLDSA44::SIG_LEN] = match MLDSA44::sign(DEV_SK, &digest, b"ISO-K0-ENROLL-V1", &rnd) {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                vga::println(
                    b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (mldsa44 sign)",
                    vga::Color::Red,
                );
            }
            return;
        }
    };

    // (4) wire AttestSubmit payload 3733 옥텟 조립 (pk(1312) || bus_kind(1) || sig(2420))
    //     handle_attest_submit 가 기대하는 wire layout
    const WIRE_ATTEST_LEN: usize = MLDSA44::PK_LEN + 1 + MLDSA44::SIG_LEN;
    let mut attest_wire = [0u8; WIRE_ATTEST_LEN];
    attest_wire[..MLDSA44::PK_LEN].copy_from_slice(&pk);
    attest_wire[MLDSA44::PK_LEN] = bus_kind as u8;
    attest_wire[MLDSA44::PK_LEN + 1..].copy_from_slice(&sig);

    // (5) WIRE_ATTEST_FIXTURE 적재  lumen smoke 가 sys_attest_fixture_export 로 회수
    // SAFETY BSP single-core 부팅 초기 본 함수 단일 진입
    unsafe {
        (*(&raw mut WIRE_ATTEST_FIXTURE)).copy_from_slice(&attest_wire);
    }

    // (6) handle_attest_submit kernel-side direct call (Leg 1 valid)
    let baseline_total = unsafe { (*(&raw const crate::hsm_attest::AUDIT_RING)).total };
    let mut resp_buf = [0u8; WIRE_FRAME_MAX];
    let n1 = handle_attest_submit(1, &attest_wire, &mut resp_buf);
    let resp_status_leg1 = u16::from_le_bytes([resp_buf[14], resp_buf[15]]);
    if n1 != 16 || resp_status_leg1 != 0 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (Leg 1 dispatcher)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (7) Leg 2 mutated sig (sig 첫 옥텟 flip == fixture offset PK_LEN+1 == 1313)
    let mut tampered = attest_wire;
    tampered[MLDSA44::PK_LEN + 1] ^= 0xFF;
    let mut resp_buf2 = [0u8; WIRE_FRAME_MAX];
    let n2 = handle_attest_submit(2, &tampered, &mut resp_buf2);
    let resp_cmd_leg2 = u16::from_le_bytes([resp_buf2[6], resp_buf2[7]]);
    let resp_status_leg2 = u16::from_le_bytes([resp_buf2[14], resp_buf2[15]]);
    if n2 != 16 || resp_cmd_leg2 != 0xFFFF || resp_status_leg2 != 3 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (Leg 2 dispatcher)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (8) audit_ring delta == 2 (5 WireReattestOk + 6 WireReattestFail)
    let after_total = unsafe { (*(&raw const crate::hsm_attest::AUDIT_RING)).total };
    if after_total != baseline_total + 2 {
        unsafe {
            vga::println(
                b"[iso-light-k0] FATAL: attest_phase5_1 wire smoke FAILED (audit_ring delta != 2)",
                vga::Color::Red,
            );
        }
        return;
    }

    // (9) ATTEST_PHASE5_1_OK marker  substring 충돌 0 검증됨
    // SAFETY identity-mapped VGA 버퍼
    unsafe {
        vga::println(
            b"[iso-light-k0] ATTEST_PHASE5_1_OK marker (wire AttestSubmit Leg1 ok + Leg2 denied + audit +2)",
            vga::Color::Green,
        );
    }

    // cleanup  비밀자료 stack-local 흔적 0
    pre.zeroize();
    digest.zeroize();
    attest_wire.zeroize();
    tampered.zeroize();
}

/// attest_payload 3733 옥텟 fixture export 핸들러 (feature smoke 한정)
///
/// SyscallNum AttestFixtureExport(13) 의 dispatch 본문 ABI
///   rdi = out_ptr (user-space dst)
///   rsi = out_len (== 3733 정확 정합)
///   반환 u64  성공 시 0, 음수 SyscallError as_rax
///
/// # Safety
/// 호출자 (lumen Ring 3) 가 ctx.arg1 == 3733 정확 정합 후 호출 권장 본 함수 자체가 검증
#[cfg(feature = "smoke")]
pub fn handle_attest_fixture_export(ctx: &mut syscall::SyscallContext) -> u64 {
    use syscall::{SyscallError, is_user_address};
    let out_ptr = ctx.arg0;
    let out_len = ctx.arg1 as usize;
    if out_len != 3733 {
        return SyscallError::BadArg.as_rax();
    }
    if !is_user_address(out_ptr) || !is_user_address(out_ptr.saturating_add(3733)) {
        return SyscallError::BadAddress.as_rax();
    }
    // SAFETY out_ptr 가 user_space dual-range 통과 SMAP stac/clac 윈도우 최소화
    //        WIRE_ATTEST_FIXTURE 는 BSP single-core 부팅 초기 채워진 BSS read-only 진입
    unsafe {
        cpu::stac();
        core::ptr::copy_nonoverlapping(
            (&raw const WIRE_ATTEST_FIXTURE) as *const u8,
            out_ptr as *mut u8,
            3733,
        );
        cpu::clac();
    }
    0
}

/// air-gap dual gate + sys_hsm_status + gap_self_check 통합 smoke test
///
/// # Safety
/// 부팅 시 단일 코어 init_audit_read_cap + init_network_cap (cfg) + gap_self_check 모두 완료 가정
/// debug + feature smoke 게이트로 release 빌드 부재
///
/// # Marker
/// VGA 4 line emit GAP_PHASE6_OK qemu-test.sh REQUIRE_GAP_PHASE6_OK env accumulator 가 잠금
#[cfg(all(target_arch = "x86_64", debug_assertions, feature = "smoke"))]
unsafe fn gap_phase6_smoke_test() {
    // Leg 1 AUDIT_READ_CAP token != 0 sanity (gap_self_check 통과 확인)
    // SAFETY BSP single-core init_audit_read_cap 호출 완료 가정 read-only snapshot
    let audit_cap_token = unsafe { (&raw const air_gap::AUDIT_READ_CAP).read().token };
    if audit_cap_token == 0 {
        // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
        unsafe {
            vga::println(
                b"[iso-light-k0] GAP_PHASE6 FAIL AUDIT_READ_CAP token 0",
                vga::Color::Red,
            );
        }
        return;
    }
    // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
    unsafe {
        vga::println(
            b"[iso-light-k0] GAP_PHASE6 leg 1 AUDIT_READ_CAP token nonzero OK",
            vga::Color::Green,
        );
    }

    // Leg 2 (cfg tls-external) NETWORK_ATTACH_CAP token != 0 sanity
    #[cfg(feature = "tls-external")]
    {
        // SAFETY BSP single-core init_network_cap 호출 완료 가정 read-only snapshot
        let network_cap_token = unsafe { (&raw const air_gap::NETWORK_ATTACH_CAP).read().token };
        if network_cap_token == 0 {
            // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
            unsafe {
                vga::println(
                    b"[iso-light-k0] GAP_PHASE6 FAIL NETWORK_ATTACH_CAP token 0",
                    vga::Color::Red,
                );
            }
            return;
        }
        // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
        unsafe {
            vga::println(
                b"[iso-light-k0] GAP_PHASE6 leg 2 NETWORK_ATTACH_CAP token nonzero OK",
                vga::Color::Green,
            );
        }
    }

    // Leg 3 (cfg not tls-external) NETWORK_SYM_PRESENT cfg const fold sanity
    #[cfg(not(feature = "tls-external"))]
    {
        const _: () = assert!(!air_gap::NETWORK_SYM_PRESENT);
        // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
        unsafe {
            vga::println(
                b"[iso-light-k0] GAP_PHASE6 leg 2 NETWORK_SYM_PRESENT const fold OK",
                vga::Color::Green,
            );
        }
    }

    // 마지막 GAP_PHASE6_OK marker (4-line 의 마지막 라인) qemu-test.sh grep 입력
    // SAFETY VGA buffer 단일 코어 부팅 시 초기화 완료 가정
    unsafe {
        vga::println(
            b"[iso-light-k0] GAP_PHASE6_OK marker",
            vga::Color::Green,
        );
    }
}
