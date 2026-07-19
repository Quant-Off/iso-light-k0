//! AUDIT_RING 12 옥텟 ABI 보존과 entropy result slot_idx schema 충돌 0 host 검증 (D-05)
//!
//! Phase 5 EnrollEvent binary stability 를 잠근 채 Phase 8 entropy 이벤트의
//! result 9..=12 신규 할당과 slot_idx 0xFE 0xF0..0xF7 sub-encoding 이 기존
//! 사용 영역과 충돌하지 않음을 검증함 Wave 3 quorum.rs 가 동일 값을 정의함
#![cfg(not(target_os = "none"))]

use iso_light_k0::hsm_attest::{AUDIT_RING_CAPACITY, EnrollEvent};

// D-05 잠금 4 events (Pitfall 6 schema discriminator)
const RESULT_ENTROPY_RESEED_ATTEMPT: u8 = 9;
const RESULT_ENTROPY_RESEED_POLLING: u8 = 10;
const RESULT_ENTROPY_RESEED_RECOVERED: u8 = 11;
const RESULT_ENTROPY_RESEED_FAILED_PANIC: u8 = 12;

// Phase 5 5.1 6 사용 result 코드 (7 은 reserved 미사용)
const PHASE5_RESULT_CODES: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 8];

// Phase 5 6 사용 slot_idx marker (0xFE 는 trust_root 와 공유 result 코드로 구분)
const PHASE5_SLOT_MARKERS: [u8; 3] = [0xFC, 0xFD, 0xFF];
const ENTROPY_SLOT_GENERIC: u8 = 0xFE;

#[test]
fn audit_ring_capacity_is_32() {
    assert_eq!(AUDIT_RING_CAPACITY, 32);
}

#[test]
fn enroll_event_abi_size_12_bytes() {
    assert_eq!(core::mem::size_of::<EnrollEvent>(), 12);
    // repr(C) u32 선두 정렬 4 보존
    assert_eq!(core::mem::align_of::<EnrollEvent>(), 4);
}

#[test]
fn entropy_result_codes_no_conflict() {
    let entropy_codes = [
        RESULT_ENTROPY_RESEED_ATTEMPT,
        RESULT_ENTROPY_RESEED_POLLING,
        RESULT_ENTROPY_RESEED_RECOVERED,
        RESULT_ENTROPY_RESEED_FAILED_PANIC,
    ];
    for (i, &e) in entropy_codes.iter().enumerate() {
        // 9..=12 신규 영역 안
        assert!((9..=12).contains(&e));
        // Phase 5 5.1 6 사용 코드와 충돌 0
        for &p in PHASE5_RESULT_CODES.iter() {
            assert_ne!(e, p);
        }
        // 4 코드 상호 유일
        for &other in entropy_codes.iter().skip(i + 1) {
            assert_ne!(e, other);
        }
    }
}

#[test]
fn entropy_slot_idx_subencoding_unique() {
    // source-specific 0xF0..=0xF7 (bus_kind 가 verdict sub-code)
    for src in 0u8..8 {
        let slot = 0xF0 | src;
        assert!((0xF0..=0xF7).contains(&slot));
        // Phase 5 HSM slot 0..=7 영역과 분리
        assert!(slot > 7);
        // Phase 5 6 marker 와 충돌 0
        for &p in PHASE5_SLOT_MARKERS.iter() {
            assert_ne!(slot, p);
        }
        assert_ne!(slot, ENTROPY_SLOT_GENERIC);
    }
    // generic 0xFE 는 Phase 5 marker 목록과 충돌 0 (trust_root 공유는 result 코드 구분)
    for &p in PHASE5_SLOT_MARKERS.iter() {
        assert_ne!(ENTROPY_SLOT_GENERIC, p);
    }
}

#[test]
fn enroll_event_field_layout_preserved() {
    // Phase 5 wire-format 회귀 가드 seq u32 선두 + 4 u8 + 4 옥텟 prefix
    let ev = EnrollEvent {
        seq: 0x0102_0304,
        slot_idx: 0xFE,
        result: RESULT_ENTROPY_RESEED_ATTEMPT,
        bus_kind: 0,
        _pad: 0,
        pk_hash_prefix: [0xAA, 0xBB, 0xCC, 0xDD],
    };
    // SAFETY EnrollEvent 는 repr(C) 12 옥텟 Copy POD 로 [u8; 12] 재해석이 유효함
    let bytes: [u8; 12] = unsafe { core::mem::transmute(ev) };
    // repr(C) little-endian 배치 실측
    assert_eq!(&bytes[0..4], &0x0102_0304u32.to_le_bytes());
    assert_eq!(bytes[4], 0xFE);
    assert_eq!(bytes[5], RESULT_ENTROPY_RESEED_ATTEMPT);
    assert_eq!(bytes[6], 0);
    assert_eq!(bytes[7], 0);
    assert_eq!(&bytes[8..12], &[0xAA, 0xBB, 0xCC, 0xDD]);
}
