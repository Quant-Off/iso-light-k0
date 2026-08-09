//! UEFI/limine 핸드오프를 펌웨어-중립 BootInfo 로 변환하는 어댑터 모듈입니다.
//!
//! # Features
//! `multiboot2` 어댑터와 대칭인 BootInfo 반환 시그니처만 잠근 표면 stub 입니다.
//! UEFI/limine 소비자는 아직 구현 범위가 아니므로 본문은 채우지 않으며
//! 발급 경로는 존재하지 않습니다. 실동작 어댑터는 x86 multiboot2 1개와 각
//! arch boot_stub 경유 합류 뿐이며 본 stub 을 호출하는 배선은 없습니다.

/// UEFI/limine 핸드오프 포인터를 파싱하여 `BootInfo` 를 반환할 예정인 표면 stub.
///
/// 아직 본문을 채우지 않았다. 현재는 시그니처만 잠그며 호출 시
/// 즉시 패닉하도록 `unimplemented!()` 로 발급 경로를 차단한다.
///
/// # Safety
/// `_handoff` 가 유효한 UEFI/limine 핸드오프 구조를 가리켜야 하며 부팅 초기
/// 단일 코어 시점에서만 호출해야 함.
#[allow(dead_code)]
pub unsafe fn parse_uefi(_handoff: u64) -> Result<super::BootInfo, super::memory_map::ParseError> {
    unimplemented!("UEFI/limine 어댑터는 Phase 11 (LIVE-01) 에서 구현됨")
}
