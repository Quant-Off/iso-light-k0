//! 펌웨어-중립 부팅 정보 (BootInfo) 를 정의하는 boot 계층입니다.
//!
//! # Features
//! GRUB Multiboot2 / UEFI(Phase 11) / DTB(Phase 10) 등 이질적 펌웨어 핸드오프를
//! 단일 `BootInfo` 구조로 수렴시켜 `crate::_kernel_start(&BootInfo)` 합류점을
//! 제공합니다. 각 어댑터 모듈(`multiboot2` 실동작 / `uefi` 표면 stub)이 부팅
//! 1회 `BootInfo` 를 채우며, 커널 본체는 이 중립 구조만 소비합니다. 모든
//! 필드는 고정 크기이며 static BSS 에 배치되어 동적 할당이 전혀 없습니다.

pub mod memory_map;
pub mod uefi;

use memory_map::MemoryMap;

/// 커널 커맨드라인 버퍼 최대 길이 (bytes)
const COMMAND_LINE_MAX: usize = 128;

/// 펌웨어-중립 부팅 정보.
///
/// 각 어댑터(multiboot2 / uefi / dtb)가 부팅 1회 채우며 커널 본체는 이 구조만
/// 소비한다. 고정 크기 배열만 사용하여 동적 할당 0 을 보장한다 (no_std).
/// mb2 어댑터가 채우지 않는 필드는 0 (미제공) 초기값으로 유지되며 Phase 10
/// (dtb) / Phase 11 (kaslr·framebuffer·rsdp) 에서 실사용 배선된다.
pub struct BootInfo {
    /// 물리 메모리 맵 (사용 가능 영역 확정)
    pub memory_map: MemoryMap,
    /// KASLR 직접 선형 매핑 오프셋 (0 = 미제공, Phase 11 LIVE-09)
    pub kaslr_offset: u64,
    /// 커널 커맨드라인 버퍼 (고정 크기)
    #[allow(dead_code)]
    pub command_line: [u8; COMMAND_LINE_MAX],
    /// command_line 의 유효 바이트 수
    #[allow(dead_code)]
    pub command_line_len: usize,
    /// ACPI RSDP 물리 포인터 (0 = 미제공)
    #[allow(dead_code)]
    pub rsdp_ptr: u64,
    /// Device Tree Blob 물리 포인터 (0 = 미제공, Phase 10 aarch64)
    #[allow(dead_code)]
    pub dtb_ptr: u64,
    /// 프레임버퍼 물리 기저 주소 (0 = 미제공)
    #[allow(dead_code)]
    pub framebuffer: u64,
}

impl BootInfo {
    /// 모든 필드가 비어 있는 BootInfo 를 const 로 생성함 (static BSS 초기값).
    pub const fn empty() -> Self {
        Self {
            memory_map: MemoryMap::empty(),
            kaslr_offset: 0,
            command_line: [0u8; COMMAND_LINE_MAX],
            command_line_len: 0,
            rsdp_ptr: 0,
            dtb_ptr: 0,
            framebuffer: 0,
        }
    }
}
