//! 펌웨어-중립 물리 메모리 맵 타입을 정의하는 모듈입니다.
//!
//! # Features
//! 부트로더가 전달한 물리 메모리 영역을 고정 크기 배열로 담는 중립 자료형
//! (`MemoryMap` / `MemoryRegion` / `MemoryKind`) 을 제공합니다. 특정 펌웨어
//! (Multiboot2 / UEFI / DTB) 파서에 의존하지 않으며, 동적 할당 없이 no_std
//! 환경에서 물리 프레임 할당자 초기화의 입력으로 사용됩니다. 실제 파싱은
//! `crate::boot::multiboot2` 등 어댑터 모듈이 담당합니다.

//
// 에러 타입
//

#[derive(Debug)]
pub enum ParseError {
    /// 전달된 펌웨어 info 주소가 유효하지 않음 (null 또는 정렬 불량)
    InvalidAddress,
    /// 헤더의 total_size가 비정상적 범위
    InvalidSize,
}

//
// 메모리 영역 타입
//

/// 물리 메모리 영역의 용도 분류 (Multiboot2 Type 필드 기반)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryKind {
    /// 자유롭게 사용 가능한 RAM
    Usable,
    /// BIOS·하드웨어에 예약된 영역
    Reserved,
    /// ACPI 정보 파싱 후 재사용 가능
    AcpiReclaimable,
    /// ACPI Non-Volatile Storage (전원 유지 필요)
    AcpiNvs,
    /// 불량 메모리 (사용 금지)
    BadMemory,
}

/// 단일 물리 메모리 영역
#[derive(Clone, Copy, Debug)]
pub struct MemoryRegion {
    /// 영역의 시작 물리 주소 (bytes)
    pub base: u64,
    /// 영역의 크기 (bytes)
    pub length: u64,
    pub kind: MemoryKind,
}

impl MemoryRegion {
    /// 영역의 끝 주소 (exclusive)
    pub fn end(self) -> u64 {
        self.base + self.length
    }
}

//
// 메모리 맵
//

/// 물리 메모리 맵이 포함할 수 있는 최대 영역 수.
/// x86_64 시스템 기준 일반적으로 10~20개이므로 64는 충분한 여유.
const MAX_REGIONS: usize = 64;

const DEFAULT_REGION: MemoryRegion = MemoryRegion {
    base: 0,
    length: 0,
    kind: MemoryKind::Reserved,
};

/// 파싱된 물리 메모리 맵.
/// 고정 크기 배열을 사용하여 동적 할당 없이 no_std 환경을 지원함.
pub struct MemoryMap {
    regions: [MemoryRegion; MAX_REGIONS],
    count: usize,
}

impl MemoryMap {
    pub const fn empty() -> Self {
        Self {
            regions: [DEFAULT_REGION; MAX_REGIONS],
            count: 0,
        }
    }

    /// 새 메모리 영역을 맵에 추가함.
    pub fn add_region(&mut self, region: MemoryRegion) -> Result<(), ParseError> {
        if self.count >= MAX_REGIONS {
            // 공간 부족: 영역을 무시하고 계속 진행 (ParseError 없이)
            return Ok(());
        }
        self.regions[self.count] = region;
        self.count += 1;
        Ok(())
    }

    /// 파싱된 모든 메모리 영역을 순회함
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.count]
    }

    /// `Usable` 영역만 필터링하여 순회함
    pub fn usable_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions()
            .iter()
            .filter(|r| r.kind == MemoryKind::Usable)
    }

    /// 전체 사용 가능한 물리 메모리 크기 (bytes)
    pub fn total_usable_bytes(&self) -> u64 {
        self.usable_regions().fold(0u64, |acc, r| acc + r.length)
    }

    /// 감지된 물리 메모리의 최상위 주소
    pub fn highest_addr(&self) -> u64 {
        self.regions().iter().fold(0u64, |acc, r| acc.max(r.end()))
    }
}
