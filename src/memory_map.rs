//! 물리 메모리 맵 파싱을 수행하는 모듈입니다.
//!
//! 부트로더(GRUB Multiboot2)가 전달하는 메모리 맵을 파싱하여 어떤 물리 주소
//! 범위가 사용 가능한지를 확정하며, 이 정보를 기반으로 물리 프레임 할당자가
//! 초기화됩니다.

//
// 에러 타입
//

#[derive(Debug)]
pub enum ParseError {
    /// 전달된 Multiboot2 info 주소가 유효하지 않음 (null 또는 정렬 불량)
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

//
// Multiboot2 원시 구조체
//
// Intel SDM / Multiboot2 spec 기반의 C-호환 메모리 레이아웃

/// Multiboot2 정보 헤더 (첫 8 bytes)
#[repr(C)]
struct Mb2Header {
    total_size: u32,
    _reserved: u32,
}

/// 모든 Multiboot2 태그의 공통 헤더
#[repr(C)]
struct Mb2TagHeader {
    typ: u32,
    size: u32,
}

/// 태그 타입 6: 메모리 맵 태그 헤더
#[repr(C)]
struct Mb2MmapTag {
    typ: u32, // = 6
    size: u32,
    entry_size: u32,
    entry_version: u32,
}

/// 메모리 맵 태그의 개별 엔트리 (24 bytes)
#[repr(C)]
struct Mb2MmapEntry {
    base: u64,
    length: u64,
    typ: u32, // 1=Available, 2=Reserved, 3=ACPI Rec, 4=ACPI NVS, 5=Bad
    _reserved: u32,
}

//
// Multiboot2 파서
//

/// Multiboot2 정보 구조체를 파싱하여 `MemoryMap`을 반환함.
///
/// GRUB이 RBX에 저장한 Multiboot2 info 주소(`info_addr`)를 기반으로
/// 메모리 맵 태그(type=6)를 찾아 물리 메모리 영역을 수집함.
///
/// # Safety
/// - `info_addr`이 유효한 물리 메모리를 가리켜야 함.
/// - 부팅 초기 identity mapping 환경에서만 호출해야 함 (phys = virt).
/// - 멀티코어 활성화 전 단일 코어에서 호출해야 함.
pub unsafe fn parse_multiboot2(info_addr: u64) -> Result<MemoryMap, ParseError> {
    // 주소 유효성 검증: null 또는 8-byte 정렬 위반 시 거부
    if info_addr == 0 || info_addr & 7 != 0 {
        return Err(ParseError::InvalidAddress);
    }

    // SAFETY: 호출자가 info_addr의 유효성을 보장함
    let header = unsafe { &*(info_addr as *const Mb2Header) };
    let total_size = header.total_size;

    // Multiboot2 spec: total_size는 최소 8 bytes, 합리적 상한 = 64 KiB
    if !(8..=65536).contains(&total_size) {
        return Err(ParseError::InvalidSize);
    }

    let mut map = MemoryMap::empty();

    // 헤더(8 bytes) 이후부터 태그를 순회
    let mut offset: u32 = 8;
    while offset < total_size {
        let tag_phys = info_addr + offset as u64;

        // SAFETY: offset < total_size이므로 info_addr 내부의 유효한 위치
        let tag = unsafe { &*(tag_phys as *const Mb2TagHeader) };

        // 태그 타입 0 = 종료 태그
        if tag.typ == 0 {
            break;
        }

        // 태그 타입 6 = 메모리 맵
        // M7 손상/악성 부트로더 핸드오프가 무경계 tag.size 로 물리 OOB read 를
        //    유발하지 못하도록 태그 전체가 info 구조 경계 내에 있어야 함
        let info_end = info_addr + total_size as u64;
        let tag_fits = tag_phys.saturating_add(tag.size as u64) <= info_end;
        if tag.typ == 6 && tag.size >= 16 && tag_fits {
            // SAFETY: tag_fits 로 tag_phys+16 <= info_end 확인됨(Mb2MmapTag 16옥텟 read 안전)
            let mmap_tag = unsafe { &*(tag_phys as *const Mb2MmapTag) };
            let entry_size = mmap_tag.entry_size as u64;

            // entry_size는 최소 Mb2MmapEntry 크기(24 bytes)여야 함
            if entry_size >= 24 {
                let entries_start = tag_phys + 16; // Mb2MmapTag 헤더 이후
                // entries_end 는 tag.size 로 산정하되 info 구조 끝으로 clamp
                let entries_end = (tag_phys + tag.size as u64).min(info_end);

                let mut entry_ptr = entries_start;
                while entry_ptr.saturating_add(entry_size) <= entries_end {
                    // SAFETY: entry_ptr은 태그 범위 내부의 유효한 위치
                    let entry = unsafe { &*(entry_ptr as *const Mb2MmapEntry) };

                    let kind = match entry.typ {
                        1 => MemoryKind::Usable,
                        3 => MemoryKind::AcpiReclaimable,
                        4 => MemoryKind::AcpiNvs,
                        5 => MemoryKind::BadMemory,
                        _ => MemoryKind::Reserved,
                    };

                    // 길이가 0인 영역은 무시
                    if entry.length > 0 {
                        let _ = map.add_region(MemoryRegion {
                            base: entry.base,
                            length: entry.length,
                            kind,
                        });
                    }

                    entry_ptr += entry_size;
                }
            }
        }

        // 다음 태그는 8-byte 정렬: (size + 7) & !7
        let next = (tag.size + 7) & !7;
        offset = match offset.checked_add(next) {
            Some(v) => v,
            None => break, // overflow guard
        };
    }

    Ok(map)
}

//
// KASLR 오프셋 파싱
//
// 부트로더가 직접 선형 매핑에 사용할 무작위 오프셋을 커널에 전달하는 방식.
// Multiboot2 커스텀 태그(type=0x4B415352 "KASR")를 통해 전달됨.
//
// 부트로더 구현 요건:
//   1. KASLR 오프셋을 2 MiB 단위로 무작위 생성
//   2. 커널 canonical 주소 범위 내에 위치: 0xFFFF_8000_0000_0000 ~
//   3. Mb2KaslrTag 구조체를 Multiboot2 info 스트림에 삽입

/// Multiboot2 KASLR 커스텀 태그 타입 식별자
/// ASCII "KASR" = 0x4B_41_53_52 (little-endian)
const MB2_TAG_KASLR: u32 = 0x4B415352;

/// Multiboot2 KASLR 커스텀 태그 (16 bytes)
#[repr(C)]
struct Mb2KaslrTag {
    typ: u32,             // = MB2_TAG_KASLR
    size: u32,            // = 16
    phys_map_offset: u64, // 2 MiB 정렬된 직접 선형 매핑 시작 가상 주소
}

/// Multiboot2 info 구조체에서 KASLR 오프셋 태그를 파싱함.
///
/// 태그를 찾으면 2 MiB 정렬 검증 후 오프셋을 반환.
/// 태그가 없거나 정렬 요건을 만족하지 않으면 `None` 반환.
/// 호출자는 `None` 수신 시 `Mmu::initialize(None)`으로 기본값을 사용해야 함.
///
/// # Safety
/// `parse_multiboot2()`와 동일한 전제 조건 적용.
pub unsafe fn parse_kaslr_offset(info_addr: u64) -> Option<u64> {
    if info_addr == 0 || info_addr & 7 != 0 {
        return None;
    }

    // SAFETY: 호출자가 info_addr의 유효성을 보장함
    let header = unsafe { &*(info_addr as *const Mb2Header) };
    let total_size = header.total_size;

    if !(8..=65536).contains(&total_size) {
        return None;
    }

    let mut offset: u32 = 8;
    while offset < total_size {
        let tag_phys = info_addr + offset as u64;

        // SAFETY: offset < total_size이므로 info_addr 내부의 유효한 위치
        let tag = unsafe { &*(tag_phys as *const Mb2TagHeader) };

        if tag.typ == 0 {
            break;
        }

        if tag.typ == MB2_TAG_KASLR && tag.size >= 16 {
            // SAFETY: 태그 크기가 Mb2KaslrTag 크기(16 bytes)를 충족함
            let kaslr_tag = unsafe { &*(tag_phys as *const Mb2KaslrTag) };
            let off = kaslr_tag.phys_map_offset;

            // 2 MiB 정렬 검증: 대용량 페이지 매핑 요건
            if off & (crate::mmu::SIZE_2MIB - 1) == 0 && off != 0 {
                return Some(off);
            }
        }

        let next = (tag.size + 7) & !7;
        offset = offset.checked_add(next)?;
    }

    None
}
