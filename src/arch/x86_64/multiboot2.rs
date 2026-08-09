//! Multiboot2 핸드오프를 펌웨어-중립 메모리 맵으로 파싱하는 어댑터 모듈입니다.
//!
//! # Features
//! GRUB이 전달한 Multiboot2 info 구조를 순회하여 물리 메모리 맵 태그(type=6)와
//! KASLR 커스텀 태그를 파싱하고, 결과를 `super::memory_map::MemoryMap` 중립
//! 자료형으로 반환합니다. 새 파싱 로직을 도입하지 않고 기존 파서를 재사용하며
//! 동적 할당은 전혀 없고 부팅 초기 identity mapping 단일 코어 시점에서만
//! 호출되어야 합니다.

use crate::boot::BootInfo;
use crate::boot::memory_map::{MemoryKind, MemoryMap, MemoryRegion, ParseError};

//
// mb2 를 BootInfo 로 변환하는 어댑터
//

/// 펌웨어-중립 부팅 정보의 static BSS 인스턴스 (부팅 1회 어댑터가 채움).
static mut BOOT_INFO: BootInfo = BootInfo::empty();

/// Multiboot2 핸드오프를 파싱하여 static `BootInfo` 를 채운 뒤 커널 합류점으로
/// 진입하는 어댑터 진입점.
///
/// boot_stub 의 `.Lkernel_entry` 간접 점프 대상으로 RDI = mb2_addr (mb2 info 물리
/// 주소) 를 수신한다. 파싱 실패 시 fail-safe(`unwrap_or_else(empty)`) 로
/// memory_map 과 kaslr_offset 을 채우며 parse_multiboot2 와 parse_kaslr_offset 을
/// 재사용한다. 나머지 BootInfo 필드는 empty 초기값을 유지하고 이후
/// `crate::_kernel_start(&BootInfo)` 로 합류한다.
///
/// # Safety
/// boot_stub 이 부팅 초기 단일 코어 identity mapping 상태에서 RDI 규약으로만
/// 진입시킨다. `BOOT_INFO` 는 본 부팅 단일 스레드 시점에만 기록되며 이후에는
/// 공유 참조(`&'static`)로만 소비된다.
// Multiboot2 는 x86/GRUB 펌웨어 핸드오프 전용이며 x86 `_kernel_start` 로 합류함
// 본 모듈은 crate::arch::x86_64 하위이므로 모듈 전체가 이미 arch cfg 게이트되어
// aarch64 컴파일 대상에서 배제된다 (per-item arch cfg 불요)
#[unsafe(no_mangle)]
pub extern "C" fn _boot_adapter_mb2(mb2_addr: u64) -> ! {
    // SAFETY: BOOT_INFO 는 부팅 단일 코어 진입에서만 기록된 후 공유 참조로만 소비됨
    unsafe {
        (*(&raw mut BOOT_INFO)).memory_map =
            parse_multiboot2(mb2_addr).unwrap_or_else(|_| MemoryMap::empty());
        // KASLR 물리맵 오프셋 태그 파싱 배선 복원 어댑터가 allocator init 이전에
        // 실행되므로 mb2 info 영역이 온전하며 태그 부재 시 0(미제공) 을 채움
        (*(&raw mut BOOT_INFO)).kaslr_offset = parse_kaslr_offset(mb2_addr).unwrap_or(0);
        super::kernel_start::_kernel_start(&*(&raw const BOOT_INFO))
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
        // 손상/악성 부트로더 핸드오프가 무경계 tag.size 로 물리 OOB read 를
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
// 부트로더가 직접 선형 매핑에 사용할 무작위 오프셋을 커널에 전달하는 방식
// Multiboot2 커스텀 태그(type=0x4B415352 "KASR")를 통해 전달됨
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
/// `_boot_adapter_mb2` 가 부팅 1회 호출하여 `BootInfo::kaslr_offset` 을 채운다.
/// 표준 grub-mkrescue ISO 는 본 커스텀 태그를 방출하지 않으므로 런타임 값은
/// 통상 `None`(0) 이며 부트로더가 태그를 삽입한 경우에만 오프셋이 흐른다.
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
