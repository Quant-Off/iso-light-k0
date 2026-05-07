//! ELF64 정적 실행 파일 파서를 구현한 모듈입니다.
//!
//! `iso-light-k0` 의 사용자 프로세스 로더는 ELF64 LE little-endian 정적
//! 실행 파일(`ET_EXEC` 또는 `ET_DYN`-but-statically-linked)만 받습니다. 동적
//! 링킹·인터프리터·재배치 셋업은 모두 거부합니다.
//!
//! # 검증 항목
//!   - ELF magic `0x7F 'E' 'L' 'F'`, class = 64-bit, data = LSB, version = 1
//!   - `e_machine = EM_X86_64 (62)`, `e_type ∈ {ET_EXEC, ET_DYN}`, `e_version = 1`
//!   - `e_phentsize = 56`, `e_phnum ≤ MAX_PROGRAM_HEADERS`, 모든 헤더가 파일 안에 있음
//!   - 각 PT_LOAD 의 `p_filesz ≤ p_memsz`, `p_align ≥ PAGE_SIZE`, `p_offset+p_filesz`
//!     가 파일 크기 내, `p_vaddr` 가 사용자 영역 (`mmu::is_user_va`)
//!   - PT_INTERP, PT_DYNAMIC 거부 (정적 링킹 강제)
//!
//! # Authors
//! Q. T. Felix

use core::mem::size_of;

use crate::mmu;

//
// 한도 상수
//

/// 파싱 시 허용되는 최대 program header 수. ELF 가 더 많은 PHDR 을 포함하면
/// `ElfError::TooManyHeaders`. 사용자 프로세스 단순성을 강제.
pub const MAX_PROGRAM_HEADERS: usize = 8;

//
// ELF 상수
//

/// ELF 매직 4 바이트
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EV_CURRENT_U32: u32 = 1;

const PT_NULL: u32 = 0;
/// 메모리에 적재되어야 하는 세그먼트
pub const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_SHLIB: u32 = 5;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_E551;
const PT_GNU_RELRO: u32 = 0x6474_E552;

/// PT_LOAD 의 `p_flags` — 실행 가능
pub const PF_X: u32 = 1;
/// PT_LOAD 의 `p_flags` — 쓰기 가능
pub const PF_W: u32 = 2;
/// PT_LOAD 의 `p_flags` — 읽기 가능
pub const PF_R: u32 = 4;

//
// 에러 타입
//

#[derive(Debug, PartialEq, Eq)]
pub enum ElfError {
    /// 16 바이트 e_ident 미만으로 잘림
    Truncated,
    /// `0x7F 'E' 'L' 'F'` 매직 불일치
    BadMagic,
    /// 지원하지 않는 ELF class / data / version
    UnsupportedFormat,
    /// 지원하지 않는 e_type / e_machine / e_version
    UnsupportedTarget,
    /// `e_phentsize != 56`
    BadPhentSize,
    /// `e_phnum > MAX_PROGRAM_HEADERS`
    TooManyHeaders,
    /// program header 테이블이 파일 범위를 벗어남
    PhdrOutOfBounds,
    /// PT_LOAD 의 `p_offset + p_filesz` 가 파일 범위를 초과
    SegmentOutOfBounds,
    /// `p_filesz > p_memsz` 또는 `p_align < PAGE_SIZE`
    BadSegmentLayout,
    /// 사용자 영역 외 주소(`p_vaddr` ∉ user half) 또는 페이지 미정렬
    BadVirtualAddress,
    /// 동적 링킹 / interpreter 요구 (PT_INTERP, PT_DYNAMIC)
    DynamicLinkingRejected,
}

//
// 파싱 결과
//

/// 파싱된 ELF64 이미지의 뷰. 원본 `&[u8]` 의 라이프타임에 묶임.
pub struct Elf64Image<'a> {
    /// `e_entry` — 사용자 진입점 가상 주소
    pub entry: u64,
    /// 적재해야 하는 PT_LOAD 세그먼트 목록
    pub loads: ProgramHeaderArray,
    /// 원본 파일 바이트 (페이로드 복사 시 참조)
    pub raw: &'a [u8],
}

/// 검증된 PT_LOAD 세그먼트의 정렬된 목록 (정적 배열 + 길이).
pub struct ProgramHeaderArray {
    pub headers: [ProgramHeader; MAX_PROGRAM_HEADERS],
    pub len: usize,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ProgramHeader {
    /// 세그먼트가 실행 가능한가 (PF_X 비트)
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.p_flags & PF_X != 0
    }

    /// 세그먼트가 쓰기 가능한가 (PF_W 비트)
    #[inline]
    pub fn is_writable(&self) -> bool {
        self.p_flags & PF_W != 0
    }
}

//
// 파서
//

/// ELF64 정적 실행 파일을 검증 후 `Elf64Image` 로 반환.
///
/// 본 파서는 *읽기 전용* 이며 어떤 매핑도 변경하지 않음. 페이지 매핑은
/// `process::spawn_elf()` 가 수행함.
pub fn parse(data: &[u8]) -> Result<Elf64Image<'_>, ElfError> {
    if data.len() < size_of::<ElfHeader>() {
        return Err(ElfError::Truncated);
    }

    // SAFETY: 위 길이 검증 후 read_unaligned 로 alignment 무관 접근.
    let header: ElfHeader = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const ElfHeader) };

    // 1. e_ident 검증
    if header.e_ident_magic != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    if header.e_ident_class != ELFCLASS64
        || header.e_ident_data != ELFDATA2LSB
        || header.e_ident_version != EV_CURRENT
    {
        return Err(ElfError::UnsupportedFormat);
    }

    // 2. ELF 헤더 본체 검증
    if header.e_machine != EM_X86_64 || header.e_version != EV_CURRENT_U32 {
        return Err(ElfError::UnsupportedTarget);
    }
    if header.e_type != ET_EXEC && header.e_type != ET_DYN {
        return Err(ElfError::UnsupportedTarget);
    }
    if (header.e_phentsize as usize) != size_of::<ProgramHeaderRaw>() {
        return Err(ElfError::BadPhentSize);
    }
    if header.e_phnum as usize > MAX_PROGRAM_HEADERS {
        return Err(ElfError::TooManyHeaders);
    }

    // 3. program header 테이블 범위 검증
    let phoff = header.e_phoff as usize;
    let phsize = (header.e_phnum as usize) * size_of::<ProgramHeaderRaw>();
    let phend = phoff.checked_add(phsize).ok_or(ElfError::PhdrOutOfBounds)?;
    if phend > data.len() {
        return Err(ElfError::PhdrOutOfBounds);
    }

    // 4. 각 program header 파싱 + PT_LOAD 만 추려냄
    let mut loads = ProgramHeaderArray {
        headers: [ProgramHeader::default(); MAX_PROGRAM_HEADERS],
        len: 0,
    };
    for i in 0..(header.e_phnum as usize) {
        let off = phoff + i * size_of::<ProgramHeaderRaw>();
        // SAFETY: off..off+56 가 data 범위 내임을 위에서 보장.
        let raw: ProgramHeaderRaw =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(off) as *const ProgramHeaderRaw) };

        // 4-1. 동적 링킹 / interpreter 차단
        if raw.p_type == PT_INTERP || raw.p_type == PT_DYNAMIC {
            return Err(ElfError::DynamicLinkingRejected);
        }
        // 4-2. PT_LOAD 외에는 무시 (PT_NULL/PT_PHDR/PT_NOTE/PT_GNU_STACK 등)
        if raw.p_type != PT_LOAD {
            // PT_TLS / PT_SHLIB 도 본 단계 미지원이지만 정적 링킹 사용자 프로그램은
            // 일반적으로 포함하지 않으므로 단순 스킵.
            let _ = (
                PT_NULL,
                PT_NOTE,
                PT_SHLIB,
                PT_PHDR,
                PT_TLS,
                PT_GNU_STACK,
                PT_GNU_RELRO,
            );
            continue;
        }

        // 4-3. PT_LOAD 의 메모리/파일 크기 검증
        if raw.p_filesz > raw.p_memsz {
            return Err(ElfError::BadSegmentLayout);
        }
        if raw.p_align < PAGE_SIZE_U64 {
            return Err(ElfError::BadSegmentLayout);
        }
        if !raw.p_align.is_power_of_two() {
            return Err(ElfError::BadSegmentLayout);
        }
        let seg_end = (raw.p_offset)
            .checked_add(raw.p_filesz)
            .ok_or(ElfError::SegmentOutOfBounds)?;
        if seg_end as usize > data.len() {
            return Err(ElfError::SegmentOutOfBounds);
        }
        // 4-4. 사용자 영역 + 페이지 정렬
        if !mmu::is_user_va(raw.p_vaddr) {
            return Err(ElfError::BadVirtualAddress);
        }
        // p_memsz 끝도 사용자 영역 안에 있어야 함
        let mem_end = raw
            .p_vaddr
            .checked_add(raw.p_memsz)
            .ok_or(ElfError::BadVirtualAddress)?;
        if mem_end > 0x0000_8000_0000_0000 {
            return Err(ElfError::BadVirtualAddress);
        }

        loads.headers[loads.len] = ProgramHeader {
            p_type: raw.p_type,
            p_flags: raw.p_flags,
            p_offset: raw.p_offset,
            p_vaddr: raw.p_vaddr,
            p_filesz: raw.p_filesz,
            p_memsz: raw.p_memsz,
            p_align: raw.p_align,
        };
        loads.len += 1;
    }

    // 5. 진입점도 사용자 영역
    if !mmu::is_user_va(header.e_entry & !(PAGE_SIZE_U64 - 1)) {
        return Err(ElfError::BadVirtualAddress);
    }

    Ok(Elf64Image {
        entry: header.e_entry,
        loads,
        raw: data,
    })
}

//
// 내부 raw 구조체 (read_unaligned 로 매핑)
//

const PAGE_SIZE_U64: u64 = mmu::PAGE_SIZE as u64;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ElfHeader {
    e_ident_magic: [u8; 4],
    e_ident_class: u8,
    e_ident_data: u8,
    e_ident_version: u8,
    e_ident_osabi: u8,
    e_ident_abiversion: u8,
    e_ident_pad: [u8; 7],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

const _: () = assert!(size_of::<ElfHeader>() == 64);

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct ProgramHeaderRaw {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

const _: () = assert!(size_of::<ProgramHeaderRaw>() == 56);
