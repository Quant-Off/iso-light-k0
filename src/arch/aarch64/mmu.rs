//! 본 모듈은 aarch64 MMU stage1 4KiB granule 페이지 테이블과 typestate 전이를 수행합니다.
//!
//! # Features
//! 48-bit VA / 4KiB granule / TTBR0(하위 user)와 TTBR1(상위 kernel) split 4-level 페이지
//! 테이블을 정적 풀(동적 할당 0)로 구축합니다. MAIR_EL1 attribute slot(Device-nGnRnE /
//! Device-nGnRE MMIO / Normal WBWA)과 TCR_EL1(T0SZ/T1SZ/TG0/TG1/IPS)을 조립하고, 각 leaf
//! descriptor 는 x86 W^X 정책을 계승하여 writable 페이지에 UXN+PXN 을 자동 강제합니다
//! (writable + executable 동시 요청은 `MmuError::WxPolicyViolation`). UART MMIO 페이지는
//! Device-nGnRE(MAIR Attr1)로 매핑되어 MMU self_test 대상이 됩니다.
//!
//! x86_64 `mmu.rs` 의 typestate 계약(`Uninitialized`/`Initialized`/`Mmu<State>`/`PhantomData`
//! /`AddressSpace`)을 exact mirror 하되 descriptor 인코딩과 TTBR split, MAIR, TCR 은 aarch64
//! 고유입니다. 12-step barrier activate 와 AT S1E1R self_test 도 이 파일에 함께 배선됩니다.

use core::marker::PhantomData;

//
// 공개 상수
//

/// 4KiB 페이지 크기 (x86 `mmu::PAGE_SIZE: usize` 공개 표면과 정합).
///
/// 본체(process.rs/elf.rs)가 `crate::mmu::PAGE_SIZE` 를 usize 로 소비하므로 x86 과
/// 동일 타입으로 노출함. 내부 물리/가상 산술은 `PAGE_SIZE_U64` 를 사용함.
pub const PAGE_SIZE: usize = 4096;

/// PAGE_SIZE 의 u64 별칭 (내부 디스크립터/주소 산술 전용).
const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

/// 2 MiB 대용량 페이지 크기 (x86 `mmu::SIZE_2MIB` 공개 표면 정합, boot/multiboot2 KASLR 정렬 검증 소비).
pub const SIZE_2MIB: u64 = 2 * 1024 * 1024;

/// 커널 선형 매핑 상위 절반 VMA 기저 (TTBR1 T1SZ=16 상위 절반 시작 주소)
///
/// TTBR1 은 VA[47:0] 을 해석하며 상위 16 bit 는 전부 1(0xFFFF_...)이어야 함
pub const KERNEL_VMA_BASE: u64 = 0xFFFF_0000_0000_0000;

/// QEMU virt PL011 UART MMIO 물리 기본 주소 (폴백 기본값, DTB/BootInfo 우선)
pub const UART_PHYS: u64 = 0x0900_0000;

/// QEMU virt GICv3 distributor MMIO 물리 기본 주소 (gic.rs GICD_PHYS_BASE 와 동일 값 aarch64 내부 공유)
pub const GICD_PHYS: u64 = 0x0800_0000;

/// QEMU virt GICv3 redistributor MMIO 물리 기본 주소 (gic.rs GICR_PHYS_BASE 와 동일 값 aarch64 내부 공유)
pub const GICR_PHYS: u64 = 0x080A_0000;

/// GICD distributor register block 매핑 크기 (64 KiB)
const GICD_MMIO_SIZE: u64 = 0x1_0000;

/// GICR redistributor 코어당 RD+SGI 프레임 매핑 크기 (64 KiB * 2 = 128 KiB)
const GICR_MMIO_SIZE: u64 = 0x2_0000;

/// QEMU virt virtio-mmio transport window 물리 기본 주소 (엔트로피 source-1 virtio-rng 슬롯)
pub const VIRTIO_MMIO_PHYS: u64 = 0x0A00_0000;

/// virtio-mmio 슬롯 stride (QEMU virt 각 transport 0x200 바이트)
pub const VIRTIO_MMIO_STRIDE: u64 = 0x200;

/// virtio-mmio 슬롯 수 (QEMU virt 기본 32 슬롯을 순차 probe)
pub const VIRTIO_MMIO_COUNT: u64 = 32;

/// virtio-mmio 전체 window 매핑 크기 (32 * 0x200 = 16 KiB, 4 page)
const VIRTIO_MMIO_SIZE: u64 = VIRTIO_MMIO_STRIDE * VIRTIO_MMIO_COUNT;

//
// 내부 상수
//

const TABLE_ENTRIES: usize = 512;
/// 정적 중간 테이블 풀 크기 (TTBR0 identity + TTBR1 linear 4-level 여유 포함)
const POOL_TABLES: usize = 24;
/// bits[47:12]: 4KiB 페이지/테이블 출력 물리 주소 마스크
const PA_MASK: u64 = 0x0000_FFFF_FFFF_F000;

//
// MAIR_EL1 attribute slots
//   Attr0 = Device-nGnRnE  Attr1 = Device-nGnRE(MMIO)  Attr2 = Normal WBWA
//

const MAIR_ATTR0_DEVICE_NGNRNE: u64 = 0x00;
const MAIR_ATTR1_DEVICE_NGNRE: u64 = 0x04;
const MAIR_ATTR2_NORMAL_WBWA: u64 = 0xFF;

/// MAIR_EL1 레지스터 값 (8-bit attribute 3 슬롯을 하위부터 배치)
pub const MAIR_EL1_VALUE: u64 =
    MAIR_ATTR0_DEVICE_NGNRNE | (MAIR_ATTR1_DEVICE_NGNRE << 8) | (MAIR_ATTR2_NORMAL_WBWA << 16);

/// descriptor AttrIndx[4:2] 슬롯 인덱스
const ATTRIDX_DEVICE: u64 = 1; // MMIO Device-nGnRE (self_test 대상)
const ATTRIDX_NORMAL: u64 = 2; // Normal WBWA

//
// stage1 descriptor 비트 (4KiB granule)
//

const DESC_VALID: u64 = 1 << 0;
/// L0..L2 table descriptor / L3 page descriptor 공통 bit1 (block 은 0)
const DESC_PAGE: u64 = 1 << 1;
const DESC_ATTRINDX_SHIFT: u64 = 2;
const DESC_AP_RW_EL1: u64 = 0b00 << 6; // RW EL1 (EL0 미허용)
const DESC_AP_RO_EL1: u64 = 0b10 << 6; // RO EL1
const DESC_AP_RW_EL1_EL0: u64 = 0b01 << 6; // RW EL1+EL0 (user 쓰기 가능 페이지)
const DESC_AP_RO_EL1_EL0: u64 = 0b11 << 6; // RO EL1+EL0 (user 읽기/실행 페이지)
const DESC_SH_NONE: u64 = 0b00 << 8; // Device non-shareable
const DESC_SH_INNER: u64 = 0b11 << 8; // Normal Inner Shareable
const DESC_AF: u64 = 1 << 10; // Access Flag (미set 시 첫 접근 fault)
const DESC_PXN: u64 = 1 << 53; // Privileged execute-never
const DESC_UXN: u64 = 1 << 54; // Unprivileged execute-never

//
// TCR_EL1 필드 (4KiB granule 48-bit VA TTBR0/TTBR1 split)
//

const TCR_T0SZ: u64 = 16; // bits[5:0] TTBR0 VA[47:0]
const TCR_T1SZ: u64 = 16 << 16; // bits[21:16] TTBR1 VA[47:0]
const TCR_TG0_4K: u64 = 0b00 << 14; // TTBR0 4KiB
const TCR_TG1_4K: u64 = 0b10 << 30; // TTBR1 4KiB (TG1 인코딩은 TG0 와 상이)
const TCR_IRGN0_WBWA: u64 = 0b01 << 8;
const TCR_ORGN0_WBWA: u64 = 0b01 << 10;
const TCR_SH0_INNER: u64 = 0b11 << 12;
const TCR_IRGN1_WBWA: u64 = 0b01 << 24;
const TCR_ORGN1_WBWA: u64 = 0b01 << 26;
const TCR_SH1_INNER: u64 = 0b11 << 28;
const TCR_IPS_SHIFT: u64 = 32; // bits[34:32] PA size

//
// KASLR 비공개 상태 (x86 PHYS_MAP_OFFSET 대응)
//

/// TTBR1 커널 선형 매핑 기저 = KERNEL_VMA_BASE + KASLR 오프셋. `initialize` 에서 설정
static mut PHYS_MAP_OFFSET: u64 = KERNEL_VMA_BASE;

/// 12-step activate 직후 커널 선형 매핑이 접근 가능한지 추적 (x86 LINEAR_MAP_ACTIVE 대응)
static mut LINEAR_MAP_ACTIVE: bool = false;

/// 커널 선형 매핑 기저 VA 를 반환함 (console 재배치 / phys_to_virt 공용).
#[inline]
pub fn linear_base() -> u64 {
    // SAFETY PHYS_MAP_OFFSET 은 initialize 에서 1 회만 설정되는 부팅 초기 값
    unsafe { *(&raw const PHYS_MAP_OFFSET) }
}

//
// 링커 섹션 경계 심볼 (linker-aarch64.ld)
//

unsafe extern "C" {
    static _text_start: u8;
    static _rodata_start: u8;
    static _data_start: u8;
    static _kernel_end_aligned: u8;
}

//
// 에러 타입
//

/// 페이지 테이블 구축과 검증 실패 종류.
///
/// W^X 위반은 x86 `mmu::MmuError::WxPolicyViolation` 계약을 계승함.
#[derive(Debug, PartialEq, Eq)]
pub enum MmuError {
    /// W^X 정책 위반 writable + 실행 가능을 동시에 요청
    WxPolicyViolation,
    /// 이미 매핑된 주소에 재매핑 시도
    AlreadyMapped,
    /// 정적 중간 테이블 풀 소진
    TableExhausted,
    /// 주소가 4KiB 정렬 경계를 만족하지 않음
    UnalignedAddress,
    /// self_test AT S1E1R 변환 실패 (PAR_EL1.F set)
    SelfTestFault,
    /// self_test UART attribute 오매핑 (PAR_EL1.SH != 0 non-Device)
    SelfTestAttr,
}

//
// arch-중립 페이지 플래그 (x86 mmu::PageTableFlags 공개 표면 mirror)
//

/// 본체(process.rs)가 소비하는 arch-중립 페이지 매핑 의도 플래그.
///
/// x86 `mmu::PageTableFlags` 의 공개 API(PRESENT/WRITABLE/USER_ACCESSIBLE/NO_EXECUTE
/// /HUGE_PAGE + empty/bits/contains/union/remove)를 동일 표면으로 노출함. 비트 값은
/// aarch64 descriptor 인코딩과 무관한 의도 비트이며 `AddressSpace::map_page` 가
/// aarch64 stage1 leaf descriptor(AP/UXN/PXN)로 번역함(x86 은 직접 PTE 비트).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct PageTableFlags(u64);

impl PageTableFlags {
    /// 매핑 존재 (x86 PRESENT 대응, aarch64 DESC_VALID 로 번역)
    pub const PRESENT: Self = Self(1 << 0);
    /// 쓰기 가능 (aarch64 AP RW + UXN/PXN W^X 자동 강제)
    pub const WRITABLE: Self = Self(1 << 1);
    /// 사용자(EL0) 접근 가능 (aarch64 AP EL1+EL0)
    pub const USER_ACCESSIBLE: Self = Self(1 << 2);
    /// 실행 금지 (x86 NO_EXECUTE, aarch64 UXN+PXN)
    pub const NO_EXECUTE: Self = Self(1 << 3);
    /// 대용량 페이지 (x86 HUGE_PAGE; aarch64 런타임 process 경로는 4KiB 만 사용)
    pub const HUGE_PAGE: Self = Self(1 << 4);

    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }
    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    #[inline]
    pub const fn remove(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

//
// 사용자 영역 판정 헬퍼 (x86 mmu::is_user_va 공개 표면 mirror)
//

/// `va` 가 사용자 가상 주소(TTBR0 하위 절반) 범위이며 4KiB 정렬인지.
///
/// aarch64 TTBR0 는 VA 하위 절반을 담당하며 커널(TTBR1) 은 상위 절반(0xFFFF_...)
/// 이므로 사용자 매핑은 `0x0 .. 0x0000_8000_0000_0000` 범위 + 페이지 정렬만 허용함
/// (x86 canonical lower half 계약 계승).
#[inline]
pub fn is_user_va(va: u64) -> bool {
    va < 0x0000_8000_0000_0000 && (va & (PAGE_SIZE_U64 - 1)) == 0
}

//
// 페이지 테이블
//

/// 4-level 페이지 테이블의 단일 레벨 (512 entry x 8 byte = 4KiB).
#[repr(C, align(4096))]
pub struct Table {
    entries: [u64; TABLE_ENTRIES],
}

impl Table {
    const fn zeroed() -> Self {
        Self {
            entries: [0u64; TABLE_ENTRIES],
        }
    }
}

/// 가상 주소에서 해당 레벨의 9-bit 인덱스 추출 (level 0..=3).
///
/// - L0 VA[47:39] / L1 VA[38:30] / L2 VA[29:21] / L3 VA[20:12]
#[inline]
fn table_index(va: u64, level: u8) -> usize {
    let shift = 12 + (3 - level) as u64 * 9;
    ((va >> shift) & 0x1FF) as usize
}

/// 테이블 물리 주소 + 인덱스로 descriptor 슬롯 포인터 계산 (build 단계 identity PA).
#[inline]
fn entry_ptr(table_pa: u64, idx: usize) -> *mut u64 {
    // SAFETY table_pa 는 AddressSpace 내부 Table 의 identity 물리 주소이며 idx < 512
    unsafe { (table_pa as *mut u64).add(idx) }
}

//
// 프로세스 주소 공간 (TTBR0 하위 user / TTBR1 상위 kernel 2 루트 + 중간 테이블 풀)
//

/// stage1 페이지 테이블 루트와 정적 중간 테이블 풀을 소유하는 주소 공간.
///
/// 동적 할당 없이 `POOL_TABLES` 개의 중간 테이블을 정적으로 보유하며 `alloc_table` bump
/// 로 소비함. TTBR0 는 하위 절반(user/identity), TTBR1 은 상위 절반(kernel linear)을 담당.
#[repr(C, align(4096))]
pub struct AddressSpace {
    ttbr0_root: Table,
    ttbr1_root: Table,
    pool: [Table; POOL_TABLES],
    pool_next: usize,
}

#[allow(clippy::new_without_default)]
impl AddressSpace {
    /// 빈(전부 invalid) 주소 공간을 생성함.
    pub const fn new() -> Self {
        Self {
            ttbr0_root: Table::zeroed(),
            ttbr1_root: Table::zeroed(),
            pool: [const { Table::zeroed() }; POOL_TABLES],
            pool_next: 0,
        }
    }

    /// TTBR0 루트 테이블 물리 주소 (build 단계 identity).
    #[inline]
    pub fn ttbr0_root_pa(&self) -> u64 {
        &self.ttbr0_root as *const Table as u64
    }

    /// TTBR1 루트 테이블 물리 주소 (build 단계 identity).
    #[inline]
    pub fn ttbr1_root_pa(&self) -> u64 {
        &self.ttbr1_root as *const Table as u64
    }

    /// 중간 테이블 하나를 풀에서 할당하고 그 물리 주소를 반환함.
    fn alloc_table(&mut self) -> Result<u64, MmuError> {
        if self.pool_next >= POOL_TABLES {
            return Err(MmuError::TableExhausted);
        }
        let idx = self.pool_next;
        self.pool_next += 1;
        self.pool[idx] = Table::zeroed();
        Ok(&self.pool[idx] as *const Table as u64)
    }

    /// 단일 4KiB leaf descriptor 를 조립함 (W^X 정책 강제).
    ///
    /// # Errors
    /// `writable` 와 `executable` 을 동시에 요청하면 `MmuError::WxPolicyViolation`,
    /// `pa` 가 4KiB 정렬이 아니면 `MmuError::UnalignedAddress`
    fn leaf_desc(pa: u64, writable: bool, executable: bool, device: bool) -> Result<u64, MmuError> {
        // W^X 명시 위반은 거부 (x86 WxPolicyViolation 계승)
        if writable && executable {
            return Err(MmuError::WxPolicyViolation);
        }
        if pa & (PAGE_SIZE_U64 - 1) != 0 {
            return Err(MmuError::UnalignedAddress);
        }
        let mut d = DESC_VALID | DESC_PAGE | DESC_AF | (pa & PA_MASK);
        if device {
            // Device-nGnRE(MAIR Attr1) non-shareable 실행 금지
            d |= (ATTRIDX_DEVICE << DESC_ATTRINDX_SHIFT) | DESC_SH_NONE | DESC_UXN | DESC_PXN;
        } else {
            // Normal WBWA(MAIR Attr2) Inner Shareable
            d |= (ATTRIDX_NORMAL << DESC_ATTRINDX_SHIFT) | DESC_SH_INNER;
        }
        d |= if writable {
            DESC_AP_RW_EL1
        } else {
            DESC_AP_RO_EL1
        };
        // W^X 자동 강제 writable 이거나 비실행 데이터는 UXN+PXN (x86 WRITABLE 이 NO_EXECUTE 로 대응)
        if writable || !executable {
            d |= DESC_UXN | DESC_PXN;
        }
        Ok(d)
    }

    /// 한 VA 에서 PA 로의 매핑을 지정 루트(high=TTBR1)로 4KiB 페이지 배선함(EL1 leaf_desc).
    ///
    /// # Errors
    /// 풀 소진 시 `TableExhausted`, 재매핑 시 `AlreadyMapped`, W^X/정렬 위반은 leaf_desc 전파
    fn map_leaf(
        &mut self,
        high: bool,
        va: u64,
        pa: u64,
        writable: bool,
        executable: bool,
        device: bool,
    ) -> Result<(), MmuError> {
        let leaf = Self::leaf_desc(pa, writable, executable, device)?;
        self.map_desc(high, va, leaf)
    }

    /// 이미 조립된 L3 leaf 디스크립터를 지정 루트로 4-level walk 배선함.
    ///
    /// L0..L2 미존재 중간 테이블은 정적 풀에서 할당하며 L3 재매핑은 거부함.
    /// `map_leaf`(EL1)와 사용자 매핑(`map_user_page`, EL0 AP) 이 공용으로 소비함.
    ///
    /// # Errors
    /// 풀 소진 시 `TableExhausted`, 재매핑 시 `AlreadyMapped`
    fn map_desc(&mut self, high: bool, va: u64, leaf: u64) -> Result<(), MmuError> {
        let mut table_pa = if high {
            self.ttbr1_root_pa()
        } else {
            self.ttbr0_root_pa()
        };
        // L0..L2 walk 미존재 중간 테이블은 풀에서 할당
        for level in 0u8..3 {
            let idx = table_index(va, level);
            let slot = entry_ptr(table_pa, idx);
            // SAFETY slot 은 self 내부 Table 슬롯 단일 코어 build 단계 배타 접근
            let cur = unsafe { *slot };
            if cur & DESC_VALID == 0 {
                let next_pa = self.alloc_table()?;
                unsafe { *slot = DESC_VALID | DESC_PAGE | (next_pa & PA_MASK) };
                table_pa = next_pa;
            } else {
                table_pa = cur & PA_MASK;
            }
        }
        let idx = table_index(va, 3);
        let slot = entry_ptr(table_pa, idx);
        // SAFETY L3 leaf 슬롯 배타 접근
        unsafe {
            if *slot & DESC_VALID != 0 {
                return Err(MmuError::AlreadyMapped);
            }
            *slot = leaf;
        }
        Ok(())
    }

    /// PA 구간 [pa_start, pa_end) 를 TTBR0 identity + TTBR1 linear 양쪽에 4KiB 페이지로 배선함.
    ///
    /// # Errors
    /// map_page 오류(풀 소진/재매핑/W^X/정렬)를 그대로 전파
    unsafe fn map_range(
        &mut self,
        linear: u64,
        pa_start: u64,
        pa_end: u64,
        writable: bool,
        executable: bool,
        device: bool,
    ) -> Result<(), MmuError> {
        let start = pa_start & !(PAGE_SIZE_U64 - 1);
        let end = (pa_end + PAGE_SIZE_U64 - 1) & !(PAGE_SIZE_U64 - 1);
        let mut pa = start;
        while pa < end {
            // TTBR0 하위 절반 identity 매핑 (MMU 전 실행 주소 연속성)
            self.map_leaf(false, pa, pa, writable, executable, device)?;
            // TTBR1 상위 절반 커널 선형 매핑 (linear + pa)
            self.map_leaf(true, linear + pa, pa, writable, executable, device)?;
            pa += PAGE_SIZE_U64;
        }
        Ok(())
    }

    /// stage1 페이지 테이블을 구축함 (커널 섹션 W^X + UART MMIO Device).
    ///
    /// 커널 텍스트/벡터는 RX, rodata 는 RO-NX, data/bss 는 RW-NX 로 매핑하고 UART MMIO
    /// 페이지는 Device-nGnRE(Attr1) writable-NX 로 매핑함. TTBR1 선형 기저는 KERNEL_VMA_BASE
    /// + KASLR 오프셋이며 self_test 및 console 재배치 대상 VA 를 제공함.
    ///
    /// # Safety
    /// MMU 활성 전(identity 실행 상태)에 1 회만 호출해야 하며 링커 섹션 심볼이 유효해야 함
    ///
    /// # Errors
    /// 정적 풀 소진/재매핑/W^X 위반 시 해당 `MmuError`
    pub unsafe fn build_stage1_map(
        &mut self,
        kaslr_offset: u64,
        uart_phys: u64,
    ) -> Result<(), MmuError> {
        let linear = KERNEL_VMA_BASE.wrapping_add(kaslr_offset & !(PAGE_SIZE_U64 - 1));
        let text = &raw const _text_start as u64;
        let rodata = &raw const _rodata_start as u64;
        let data = &raw const _data_start as u64;
        let end = &raw const _kernel_end_aligned as u64;
        // SAFETY build 단계 단일 코어 배타 접근 각 map_range 는 4KiB 정렬 구간
        unsafe {
            // 커널 .text + .vector_table RX (Normal executable read-only)
            self.map_range(linear, text, rodata, false, true, false)?;
            // .rodata RO-NX
            self.map_range(linear, rodata, data, false, false, false)?;
            // .data + .bss RW-NX (W^X writable 은 UXN+PXN 자동 강제)
            self.map_range(linear, data, end, true, false, false)?;
            // UART MMIO Device-nGnRE writable-NX (self_test 대상)
            let uart = uart_phys & !(PAGE_SIZE_U64 - 1);
            self.map_range(linear, uart, uart + PAGE_SIZE_U64, true, false, true)?;
            // GICD distributor MMIO Device-nGnRE writable-NX (MMU on 후 gic::setup 접근 확보)
            self.map_range(linear, GICD_PHYS, GICD_PHYS + GICD_MMIO_SIZE, true, false, true)?;
            // GICR redistributor MMIO Device-nGnRE writable-NX (RD+SGI 프레임 128 KiB)
            self.map_range(linear, GICR_PHYS, GICR_PHYS + GICR_MMIO_SIZE, true, false, true)?;
            // virtio-mmio transport window Device-nGnRE writable-NX (virtio-rng probe + virtqueue MMIO)
            self.map_range(
                linear,
                VIRTIO_MMIO_PHYS,
                VIRTIO_MMIO_PHYS + VIRTIO_MMIO_SIZE,
                true,
                false,
                true,
            )?;
        }
        Ok(())
    }

    //
    // 런타임 process 주소 공간 표면 (x86 mmu::AddressSpace 공개 API mirror)
    //
    // 본체(process.rs)는 x86 과 동일한 map_page/map_user_page/walk_to_phys/
    // inherit_kernel_mappings 표면을 소비함. 아래 구현은 aarch64 stage1 4KiB leaf
    // descriptor 로 번역하며, x86 W^X 와 사용자 격리 계약을 계승하고 사용자 페이지는
    // TTBR0 하위 절반, 커널 매핑은 TTBR1 상위 절반으로 배선
    //

    /// 사용자(EL0) 4KiB leaf descriptor 를 조립함 (W^X 자동 강제).
    ///
    /// 데이터(`writable = true`) 는 RW EL1+EL0 + UXN+PXN(NX), 코드(`writable = false`)
    /// 는 RO EL1+EL0 + PXN(커널 실행 금지, 사용자 실행 허용).
    ///
    /// # Errors
    /// `pa` 가 4KiB 정렬이 아니면 `MmuError::UnalignedAddress`
    fn leaf_desc_user(pa: u64, writable: bool) -> Result<u64, MmuError> {
        if pa & (PAGE_SIZE_U64 - 1) != 0 {
            return Err(MmuError::UnalignedAddress);
        }
        let mut d = DESC_VALID
            | DESC_PAGE
            | DESC_AF
            | (pa & PA_MASK)
            | (ATTRIDX_NORMAL << DESC_ATTRINDX_SHIFT)
            | DESC_SH_INNER;
        if writable {
            // 사용자 데이터 RW, EL1+EL0 실행 금지(UXN+PXN)로 W^X 자동
            d |= DESC_AP_RW_EL1_EL0 | DESC_UXN | DESC_PXN;
        } else {
            // 사용자 코드 RO EL1+EL0 사용자 실행 허용(UXN=0) 커널 실행 금지(PXN)
            d |= DESC_AP_RO_EL1_EL0 | DESC_PXN;
        }
        Ok(d)
    }

    /// 4KiB 페이지 매핑 (x86 `AddressSpace::map_page` 대응). 플래그를 aarch64 leaf
    /// descriptor 로 번역하여 TTBR0(하위)/TTBR1(상위) 루트에 배선함.
    ///
    /// # Errors
    /// - `UnalignedAddress`: `virt_addr`/`phys_addr` 가 4KiB 정렬이 아닐 때
    /// - `WxPolicyViolation`: WRITABLE 이면서 NO_EXECUTE 부재(실행 가능)일 때
    /// - `AlreadyMapped` / `TableExhausted`: walk 배선 실패
    pub fn map_page(
        &mut self,
        virt_addr: u64,
        phys_addr: u64,
        flags: PageTableFlags,
    ) -> Result<(), MmuError> {
        if virt_addr & (PAGE_SIZE_U64 - 1) != 0 || phys_addr & (PAGE_SIZE_U64 - 1) != 0 {
            return Err(MmuError::UnalignedAddress);
        }
        let writable = flags.contains(PageTableFlags::WRITABLE);
        let executable = !flags.contains(PageTableFlags::NO_EXECUTE);
        // x86 W^X 계약: WRITABLE 은 NO_EXECUTE 필수
        if writable && executable {
            return Err(MmuError::WxPolicyViolation);
        }
        let high = virt_addr >= 0x0000_8000_0000_0000;
        let leaf = if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
            Self::leaf_desc_user(phys_addr, writable)?
        } else {
            Self::leaf_desc(phys_addr, writable, executable, false)?
        };
        self.map_desc(high, virt_addr, leaf)
    }

    /// 사용자 페이지 매핑 (x86 `AddressSpace::map_user_page` 대응, EL0 접근 + W^X).
    ///
    /// 코드(`writable = false`) 는 RO+X(EL0), 데이터(`writable = true`) 는 RW+NX(EL0).
    /// TTBR0 하위 절반에만 배선하여 커널(TTBR1) 격리를 유지함.
    ///
    /// # Errors
    /// - `UnalignedAddress`: `virt_addr` 가 사용자 영역(TTBR0 하위 절반) 밖이거나 미정렬
    /// - `AlreadyMapped` / `TableExhausted`: walk 배선 실패
    pub fn map_user_page(
        &mut self,
        virt_addr: u64,
        phys_addr: u64,
        writable: bool,
    ) -> Result<(), MmuError> {
        if !is_user_va(virt_addr) {
            return Err(MmuError::UnalignedAddress);
        }
        let leaf = Self::leaf_desc_user(phys_addr, writable)?;
        self.map_desc(false, virt_addr, leaf)
    }

    /// 가상 주소 `va` 의 4KiB 페이지 물리 주소를 페이지 테이블 워크로 산출함
    /// (x86 `AddressSpace::walk_to_phys` 대응). 매핑 없거나 block(대용량) leaf 면 `None`.
    ///
    /// # Safety
    /// build 단계(선형 매핑 미활성) 중간 테이블이 identity 물리 주소로 접근 가능하다고
    /// 가정함. 활성화 이후에는 선형 매핑 경로로 전환되어야 하며 사용 전제 변경 시 갱신 필요.
    pub unsafe fn walk_to_phys(&self, va: u64) -> Option<u64> {
        let high = va >= 0x0000_8000_0000_0000;
        let mut table_pa = if high {
            self.ttbr1_root_pa()
        } else {
            self.ttbr0_root_pa()
        };
        for level in 0u8..3 {
            let idx = table_index(va, level);
            let slot = entry_ptr(table_pa, idx);
            // SAFETY identity build 단계 중간 테이블 접근
            let cur = unsafe { *slot };
            if cur & DESC_VALID == 0 {
                return None;
            }
            // block descriptor(bit1==0) 는 4KiB process 경로 미사용 -> None
            if cur & DESC_PAGE == 0 {
                return None;
            }
            table_pa = cur & PA_MASK;
        }
        let idx = table_index(va, 3);
        let slot = entry_ptr(table_pa, idx);
        // SAFETY L3 leaf 슬롯 접근
        let leaf = unsafe { *slot };
        if leaf & DESC_VALID == 0 {
            return None;
        }
        Some(leaf & PA_MASK)
    }

    /// 다른 `AddressSpace` 의 커널 상위 절반(TTBR1 루트 전 엔트리) 을 계승함
    /// (x86 `inherit_kernel_mappings` 의 PML4[256..512] 계승 대응).
    ///
    /// 사용자 하위 절반(TTBR0) 은 변경하지 않으므로 사용자 격리는 유지됨. 계승된
    /// 엔트리는 `from` 의 중간 테이블 풀을 가리켜 커널 매핑을 공유함.
    ///
    /// # Safety
    /// - `from` 의 TTBR1 루트가 유효한 커널 매핑(build_stage1_map 완료) 을 보유해야 함.
    /// - 본 객체 TTBR1 루트 상위 절반이 비어 있거나 동일 매핑이어야 함.
    pub unsafe fn inherit_kernel_mappings(&mut self, from: &AddressSpace) {
        for i in 0..TABLE_ENTRIES {
            self.ttbr1_root.entries[i] = from.ttbr1_root.entries[i];
        }
    }
}

/// ID_AA64MMFR0_EL1.PARange 를 읽어 IPS 후보를 반환함 (하드코딩 폴백 0b101 = 48-bit PA).
pub fn read_parange() -> u64 {
    let mmfr0: u64;
    // SAFETY mrs 시스템 레지스터 read 부작용 없음
    unsafe {
        core::arch::asm!(
            "mrs {v}, id_aa64mmfr0_el1",
            v = out(reg) mmfr0,
            options(nomem, nostack, preserves_flags),
        );
    }
    let parange = mmfr0 & 0xF;
    // TCR_EL1.IPS 는 최대 0b101(48-bit) 로 clamp (하드웨어 초과 인코딩 회피)
    if parange > 0b101 { 0b101 } else { parange }
}

/// TCR_EL1 값을 조립함 (4KiB granule 48-bit VA TTBR split Inner Shareable WBWA).
pub fn build_tcr_el1() -> u64 {
    TCR_T0SZ
        | TCR_T1SZ
        | TCR_TG0_4K
        | TCR_TG1_4K
        | TCR_IRGN0_WBWA
        | TCR_ORGN0_WBWA
        | TCR_SH0_INNER
        | TCR_IRGN1_WBWA
        | TCR_ORGN1_WBWA
        | TCR_SH1_INNER
        | (read_parange() << TCR_IPS_SHIFT)
}

//
// Typestate MMU (x86 mmu::Mmu<State> 계약 exact mirror)
//

pub struct Uninitialized;
pub struct Initialized;

/// 타입 수준 상태 머신으로 MMU 초기화 순서를 컴파일 타임에 강제함.
///
/// `Mmu<Uninitialized>` 에서 `initialize` 를 호출하면 `Mmu<Initialized>` 로 전이되며,
/// 그 상태에서만 `activate`/`self_test` 가 호출 가능함.
pub struct Mmu<State> {
    _marker: PhantomData<State>,
}

#[allow(clippy::new_without_default)]
impl Mmu<Uninitialized> {
    pub const fn new() -> Self {
        Mmu {
            _marker: PhantomData,
        }
    }

    /// KASLR 오프셋을 반영하여 `Mmu<Initialized>` 로 상태 전환함 (HAL pre_mmu_enable).
    ///
    /// `None` 이면 KASLR 오프셋 0(고정 KERNEL_VMA_BASE)을 사용함. 오프셋은 4KiB 정렬로
    /// 보정되어 TTBR1 선형 매핑 기저 `PHYS_MAP_OFFSET` 에 저장됨.
    pub fn initialize(self, kaslr_offset: Option<u64>) -> Mmu<Initialized> {
        let aligned = kaslr_offset.unwrap_or(0) & !(PAGE_SIZE_U64 - 1);
        // SAFETY 부팅 초기 단일 코어 이 함수는 1 회만 호출됨
        unsafe {
            *(&raw mut PHYS_MAP_OFFSET) = KERNEL_VMA_BASE.wrapping_add(aligned);
        }
        Mmu {
            _marker: PhantomData,
        }
    }
}

impl Mmu<Initialized> {
    /// 지정 주소 공간을 현재 코어에 활성화함 (12-step barrier 시퀀스).
    ///
    /// 정해진 순서를 그대로 지켜야 하며 barrier 생략이나 재배치는 금지된다.
    /// 특히 `MSR SCTLR_EL1`(M=1) 앞뒤 ISB 가 핵심(M-bit 켜기 전후 컨텍스트 동기화)이다.
    /// step 1 DC CVAC 는 페이지 테이블 전 영역(루트 2 + 정적 풀)을 PoC 로 clean 한다.
    ///
    /// # Safety
    /// `space` 의 TTBR0/TTBR1 루트가 유효한 물리 주소에 있고 커널 매핑을 포함해야 하며
    /// `build_stage1_map` 완료 후 MMU off 상태에서 1 회만 호출해야 함
    pub unsafe fn activate(&self, space: &AddressSpace) {
        let ttbr0 = space.ttbr0_root_pa();
        let ttbr1 = space.ttbr1_root_pa();
        let mair = MAIR_EL1_VALUE;
        let tcr = build_tcr_el1();
        let table_bytes = core::mem::size_of::<AddressSpace>() as u64;
        // 현재 SCTLR_EL1 을 읽어 M(bit0)만 set (C/I 캐시 비트는 현 상태 유지)
        let mut sctlr: u64;
        // SAFETY 시스템 레지스터 read 부작용 없음
        unsafe {
            core::arch::asm!(
                "mrs {v}, sctlr_el1",
                v = out(reg) sctlr,
                options(nomem, nostack, preserves_flags),
            );
        }
        sctlr |= 1; // SCTLR_EL1.M = 1 MMU enable

        // SAFETY: 12-step barrier 순서 재배치 금지, SCTLR 앞뒤 ISB 필수
        //         DC CVAC 루프가 cmp/b.lo 로 NZCV 를 변경하므로 preserves_flags 미부여
        unsafe {
            core::arch::asm!(
                // step 1 DC CVAC 페이지 테이블 을 PoC 로 clean (MMU off 기록분을 table walker 가시화)
                "   mov   {p}, {t0}",
                "   add   {e}, {t0}, {sz}",
                "2: dc    cvac, {p}",
                "   add   {p}, {p}, #64",
                "   cmp   {p}, {e}",
                "   b.lo  2b",
                // step 2 DSB ISH cache maintenance 완료를 후속 명령 전에 보장
                "   dsb   ish",
                // step 3 IC IALLU icache 의 old 물리 매핑 명령 제거 (PoU)
                "   ic    iallu",
                // step 4 DSB ISH ic 완료 보장
                "   dsb   ish",
                // step 5 ISB 파이프라인 flush
                "   isb",
                // step 6 MSR TTBR0_EL1 하위 절반 user 루트
                "   msr   ttbr0_el1, {t0}",
                // step 7 MSR TTBR1_EL1 상위 절반 kernel 루트 (TTBR split)
                "   msr   ttbr1_el1, {t1}",
                // step 8 MSR MAIR_EL1 메모리 속성 slot
                "   msr   mair_el1, {mair}",
                // step 9 MSR TCR_EL1 변환 제어 (4KiB 48-bit VA)
                "   msr   tcr_el1, {tcr}",
                // step 10 ISB SCTLR 앞 동기화 (제어 레지스터 반영 후 M-bit)
                "   isb",
                // step 11 MSR SCTLR_EL1 M=1 MMU enable (모든 제어 레지스터 세팅 후 마지막)
                "   msr   sctlr_el1, {sctlr}",
                // step 12 ISB SCTLR 뒤 동기화 (새 변환 상태로 fetch)
                "   isb",
                t0 = in(reg) ttbr0,
                t1 = in(reg) ttbr1,
                mair = in(reg) mair,
                tcr = in(reg) tcr,
                sctlr = in(reg) sctlr,
                sz = in(reg) table_bytes,
                p = out(reg) _,
                e = out(reg) _,
                options(nostack),
            );
            *(&raw mut LINEAR_MAP_ACTIVE) = true;
        }
    }
}

/// MMU enable 직후 UART MMIO 매핑 attribute 를 검증함.
///
/// `AT S1E1R, <uart_va>` 로 stage1 EL1 read 변환을 강제 실행한 뒤 PAR_EL1 을 읽어
/// F(fault) 미set 과 ATTR(bits[63:56]) == Device-nGnRE(0x04)를 확인한다. PAR_EL1.ATTR 은
/// MAIR Attr 인코딩을 그대로 반환하므로 UART 가 실수로 Normal cacheable(0xFF)로 오매핑되면
/// ATTR != 0x04 로 조기 검출된다(직렬 소실/speculative fault 차단). 아키텍처상 Device 메모리의
/// PAR_EL1.SH 는 Outer Shareable(0b10)로 강제되므로 shareability 가 아니라 memory attribute 로
/// Device 여부를 판정한다.
///
/// # Safety
/// `Mmu<Initialized>::activate` 완료 후 MMU 활성 상태에서만 호출해야 함
///
/// # Errors
/// 변환 실패(PAR_EL1.F set) 시 `SelfTestFault`, Device attribute 아니면(ATTR != 0x04) `SelfTestAttr`
pub unsafe fn self_test(uart_va: u64) -> Result<(), MmuError> {
    let par: u64;
    // SAFETY AT S1E1R 은 변환만 수행하며 ISB 로 PAR_EL1 갱신 가시화 후 read
    unsafe {
        core::arch::asm!(
            "at s1e1r, {va}",
            "isb",
            "mrs {par}, par_el1",
            va = in(reg) uart_va,
            par = out(reg) par,
            options(nostack, preserves_flags),
        );
    }
    // PAR_EL1.F (bit0) 1 이면 stage1 변환 실패
    if par & 1 != 0 {
        return Err(MmuError::SelfTestFault);
    }
    // PAR_EL1.ATTR (bits[63:56]) 이 Device-nGnRE(MAIR Attr1 0x04)가 아니면 오매핑
    if (par >> 56) & 0xFF != MAIR_ATTR1_DEVICE_NGNRE {
        return Err(MmuError::SelfTestAttr);
    }
    Ok(())
}

/// MMU 활성 후처리 self_test -> console 재배치 -> MMU=ON 마커 (HAL post_mmu_enable).
///
/// self_test 실패는 fail-stop(halt)으로 처리하여 오매핑 상태 진행을 차단한다. 통과 시
/// 콘솔 base 를 커널 선형 매핑 VA(linear_base + UART_PHYS)로 갱신하고 boot proof 마커
/// `MMU=ON` 을 release 포함 무조건 emit 한다.
///
/// # Safety
/// `Mmu<Initialized>::activate` 완료 직후 1 회만 호출해야 함
pub unsafe fn post_mmu_enable() {
    // SAFETY: MMU 활성 상태, identity UART VA 로 self_test 후 선형 VA 로 콘솔 재배치
    unsafe {
        // self_test 실패 시 fail-stop, 오매핑 진행 차단
        if self_test(UART_PHYS).is_err() {
            super::cpu::halt_loop();
        }
        // 커널 선형 매핑 VA 로 콘솔 base 갱신 (TTBR1 UART Device 매핑)
        super::console::update_base((linear_base() + UART_PHYS) as *mut u8);
        // MMU=ON boot proof 마커 (release 포함 무조건 emit)
        super::console::write_bytes(b"MMU=ON\r\n");
    }
}
