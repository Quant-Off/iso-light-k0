//! x86_64 4단계 페이지 테이블 및 KASLR 직접 선형 매핑을 수행하는 모듈입니다.
//!
//! 가시성 격리(Visibility Isolation):
//! `PHYS_MAP_OFFSET` 과 `LINEAR_MAP_ACTIVE` 는 `static mut` 이지만 `pub` 가
//! 아니므로 외부 모듈에서 직접 접근할 수 없으며, `phys_to_linear_virt()` 도
//! 비공개 함수로 mmu.rs 내부에서만 호출됩니다. 외부 코드는
//! `Mmu<Initialized>::phys_to_virt*()` 를 통해서만 물리/가상 변환에 접근할 수
//! 있고, 컴파일 타임에 이 경계가 강제됩니다.
//!
//! 직접 선형 매핑(Direct Linear Map):
//!   phys [0, highest) -> virt [PHYS_MAP_OFFSET, PHYS_MAP_OFFSET + highest).
//!   2 MiB 대용량 페이지를 사용하여 PML4 오버헤드를 1/512 로 줄임.
//!
//! KASLR:
//!   PHYS_MAP_OFFSET 은 부트로더가 Multiboot2 커스텀 태그로 전달.
//!   커널 내부에 하드코딩된 상수가 없으며, 기본값은 mmu.rs 내부에만 존재.

use core::marker::PhantomData;

//
// 공개 상수
//

pub const PAGE_SIZE: usize = 4096;
pub const SIZE_2MIB: u64 = 2 * 1024 * 1024;

/// 커널 세그먼트 VMA 기저 주소 (linker.ld의 KERNEL_VMA_BASE와 동기화 필수).
///
/// x86_64 kernel code model 기준:
///   VMA = phys + KERNEL_VMA_BASE
///   phys = VMA - KERNEL_VMA_BASE
///
/// CR3에는 물리 주소가 필요하므로 `pml4_phys_addr()`가 이 값을 사용해 변환함.
pub const KERNEL_VMA_BASE: u64 = 0xFFFF_FFFF_8000_0000;

//
// 내부 상수
//

const TABLE_ENTRIES: usize = 512;
/// bits[51:12]: 4 KiB 페이지 물리 주소 마스크 (Intel SDM Vol.3A Table 4-20)
const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// bits[51:21]: 2 MiB 대용량 페이지 물리 주소 마스크 (Intel SDM Vol.3A Table 4-17)
const HUGE_PHYS_MASK: u64 = 0x000F_FFFF_FFE0_0000;
/// KASLR 태그가 없을 때의 기본 직접 매핑 오프셋. mmu.rs 외부에 노출하지 않음.
const DEFAULT_PHYS_MAP_OFFSET: u64 = 0xFFFF_8000_0000_0000;

//
// KASLR 비공개 상태
//
// 이 두 static은 `pub`이 없으므로 mmu 모듈 외부에서 직접 접근 불가
// Rust 가시성 시스템이 컴파일 타임에 접근을 차단함

/// 직접 선형 매핑의 시작 가상 주소 (= 물리 0번지의 커널 가상 주소).
/// Mmu::initialize()에서 단 한 번 설정되고 이후 불변으로 취급함.
static mut PHYS_MAP_OFFSET: u64 = 0;

/// CR3에 새 PML4가 로드되어 선형 매핑 영역이 실제로 접근 가능한 상태인지 추적.
/// activate() 직후 true로 설정됨.
static mut LINEAR_MAP_ACTIVE: bool = false;

/// 물리 주소를 직접 선형 매핑 영역의 가상 주소로 변환.
///
/// 이 함수는 `pub`이 아니므로 mmu.rs 내부에서만 호출 가능.
/// 모듈 외부에서 PHYS_MAP_OFFSET에 임의로 접근하거나 물리 포인터를 직접
/// 구성하는 것은 컴파일 타임에 차단된다.
#[inline]
fn phys_to_linear_virt(phys: u64) -> *mut u8 {
    // SAFETY: PHYS_MAP_OFFSET은 initialize()에서 한 번만 설정됨
    //         LINEAR_MAP_ACTIVE가 true인 경우에만 반환된 포인터가 유효함
    (unsafe { *(&raw const PHYS_MAP_OFFSET) } + phys) as *mut u8
}

//
// 페이지 테이블 플래그
//

/// x86_64 페이지 테이블 엔트리 플래그 (Intel SDM Vol.3A Table 4-11)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct PageTableFlags(u64);

impl PageTableFlags {
    pub const PRESENT: Self = Self(1 << 0);
    pub const WRITABLE: Self = Self(1 << 1);
    pub const USER_ACCESSIBLE: Self = Self(1 << 2);
    pub const WRITE_THROUGH: Self = Self(1 << 3);
    pub const NO_CACHE: Self = Self(1 << 4);
    pub const ACCESSED: Self = Self(1 << 5);
    pub const DIRTY: Self = Self(1 << 6);
    /// PD/PDPT 레벨에서 2 MiB/1 GiB 대용량 페이지 활성화
    pub const HUGE_PAGE: Self = Self(1 << 7);
    pub const GLOBAL: Self = Self(1 << 8);
    pub const NO_EXECUTE: Self = Self(1 << 63);

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
// 에러 타입
//

#[derive(Debug)]
pub enum MmuError {
    /// W^X 정책 위반: WRITABLE + 실행 가능을 동시에 요청
    WxPolicyViolation,
    /// 이미 매핑된 주소에 재매핑 시도
    AlreadyMapped,
    /// 물리 프레임 할당 실패 (메모리 부족)
    FrameAllocFailed,
    /// 주소가 요구 정렬 경계를 만족하지 않음
    UnalignedAddress,
}

//
// 페이지 테이블 엔트리
//

/// 8-byte 페이지 테이블 엔트리 (4 KiB 및 2 MiB 페이지 공용)
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub const fn unused() -> Self {
        Self(0)
    }

    #[inline]
    pub fn is_present(self) -> bool {
        self.flags().contains(PageTableFlags::PRESENT)
    }

    #[inline]
    pub fn flags(self) -> PageTableFlags {
        PageTableFlags(self.0 & !PHYS_ADDR_MASK)
    }

    #[inline]
    pub fn phys_addr(self) -> u64 {
        self.0 & PHYS_ADDR_MASK
    }

    /// 4 KiB 페이지 엔트리 설정. W^X: WRITABLE 시 NO_EXECUTE 자동 강제.
    pub fn set(&mut self, phys_addr: u64, mut flags: PageTableFlags) -> Result<(), MmuError> {
        if phys_addr & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(MmuError::UnalignedAddress);
        }
        if flags.contains(PageTableFlags::WRITABLE) {
            flags = flags.union(PageTableFlags::NO_EXECUTE);
        }
        self.0 = (phys_addr & PHYS_ADDR_MASK) | flags.bits();
        Ok(())
    }

    /// 2 MiB 대용량 페이지 엔트리 설정 (PD 레벨 전용).
    /// 물리 주소는 2 MiB 정렬 필수. W^X: WRITABLE 시 NO_EXECUTE 자동 강제.
    pub fn set_huge(&mut self, phys_addr: u64, mut flags: PageTableFlags) -> Result<(), MmuError> {
        if phys_addr & (SIZE_2MIB - 1) != 0 {
            return Err(MmuError::UnalignedAddress);
        }
        if flags.contains(PageTableFlags::WRITABLE) {
            flags = flags.union(PageTableFlags::NO_EXECUTE);
        }
        self.0 = (phys_addr & HUGE_PHYS_MASK) | flags.bits();
        Ok(())
    }
}

//
// 페이지 테이블
//

/// 4단계 페이지 테이블의 단일 레벨 (PML4 / PDPT / PD / PT).
/// 512 엔트리 × 8 bytes = 4 KiB, 페이지 정렬 필수.
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; TABLE_ENTRIES],
}

impl PageTable {
    pub const fn empty() -> Self {
        Self {
            entries: [PageTableEntry::unused(); TABLE_ENTRIES],
        }
    }

    /// 가상 주소에서 해당 레벨의 9-bit 인덱스 추출 (level: 1..=4).
    ///
    /// - L4 (PML4):  virt[47:39]
    /// - L3 (PDPT):  virt[38:30]
    /// - L2 (PD):    virt[29:21]
    /// - L1 (PT):    virt[20:12]
    #[inline]
    pub fn index(virt_addr: u64, level: u8) -> usize {
        let shift = 12 + (level - 1) as u64 * 9;
        ((virt_addr >> shift) & 0x1FF) as usize
    }
}

//
// 프로세스 주소 공간
//

/// 프로세스별 독립적인 가상 주소 공간 (PML4 루트 테이블 소유).
///
/// 페이지 매핑을 담당하는 순수 데이터 구조체.
/// 하드웨어 활성화(CR3 로드)는 `Mmu<Initialized>::activate()`가 전담함.
///
/// # 격리 모델
/// - 커널 주소 공간:   PML4[256..511] (모든 프로세스가 공유하는 상위 절반)
/// - 사용자 주소 공간: PML4[0..255]   (프로세스마다 고유한 하위 절반)
#[repr(C, align(4096))]
pub struct AddressSpace {
    pml4: PageTable,
}

#[allow(clippy::new_without_default)]
impl AddressSpace {
    pub const fn new() -> Self {
        Self {
            pml4: PageTable::empty(),
        }
    }

    /// PML4 물리 주소 반환 (CR3에 로드할 값).
    ///
    /// Higher-Half 재배치 후 `KERNEL_ADDR_SPACE`는 `.bss` 섹션에 위치하므로
    /// VMA = phys + KERNEL_VMA_BASE 관계가 성립함. CR3은 물리 주소를 요구하므로
    /// VMA 범위에 있는 경우 KERNEL_VMA_BASE를 빼서 물리 주소로 변환함.
    ///
    /// 할당자(alloc_frame)로 생성된 사용자 공간 `AddressSpace`는
    /// 물리 주소가 직접 사용되므로(< KERNEL_VMA_BASE) 그대로 반환함.
    pub fn pml4_phys_addr(&self) -> u64 {
        let vma = &self.pml4 as *const PageTable as u64;
        if vma >= KERNEL_VMA_BASE {
            // 커널 .bss에 정적 할당된 경우: VMA -> 물리 주소 변환
            vma - KERNEL_VMA_BASE
        } else {
            // 할당자 프레임(물리 주소 직접 사용): 변환 불필요
            vma
        }
    }

    /// 4 KiB 페이지 매핑 (커널 텍스트/데이터 세그먼트용).
    ///
    /// W^X: WRITABLE 플래그 없이 PRESENT만 설정하면 실행 가능(코드).
    ///      WRITABLE을 설정하면 NO_EXECUTE 없이는 WxPolicyViolation을 반환.
    ///
    /// # 전제 조건
    /// identity mapping(phys == virt) 또는 `Mmu<Initialized>::build_linear_map()`
    /// 완료 후 LINEAR_MAP_ACTIVE 상태에서 호출해야 함.
    pub fn map_page(
        &mut self,
        virt_addr: u64,
        phys_addr: u64,
        flags: PageTableFlags,
    ) -> Result<(), MmuError> {
        if virt_addr & (PAGE_SIZE as u64 - 1) != 0 || phys_addr & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(MmuError::UnalignedAddress);
        }
        if flags.contains(PageTableFlags::WRITABLE) && !flags.contains(PageTableFlags::NO_EXECUTE) {
            return Err(MmuError::WxPolicyViolation);
        }

        // SAFETY: self.pml4는 자신이 소유한 유효한 페이지 테이블
        let pml4_ptr = &mut self.pml4 as *mut PageTable;
        let pdpt = unsafe { alloc_or_get_table(pml4_ptr, PageTable::index(virt_addr, 4))? };
        let pd = unsafe { alloc_or_get_table(pdpt, PageTable::index(virt_addr, 3))? };
        let pt = unsafe { alloc_or_get_table(pd, PageTable::index(virt_addr, 2))? };

        let leaf = unsafe { &mut (*pt).entries[PageTable::index(virt_addr, 1)] };
        if leaf.is_present() {
            return Err(MmuError::AlreadyMapped);
        }
        leaf.set(phys_addr, flags.union(PageTableFlags::PRESENT))
    }

    /// 2 MiB 대용량 페이지 매핑 (직접 선형 매핑 구축 전용).
    ///
    /// PD 레벨에서 HUGE_PAGE 플래그를 설정하여 PT 레벨을 생략함.
    /// 4 KiB 페이지 대비 페이지 테이블 엔트리를 512배 절감하여
    /// 전체 물리 메모리 매핑의 오버헤드를 최소화함.
    ///
    /// W^X: WRITABLE 설정 시 NO_EXECUTE 없이는 WxPolicyViolation 반환.
    pub fn map_2mib_page(
        &mut self,
        virt_addr: u64,
        phys_addr: u64,
        flags: PageTableFlags,
    ) -> Result<(), MmuError> {
        if virt_addr & (SIZE_2MIB - 1) != 0 || phys_addr & (SIZE_2MIB - 1) != 0 {
            return Err(MmuError::UnalignedAddress);
        }
        if flags.contains(PageTableFlags::WRITABLE) && !flags.contains(PageTableFlags::NO_EXECUTE) {
            return Err(MmuError::WxPolicyViolation);
        }

        // 3단계 워크만 수행: PML4 -> PDPT -> PD (PD 엔트리에서 HUGE_PAGE로 종결)
        let pml4_ptr = &mut self.pml4 as *mut PageTable;
        let pdpt = unsafe { alloc_or_get_table(pml4_ptr, PageTable::index(virt_addr, 4))? };
        let pd = unsafe { alloc_or_get_table(pdpt, PageTable::index(virt_addr, 3))? };

        let pd_entry = unsafe { &mut (*pd).entries[PageTable::index(virt_addr, 2)] };
        if pd_entry.is_present() {
            return Err(MmuError::AlreadyMapped);
        }

        // PRESENT와 HUGE_PAGE를 항상 추가하여 2 MiB 직접 매핑 엔트리 완성
        pd_entry.set_huge(
            phys_addr,
            flags
                .union(PageTableFlags::PRESENT)
                .union(PageTableFlags::HUGE_PAGE),
        )
    }
}

//
// 페이지 테이블 워크 헬퍼
//

/// 지정 인덱스의 다음 레벨 페이지 테이블 포인터 반환.
/// 엔트리가 없으면 새 물리 프레임을 할당하여 초기화함.
///
/// # Safety
/// - `table`은 유효한 `PageTable`에 대한 포인터여야 함.
/// - LINEAR_MAP_ACTIVE == false: identity mapping(phys == virt) 가정.
/// - LINEAR_MAP_ACTIVE == true:  선형 매핑 영역을 통해 접근.
unsafe fn alloc_or_get_table(
    table: *mut PageTable,
    index: usize,
) -> Result<*mut PageTable, MmuError> {
    // SAFETY: 호출자가 table의 유효성을 보장
    let entry = unsafe { &mut (*table).entries[index] };
    let linear_active = unsafe { *(&raw const LINEAR_MAP_ACTIVE) };

    if entry.is_present() {
        // 대용량 페이지(HUGE_PAGE) 리프 엔트리 감지
        // HUGE_PAGE 플래그가 설정된 엔트리는 2 MiB/1 GiB 대용량 페이지의
        // 리프(leaf) 엔트리임. 하위 페이지 테이블을 가리키는 포인터가 아니므로,
        // phys_addr()를 *mut PageTable로 해석하면 잘못된(null 포함) 포인터를
        // 역참조하는 UB가 발생함
        // 따라서 AlreadyMapped를 반환하여 호출자(map_page/map_2mib_page)가
        // "이미 다른 크기로 매핑됨"을 인지하도록 함
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            return Err(MmuError::AlreadyMapped);
        }
        let phys = entry.phys_addr();
        let ptr = if linear_active {
            phys_to_linear_virt(phys) // 선형 매핑 활성 후
        } else {
            phys as *mut u8 // 부트스트랩: identity mapping
        };
        Ok(ptr as *mut PageTable)
    } else {
        // 새 페이지 테이블 프레임 할당
        // SAFETY: 부팅 초기 단일 코어 접근
        let frame = unsafe { crate::allocator::alloc_frame() }.ok_or(MmuError::FrameAllocFailed)?;

        let new_phys = frame.addr();
        let new_ptr = if linear_active {
            phys_to_linear_virt(new_phys) as *mut PageTable
        } else {
            new_phys as *mut PageTable
        };

        // 새 페이지 테이블 프레임을 volatile write로 0 소거
        // `write(PageTable::empty())`는 컴파일러의 dead store elimination으로
        // 제거될 수 있으므로 elib-k0-nt의 `secure_zero`로 소거를 보장함
        // SAFETY: new_ptr은 PAGE_SIZE 바이트의 유효한 쓰기 가능 프레임을 가리킴
        unsafe {
            zeroize::volatile::secure_zero(new_ptr as *mut u8, PAGE_SIZE);
        }

        // 중간 레벨 엔트리: PRESENT | WRITABLE | NO_EXECUTE
        let mid_flags = PageTableFlags::PRESENT
            .union(PageTableFlags::WRITABLE)
            .union(PageTableFlags::NO_EXECUTE);
        entry.set(new_phys, mid_flags)?;

        Ok(new_ptr)
    }
}

//
// Typestate MMU
//

pub struct Uninitialized;
pub struct Initialized;

/// 타입 수준 상태 머신으로 MMU 초기화 순서를 컴파일 타임에 강제함.
///
/// `Mmu<Uninitialized>` 에서 `initialize(offset)` 을 호출하면
/// `Mmu<Initialized>` 로 전이되며, 그 상태에서만 `build_linear_map()`,
/// `phys_to_virt*()`, `activate()` 가 호출 가능함.
///
/// `Mmu<Initialized>` 없이는 물리/가상 주소 변환 및 주소 공간 전환이
/// 컴파일 타임에 차단됨.
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

    /// KASLR 오프셋을 설정하고 `Mmu<Initialized>`로 상태 전환.
    ///
    /// `kaslr_offset`은 부트로더가 Multiboot2 커스텀 태그로 전달한 값.
    /// `None`이면 mmu.rs 내부의 기본값(`DEFAULT_PHYS_MAP_OFFSET`)을 사용함.
    ///
    /// 오프셋은 2 MiB 정렬로 강제 보정되어 `PHYS_MAP_OFFSET`에 저장됨.
    /// 이 값은 이후 `phys_to_linear_virt()`를 통해서만 접근 가능.
    pub fn initialize(self, kaslr_offset: Option<u64>) -> Mmu<Initialized> {
        let raw_offset = kaslr_offset.unwrap_or(DEFAULT_PHYS_MAP_OFFSET);
        // 2 MiB 정렬 강제: 대용량 페이지 매핑 요건 충족
        let aligned_offset = raw_offset & !(SIZE_2MIB - 1);

        // SAFETY: 부팅 초기 단일 코어, 이 함수는 한 번만 호출됨
        unsafe {
            *(&raw mut PHYS_MAP_OFFSET) = aligned_offset;
        }

        // TODO(x86_64): IA32_EFER.NXE 활성화, IOMMU/VT-d 설정
        // TODO(aarch64): TTBR0_EL1/TTBR1_EL1 설정, SMMU 활성화
        Mmu {
            _marker: PhantomData,
        }
    }
}

impl Mmu<Initialized> {
    /// 지정한 주소 공간을 현재 CPU 코어에 활성화함 (CR3 재로드).
    ///
    /// CR3 로드 직후 `LINEAR_MAP_ACTIVE = true`를 설정하여 이후
    /// `alloc_or_get_table`이 선형 매핑 영역을 통해 테이블에 접근하도록 전환함.
    ///
    /// # Safety
    /// - `space`의 PML4가 유효한 물리 주소에 위치해야 함.
    /// - 직접 선형 매핑(`build_linear_map`)과 커널 매핑이 완료된 이후에 호출해야 함.
    /// - 커널 PML4[256..511] 범위에 커널 주소 공간이 매핑되어야 인터럽트 진입이 안전함.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn activate(&self, space: &AddressSpace) {
        let pml4_phys = space.pml4_phys_addr();
        // SAFETY: 호출자가 PML4 유효성과 커널 매핑 포함을 보장함
        //         CR3 쓰기 후 TLB 전체 플러시. 이후 LINEAR_MAP_ACTIVE = true
        unsafe {
            core::arch::asm!(
                "mov cr3, {pml4}",
                pml4 = in(reg) pml4_phys,
                options(nostack, preserves_flags),
            );
            // CR3 로드 완료: 선형 매핑 영역이 이제 접근 가능
            *(&raw mut LINEAR_MAP_ACTIVE) = true;
        }
    }

    /// 물리 주소를 직접 선형 매핑 영역의 읽기 전용 포인터로 변환.
    ///
    /// `Mmu<Initialized>` 인스턴스 없이는 호출 불가하므로, 물리 메모리 직접 접근 경로를
    /// 초기화된 MMU 컨텍스트로 제한함.
    ///
    /// # Safety
    /// `activate()` 호출 이후에만 반환된 포인터가 유효함.
    #[inline]
    pub unsafe fn phys_to_virt<T>(&self, phys: u64) -> *const T {
        phys_to_linear_virt(phys) as *const T
    }

    /// 물리 주소를 직접 선형 매핑 영역의 가변 포인터로 변환.
    ///
    /// # Safety
    /// `activate()` 호출 이후, 해당 물리 메모리 영역에 대한 단독 접근이
    /// 보장된 상태에서만 사용해야 함.
    #[inline]
    pub unsafe fn phys_to_virt_mut<T>(&self, phys: u64) -> *mut T {
        phys_to_linear_virt(phys) as *mut T
    }

    /// 직접 선형 매핑 영역을 PML4에 구축함.
    ///
    /// 물리 주소 범위 `[0, highest_phys_addr)` 전체를
    /// `[PHYS_MAP_OFFSET, PHYS_MAP_OFFSET + highest_phys_addr)` 에 2 MiB 페이지로 매핑.
    ///
    /// 이 함수는 `PHYS_MAP_OFFSET`을 직접 읽는 유일한 공개 경로이며,
    /// 오프셋 값 자체는 외부에 노출하지 않음.
    ///
    /// # 매핑 속성
    /// PRESENT | WRITABLE | NO_EXECUTE | HUGE_PAGE
    /// (물리 메모리는 임의 데이터를 포함하므로 실행 불가로 설정)
    pub fn build_linear_map(
        &self,
        space: &mut AddressSpace,
        highest_phys_addr: u64,
    ) -> Result<(), MmuError> {
        // PHYS_MAP_OFFSET 읽기: mmu.rs 내부이므로 허용
        let offset = unsafe { *(&raw const PHYS_MAP_OFFSET) };

        // 비트맵 할당자가 관리하는 물리 메모리 상한 (4 GiB)
        // highest_phys_addr가 매우 클 경우(BIOS Reserved 영역 포함):
        //   (1) highest_phys_addr + SIZE_2MIB - 1 이 u64::MAX를 초과 (Debug 빌드 panic)
        //   (2) page_count가 천문학적 수치가 되어 무한에 가까운 루프 실행
        // 할당자 비트맵 커버리지(4 GiB)로 상한을 제한하여 두 문제를 동시 해결함
        const MAX_MAPPABLE_PHYS: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
        let highest_phys_addr = highest_phys_addr.min(MAX_MAPPABLE_PHYS);

        // 2 MiB 단위로 올림하여 마지막 프레임까지 포함
        // highest_phys_addr ≤ 4 GiB이므로 saturating_add 불필요하지만
        // 방어적으로 적용하여 미래의 MAX_MAPPABLE_PHYS 변경에 안전하게 대응
        let page_count = highest_phys_addr.saturating_add(SIZE_2MIB - 1) / SIZE_2MIB;

        let map_flags = PageTableFlags::PRESENT
            .union(PageTableFlags::WRITABLE)
            .union(PageTableFlags::NO_EXECUTE);

        for i in 0..page_count {
            let phys_base = i * SIZE_2MIB;
            let virt_base = offset + phys_base;
            space.map_2mib_page(virt_base, phys_base, map_flags)?;
        }

        Ok(())
    }
}
