//! 정적 프로세스 슬롯 풀과 Ring 3 진입 메커니즘을 구현한 모듈입니다.
//!
//! # 설계 원칙
//!   - `alloc` 절대 미사용 — `MAX_PROCESSES` 개의 정적 `Option<Process>` 슬롯을
//!     사용. 슬롯 할당 실패는 `ProcessError::SlotsFull`.
//!   - 사용자 주소 공간은 별도 PML4 프레임 한 개를 `allocator::alloc_frame()`
//!     으로 받아 0-소거 후 커널 PML4 의 상위 절반을 inherit (커널 매핑 공유).
//!   - 사용자 매핑은 `mmu::AddressSpace::map_user_page()` 로 항상 `USER_ACCESSIBLE`
//!     플래그 + W^X 가 강제됨.
//!   - Ring 3 진입은 `enter_ring3()` 에서 단일 atomic asm 블록으로 수행:
//!     `swapgs` → iretq 스택 frame 구축 → `iretq`. 사이에 어떤 RFLAGS / GS
//!     관찰 윈도우도 두지 않음.
//!
//! # 보안 모델
//!   - 사용자 PML4 는 커널 매핑 영역(PML4[256..512]) 을 `inherit_kernel_mappings`
//!     로 공유함. 이로써 syscall stub / dispatch / TSS / per-CPU 영역이 사용자
//!     PML4 활성 상태에서도 접근 가능. 사용자 영역(PML4[0..256]) 은 격리됨.
//!   - SMEP/SMAP 가 활성이므로 커널이 사용자 페이지에서 실행/접근 불가. 그러나
//!     반대 방향(사용자가 커널 페이지 접근)은 페이지 테이블의 USER_ACCESSIBLE
//!     플래그 부재로 자동 차단됨.
//!   - 사용자 RFLAGS 는 항상 `0x202` (IF=1 + reserved 1 비트) 로 강제 — 사용자
//!     가 IOPL 상승, 단일 스텝 트랩 등을 임의로 설정할 수 없음.
//!
//! # Authors
//! Q. T. Felix

use crate::boot::{USER_CS, USER_DS};
use crate::elf::{self, Elf64Image, ProgramHeader};
use crate::mmu::{self, AddressSpace, PAGE_SIZE, PageTableFlags};
use crate::stack;

//
// 슬롯 / 한도 상수
//

/// 정적 프로세스 슬롯 수. `alloc` 미사용 정책에 따라 컴파일 타임 고정.
pub const MAX_PROCESSES: usize = 4;

/// 사용자 가상 주소의 표준 진입점 베이스 (Linux x86_64 default + 1MiB 정렬).
/// ELF 로더가 별도 베이스를 지정하지 않을 때 사용함.
pub const DEFAULT_USER_ENTRY: u64 = 0x0000_0000_0040_0000;

/// 사용자 스택 최상단 (canonical lower half 의 끝 직전, 16-byte 정렬).
/// 256 KiB 의 사용자 스택을 매핑하면 본체는 [TOP - 256KiB, TOP) 범위.
pub const DEFAULT_USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;

/// 사용자 스택 본체 크기.
pub const DEFAULT_USER_STACK_SIZE: usize = 64 * 1024;

//
// 프로세스 식별자 / 상태
//

/// 프로세스 핸들. 슬롯 인덱스 + 단조 증가 generation 으로 stale 핸들 사용을
/// 검출함 (Phase B 1차에는 generation 미사용, 슬롯 인덱스 단독으로 충분).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessId(pub u8);

/// 프로세스 생명주기.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessState {
    /// 메모리에 적재되어 진입 대기 중
    Loaded,
    /// 현재 CPU 코어에서 실행 중 (Phase B 단일 코어 가정)
    Running,
    /// `sys_exit` 또는 fault 로 종료
    Exited,
}

/// 프로세스 슬롯 메타데이터. PML4 자체는 별도 프레임(`pml4_phys`) 에 위치.
pub struct Process {
    pub id: ProcessId,
    pub state: ProcessState,
    /// 사용자 PML4 의 물리 주소 (CR3 적재 값)
    pub pml4_phys: u64,
    /// 사용자 진입 RIP
    pub entry_rip: u64,
    /// 사용자 RSP (스택 최상단, 16-byte 정렬)
    pub user_rsp: u64,
    /// 사용자 스택 매핑 범위 [bottom, top) — 디버깅 / 정리에 사용
    pub user_stack_range: (u64, u64),
}

//
// 에러 타입
//

#[derive(Debug, PartialEq, Eq)]
pub enum ProcessError {
    /// 정적 슬롯 풀 소진
    SlotsFull,
    /// 매핑 / 페이지 할당 실패 (`MmuError` 매핑)
    Mmu(mmu::MmuError),
    /// 사용자 주소 공간 PML4 프레임 할당 실패
    PmAllocFailed,
    /// 사용자 영역이 아닌 주소 / 정렬 오류
    BadAddress,
    /// ELF 파싱 실패
    Elf(elf::ElfError),
}

impl From<elf::ElfError> for ProcessError {
    fn from(e: elf::ElfError) -> Self {
        ProcessError::Elf(e)
    }
}

impl From<mmu::MmuError> for ProcessError {
    fn from(e: mmu::MmuError) -> Self {
        ProcessError::Mmu(e)
    }
}

//
// 정적 슬롯 풀
//

// SAFETY: 부팅 초기 단일 코어, 본 모듈의 공개 API 만 슬롯 풀에 접근하며
//         내부적으로 직렬화됨.
static mut PROCESSES: [Option<Process>; MAX_PROCESSES] = [const { None }; MAX_PROCESSES];

/// 첫 번째 빈 슬롯을 찾아 인덱스를 반환.
fn find_free_slot() -> Option<usize> {
    // SAFETY: 단일 코어 직렬 접근
    let table = unsafe { &*(&raw const PROCESSES) };
    for (i, slot) in table.iter().enumerate() {
        if slot.is_none() {
            return Some(i);
        }
    }
    None
}

/// 슬롯에 프로세스를 기록하고 핸들 반환.
///
/// # Safety
/// `find_free_slot()` 으로 받은 비어 있는 슬롯 인덱스만 전달.
unsafe fn put_slot(idx: usize, p: Process) -> ProcessId {
    let id = p.id;
    // SAFETY: 호출자가 빈 슬롯을 보장함
    unsafe {
        (*(&raw mut PROCESSES))[idx] = Some(p);
    }
    id
}

/// 슬롯 인덱스로 프로세스 참조를 가져옴.
pub fn get(id: ProcessId) -> Option<&'static Process> {
    let idx = id.0 as usize;
    if idx >= MAX_PROCESSES {
        return None;
    }
    // SAFETY: 단일 코어, 슬롯은 spawn 후 변경되지 않음 (Phase B 단순화 가정)
    unsafe { (*(&raw const PROCESSES))[idx].as_ref() }
}

//
// 사용자 주소 공간 빌더
//

/// 새 사용자 PML4 프레임을 할당하고 커널 매핑을 inherit 함.
///
/// 반환되는 `*mut AddressSpace` 는 *물리 주소가 동시에 가상 주소* 인 직접
/// 매핑 영역 (KERNEL_VMA_BASE 미적용) 의 포인터. 호출자는 같은 프레임에
/// 사용자 페이지 매핑을 추가한 뒤 `phys_addr` 를 사용하여 CR3 에 적재함.
///
/// # Safety
/// - `kernel_space` 가 유효한 커널 PML4 (build_linear_map + 커널 세그먼트
///   매핑 완료) 여야 함.
/// - 부팅 초기 또는 외부 동기화가 보장된 단일 코어 환경에서 호출.
unsafe fn alloc_user_address_space(
    kernel_space: &AddressSpace,
) -> Result<*mut AddressSpace, ProcessError> {
    // SAFETY: 부팅 초기 단일 코어, 프레임 alloc
    let frame = unsafe { crate::allocator::alloc_frame() }.ok_or(ProcessError::PmAllocFailed)?;
    let phys = frame.addr();

    // 부팅 초기엔 LINEAR_MAP_ACTIVE 이전이라 phys==virt(identity) 가정.
    // activate() 후에는 mmu::Initialized 가 phys -> virt 로 변환해야 하지만,
    // 본 함수는 activate 전에만 호출됨 (Phase B 단순화).
    let space_ptr = phys as *mut AddressSpace;

    // SAFETY: PML4 프레임 4 KiB 를 0-소거 후, AddressSpace::new() 동등의
    //         초기 상태로 둠. 그 다음 커널 매핑을 inherit + boot_stack 영역
    //         identity 매핑(저주소).
    unsafe {
        zeroize::volatile::secure_zero(space_ptr as *mut u8, PAGE_SIZE);
        (*space_ptr).inherit_kernel_mappings(kernel_space);
        map_boot_stack_identity(&mut *space_ptr)?;
    }

    Ok(space_ptr)
}

/// 부트 스택(`.boot_bss`, 저주소 = phys = vma) 영역을 사용자 PML4 에 identity
/// 매핑(USER_ACCESSIBLE 없음, RW+NX) 으로 추가함. CR3 가 사용자 PML4 로 전환된
/// 상태에서도 RSP0 가 가리키는 부트 스택에 접근할 수 있도록 보장.
///
/// # Safety
/// `space` 는 alloc_user_address_space 가 갓 만든 사용자 PML4. 호출 시점에
/// 부트 페이지 테이블이 활성(중간 테이블 identity-mapped) 이어야 함.
unsafe fn map_boot_stack_identity(space: &mut AddressSpace) -> Result<(), ProcessError> {
    let (bottom, top) = stack::boot_stack_range();
    let pages = ((top - bottom) as usize) / PAGE_SIZE;
    let flags = PageTableFlags::PRESENT
        .union(PageTableFlags::WRITABLE)
        .union(PageTableFlags::NO_EXECUTE);
    for i in 0..pages {
        let va = bottom + (i as u64) * (PAGE_SIZE as u64);
        space.map_page(va, va, flags)?;
    }
    Ok(())
}

/// 사용자 코드/데이터 페이지를 [base, base+pages*4KiB) 영역에 매핑함.
/// 코드 페이지(`writable = false`) 는 R+X, 데이터 페이지(`writable = true`)
/// 는 RW+NX. 각 페이지에 새 물리 프레임을 할당하며, 페이지 본체는 0-소거됨.
///
/// # Safety
/// `space` 는 alloc_user_address_space 로 반환된 사용자 PML4 를 가리켜야 함.
unsafe fn map_user_region(
    space: &mut AddressSpace,
    base_va: u64,
    pages: usize,
    writable: bool,
) -> Result<(), ProcessError> {
    if !mmu::is_user_va(base_va) {
        return Err(ProcessError::BadAddress);
    }
    for i in 0..pages {
        let frame =
            unsafe { crate::allocator::alloc_frame() }.ok_or(ProcessError::PmAllocFailed)?;
        let phys = frame.addr();
        // SAFETY: 새로 할당된 프레임을 0-소거 (information leak 방지)
        unsafe {
            zeroize::volatile::secure_zero(phys as *mut u8, PAGE_SIZE);
        }
        let va = base_va + (i as u64) * (PAGE_SIZE as u64);
        space.map_user_page(va, phys, writable)?;
    }
    Ok(())
}

/// 사용자 페이로드(코드+데이터 raw 바이트) 를 사용자 주소 공간에 적재함.
///
/// `payload` 는 base_va 부터 시작하는 raw 메모리 이미지. 페이지 단위로
/// 매핑하면서 직접 선형 매핑 영역(identity 가정) 을 통해 페이지 본체에
/// 페이로드를 복사함. ELF 로더가 등장하기 전까지의 임시 경로.
///
/// # Safety
/// `space` 는 사용자 PML4. `payload` 는 유효한 슬라이스. 호출 시점에
/// 부트 페이지 테이블이 활성화되어 있고 (LINEAR_MAP_ACTIVE = false),
/// 새 프레임에 대한 identity write 가 가능해야 함.
pub unsafe fn load_flat_payload(
    space: &mut AddressSpace,
    base_va: u64,
    payload: &[u8],
    writable: bool,
) -> Result<(), ProcessError> {
    if !mmu::is_user_va(base_va) {
        return Err(ProcessError::BadAddress);
    }
    let total_bytes = payload.len();
    let pages = total_bytes.div_ceil(PAGE_SIZE);
    if pages == 0 {
        return Err(ProcessError::BadAddress);
    }

    // 1. 페이지 매핑 + 0-소거
    unsafe {
        map_user_region(space, base_va, pages, writable)?;
    }

    // 2. 매핑된 각 페이지에 페이로드 복사 (identity-mapped 가정)
    //    페이지 테이블에서 phys 를 다시 읽어와 그 phys 주소를 직접 식별자로 사용.
    let mut copied = 0usize;
    for i in 0..pages {
        let va = base_va + (i as u64) * (PAGE_SIZE as u64);
        // SAFETY: 부트 페이지 테이블 활성, 중간 테이블 identity-mapped
        let phys = unsafe { space.walk_to_phys(va) }.ok_or(ProcessError::BadAddress)?;
        let chunk = (total_bytes - copied).min(PAGE_SIZE);
        // SAFETY: phys 는 방금 allocator 로 받은 4 KiB 프레임의 물리 주소.
        //         부트 PML4 는 4 GiB identity map 을 보유하므로 phys < 4 GiB
        //         범위에서 직접 쓰기 가능.
        unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr().add(copied), phys as *mut u8, chunk);
        }
        copied += chunk;
    }
    Ok(())
}

/// 사용자 주소 공간에 사용자 스택을 매핑함.
///
/// `top` 은 사용자 스택 최상단(고주소, 16-byte 정렬). 본체는 [top - size, top)
/// 영역에 매핑됨.
///
/// # Safety
/// `space` 는 `alloc_user_address_space()` 로 받은 사용자 PML4 를 가리켜야
/// 하며, 부트 페이지 테이블이 활성(`LINEAR_MAP_ACTIVE = false`) 인 상태여야 함.
pub unsafe fn map_user_stack(
    space: &mut AddressSpace,
    top: u64,
    size: usize,
) -> Result<(u64, u64), ProcessError> {
    if size == 0 || !size.is_multiple_of(PAGE_SIZE) {
        return Err(ProcessError::BadAddress);
    }
    let bottom = top
        .checked_sub(size as u64)
        .ok_or(ProcessError::BadAddress)?;
    if !mmu::is_user_va(bottom) {
        return Err(ProcessError::BadAddress);
    }
    let pages = size / PAGE_SIZE;
    unsafe {
        map_user_region(space, bottom, pages, /* writable = */ true)?;
    }
    Ok((bottom, top))
}

//
// spawn / enter
//

/// flat raw 페이로드 한 덩어리를 새 사용자 프로세스로 적재함.
///
/// `code_payload` 는 사용자 코드(R+X) 페이지에, `data_payload` 는 사용자
/// 데이터(RW+NX) 페이지에 각각 적재됨. 사용자 스택은 자동으로 매핑됨.
///
/// 본 함수는 ELF 로더가 도래하기 전까지의 단순 진입 경로이며, 단일 진입점
/// 사용자 프로그램의 `_start` 검증용임.
///
/// # Safety
/// 부팅 초기 단일 코어 + LINEAR_MAP_ACTIVE = false 단계에서 호출.
pub unsafe fn spawn_flat(
    kernel_space: &AddressSpace,
    code_payload: &[u8],
) -> Result<ProcessId, ProcessError> {
    let slot = find_free_slot().ok_or(ProcessError::SlotsFull)?;

    // 1. 사용자 PML4 생성 + 커널 매핑 inherit
    let space_ptr = unsafe { alloc_user_address_space(kernel_space)? };
    // SAFETY: 갓 할당된 PML4 프레임 — 단독 접근
    let space = unsafe { &mut *space_ptr };

    // 2. 사용자 코드 페이로드 적재 (R+X)
    unsafe {
        load_flat_payload(
            space,
            DEFAULT_USER_ENTRY,
            code_payload,
            /* writable */ false,
        )?;
    }

    // 3. 사용자 스택 매핑
    let (stack_bottom, stack_top) =
        unsafe { map_user_stack(space, DEFAULT_USER_STACK_TOP, DEFAULT_USER_STACK_SIZE)? };

    // 4. 슬롯에 프로세스 메타데이터 저장
    let pml4_phys = space_ptr as u64;
    let id = ProcessId(slot as u8);
    let process = Process {
        id,
        state: ProcessState::Loaded,
        pml4_phys,
        entry_rip: DEFAULT_USER_ENTRY,
        user_rsp: stack_top & !0xF, // 16-byte 정렬
        user_stack_range: (stack_bottom, stack_top),
    };
    // SAFETY: 위 find_free_slot() 결과를 그대로 사용
    unsafe {
        put_slot(slot, process);
    }
    Ok(id)
}

/// 정적 ELF64 사용자 실행 파일을 새 사용자 프로세스로 적재함.
///
/// 흐름:
///   1. ELF 파싱 (헤더 + PT_LOAD 검증) → `Elf64Image`
///   2. 새 사용자 PML4 + boot stack identity 매핑
///   3. 각 PT_LOAD 세그먼트에 대해 페이지 매핑 + 파일 데이터 복사 + .bss 0-소거
///   4. 사용자 스택 매핑
///   5. 정적 슬롯에 메타데이터 기록
///
/// # Safety
/// 부팅 초기 단일 코어 + 부트 페이지 테이블 활성 단계에서 호출.
pub unsafe fn spawn_elf(
    kernel_space: &AddressSpace,
    elf_bytes: &[u8],
) -> Result<ProcessId, ProcessError> {
    let image: Elf64Image<'_> = elf::parse(elf_bytes)?;

    let slot = find_free_slot().ok_or(ProcessError::SlotsFull)?;

    // 1. 사용자 PML4 + 커널 매핑 + boot stack identity
    let space_ptr = unsafe { alloc_user_address_space(kernel_space)? };
    // SAFETY: 갓 만든 PML4 — 단독 접근
    let space = unsafe { &mut *space_ptr };

    // 2. PT_LOAD 적재
    for i in 0..image.loads.len {
        let ph = image.loads.headers[i];
        // SAFETY: phys 직접 접근(부트 페이지 테이블 활성, identity)
        unsafe {
            load_segment(space, &ph, image.raw)?;
        }
    }

    // 3. 사용자 스택 매핑
    let (stack_bottom, stack_top) =
        unsafe { map_user_stack(space, DEFAULT_USER_STACK_TOP, DEFAULT_USER_STACK_SIZE)? };

    // 4. 슬롯 채우기
    let pml4_phys = space_ptr as u64;
    let id = ProcessId(slot as u8);
    let process = Process {
        id,
        state: ProcessState::Loaded,
        pml4_phys,
        entry_rip: image.entry,
        user_rsp: stack_top & !0xF,
        user_stack_range: (stack_bottom, stack_top),
    };
    // SAFETY: find_free_slot 결과 사용
    unsafe {
        put_slot(slot, process);
    }
    Ok(id)
}

/// 단일 PT_LOAD 세그먼트를 사용자 PML4 에 매핑하고 파일 데이터 복사.
///
/// 동일 가상 페이지가 여러 PT_LOAD 에 걸쳐 매핑되는 경우 (`p_align >= 4 KiB`
/// 가 강제되어도 ELF 가 잘못 만든 케이스) 는 `MmuError::AlreadyMapped` 로
/// 거부됨.
unsafe fn load_segment(
    space: &mut AddressSpace,
    ph: &ProgramHeader,
    raw: &[u8],
) -> Result<(), ProcessError> {
    // 페이지 정렬된 시작 / 끝 (4 KiB)
    let page_mask = !(PAGE_SIZE as u64 - 1);
    let va_start = ph.p_vaddr & page_mask;
    let va_end = (ph.p_vaddr + ph.p_memsz + (PAGE_SIZE as u64 - 1)) & page_mask;
    let pages = ((va_end - va_start) as usize) / PAGE_SIZE;

    // PT_LOAD flags → writable 결정 (PF_W 우선; PF_X 만 있으면 R+X 코드 페이지)
    let writable = ph.is_writable();

    // 페이지 매핑 + 0-소거 (mmu::map_user_page 의 W^X 가 자동 적용됨)
    // SAFETY: alloc + 0-소거는 새 프레임에 대해서만 수행
    unsafe {
        map_user_region(space, va_start, pages, writable)?;
    }

    // 파일 데이터 복사 (p_filesz). p_memsz - p_filesz 영역은 .bss 로 0-유지.
    let file_off = ph.p_offset as usize;
    let file_len = ph.p_filesz as usize;
    let mut copied = 0usize;
    while copied < file_len {
        let va = ph.p_vaddr + copied as u64;
        // SAFETY: identity-mapped (boot pml4 active)
        let phys = unsafe { space.walk_to_phys(va & page_mask) }.ok_or(ProcessError::BadAddress)?;
        let page_off = (va & (PAGE_SIZE as u64 - 1)) as usize;
        let page_remain = PAGE_SIZE - page_off;
        let chunk = (file_len - copied).min(page_remain);
        // SAFETY: phys 는 방금 alloc 된 4 KiB 프레임. 부트 PML4 의 4 GiB
        //         identity map 으로 직접 쓰기 가능.
        unsafe {
            core::ptr::copy_nonoverlapping(
                raw.as_ptr().add(file_off + copied),
                (phys + page_off as u64) as *mut u8,
                chunk,
            );
        }
        copied += chunk;
    }
    Ok(())
}

/// 프로세스를 활성화하고 Ring 3 으로 점프함. 이 함수는 결코 반환하지 않음.
///
/// 1. CR3 ← 사용자 PML4 물리 주소
/// 2. swapgs (커널 GS=&PerCpu → KERNEL_GS_BASE; 사용자 GS=0)
/// 3. iretq 스택 frame 구축 후 `iretq` (Ring 0 → Ring 3)
///
/// # Safety
/// - `pid` 가 `Loaded` 상태여야 함.
/// - 호출 전에 `syscall::install()` + `tss::set_rsp0()` 가 완료되어 있어야 함.
/// - 인터럽트 비활성화(CLI) 상태에서 호출 권장 (iretq 가 RFLAGS=0x202 로
///   IF=1 을 설정하여 사용자 진입 직후 인터럽트 활성).
pub unsafe fn enter_ring3(pid: ProcessId) -> ! {
    let p = match get(pid) {
        Some(p) => p,
        None => loop {
            // SAFETY: 잘못된 pid → 즉시 정지 (방어적 fail-stop)
            unsafe {
                core::arch::asm!("cli", "hlt", options(nostack, preserves_flags));
            }
        },
    };
    let cr3 = p.pml4_phys;
    let rip = p.entry_rip;
    let rsp = p.user_rsp;

    // SAFETY: 아래 asm 블록은 단일 atomic 시퀀스로 CR3 적재 → swapgs →
    //         iretq 순으로 실행. 사이에 어떤 high-level 연산도 끼지 않음.
    //         iretq 는 RFLAGS = 0x202 (IF=1, reserved=1) 와 CS:RIP, SS:RSP 를
    //         적재하여 Ring 3 으로 권한 강하.
    unsafe {
        core::arch::asm!(
            // 1. 사용자 PML4 활성화
            "mov cr3, {cr3}",
            // 2. swapgs: 커널 GS=&PerCpu → KERNEL_GS_BASE,
            //            KERNEL_GS_BASE(=0) → GS_BASE (사용자 GS=0)
            "swapgs",
            // 3. iretq 스택 frame: 역순 push (SS, RSP, RFLAGS, CS, RIP)
            "push {ss}",
            "push {rsp}",
            "push 0x202",                       // RFLAGS = IF=1 + bit1
            "push {cs}",
            "push {rip}",
            "iretq",
            cr3 = in(reg) cr3,
            ss  = in(reg) USER_DS as u64,
            cs  = in(reg) USER_CS as u64,
            rsp = in(reg) rsp,
            rip = in(reg) rip,
            options(noreturn),
        );
    }
}
