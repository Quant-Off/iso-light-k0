//! 비트맵 기반 물리 프레임 할당을 수행하는 모듈입니다.
//!
//! 설계 원칙:
//!   - 비트맵으로 각 4 KiB 물리 프레임의 사용 여부를 추적
//!   - Bit=1: 사용 중 또는 예약됨 (USED/RESERVED)
//!   - Bit=0: 자유롭게 할당 가능 (FREE)
//!   - 초기 상태: 모든 비트 = 1 (전체 예약)
//!   - `init_from_memory_map()` 호출 시 Usable 영역의 비트를 0으로 해제
//!
//! 성능:
//!   - 할당: 64비트 워드 단위 스캔 + `trailing_ones()`로 O(n/64) 평균
//!   - 해제: O(1) 비트 조작
//!   - 워드 힌트(`next_free_word`)로 순차 할당 시 사실상 O(1)

use crate::memory_map::MemoryMap;

//
// 상수
//

/// 비트맵으로 커버하는 최대 물리 메모리 크기: 4 GiB
const MAX_PHYS_ADDR: u64 = 4 * 1024 * 1024 * 1024;
/// 물리 프레임 크기: 4 KiB
pub const FRAME_SIZE: u64 = 4096;
/// 관리 가능한 최대 프레임 수: 4 GiB / 4 KiB = 1,048,576
const MAX_FRAMES: usize = (MAX_PHYS_ADDR / FRAME_SIZE) as usize;
/// 비트맵 배열 크기 (64비트 워드 단위): 1,048,576 / 64 = 16,384 words = 128 KiB
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

//
// 물리 프레임 타입
//

/// 4 KiB 정렬된 물리 프레임 주소를 나타내는 타입.
/// 생성 시 정렬 보장, 이후 불변이므로 안전하게 raw 포인터로 변환 가능.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysFrame(u64);

impl PhysFrame {
    /// 물리 주소에서 `PhysFrame`을 생성함. 4 KiB 정렬되지 않으면 `None`.
    pub fn from_addr(addr: u64) -> Option<Self> {
        if addr & (FRAME_SIZE - 1) != 0 {
            None
        } else {
            Some(Self(addr))
        }
    }

    /// 물리 주소 반환
    pub fn addr(self) -> u64 {
        self.0
    }

    /// 프레임 인덱스 (= 물리 주소 / FRAME_SIZE)
    fn index(self) -> usize {
        (self.0 / FRAME_SIZE) as usize
    }
}

//
// 에러 타입
//

#[derive(Debug)]
pub enum AllocError {
    /// 가용 물리 프레임 소진
    OutOfMemory,
    /// 비트맵 범위를 벗어난 프레임 주소
    InvalidFrame,
    /// 이미 해제된 프레임을 다시 해제 시도 (double-free)
    DoubleFree,
}

//
// 비트맵 프레임 할당자
//

/// 비트맵 기반 물리 프레임 할당자.
///
/// 128 KiB의 정적 비트맵으로 최대 4 GiB의 물리 메모리를 관리함.
/// 전체 상태를 비트맵 하나로 표현하여 감사(audit) 용이성을 극대화함.
pub struct BitmapFrameAllocator {
    /// 비트맵: 각 비트가 하나의 4 KiB 프레임을 표현
    /// Bit=0: FREE, Bit=1: USED/RESERVED
    bitmap: [u64; BITMAP_WORDS],
    /// 현재 사용 가능한 프레임 수
    free_count: usize,
    /// 다음 할당 스캔을 시작할 워드 인덱스 힌트 (순차 할당 최적화)
    next_free_word: usize,
}

// `Default` 는 `const` 컨텍스트(static 초기화)에서 호출 불가하므로, 정적
// 할당자 자체를 0이 아닌 비트맵으로 초기화하는 본 타입에는 적합하지 않음
#[allow(clippy::new_without_default)]
impl BitmapFrameAllocator {
    /// 모든 프레임을 예약(USED) 상태로 초기화.
    /// `init_from_memory_map()` 호출 전까지는 할당 불가.
    pub const fn new() -> Self {
        Self {
            bitmap: [u64::MAX; BITMAP_WORDS], // 전체 예약
            free_count: 0,
            next_free_word: 0,
        }
    }

    //
    // 비트 조작 헬퍼
    //

    fn is_free(&self, frame_idx: usize) -> bool {
        let (word, bit) = (frame_idx / 64, frame_idx % 64);
        (self.bitmap[word] >> bit) & 1 == 0
    }

    fn mark_used(&mut self, frame_idx: usize) {
        let (word, bit) = (frame_idx / 64, frame_idx % 64);
        self.bitmap[word] |= 1u64 << bit;
    }

    fn mark_free(&mut self, frame_idx: usize) {
        let (word, bit) = (frame_idx / 64, frame_idx % 64);
        self.bitmap[word] &= !(1u64 << bit);
    }

    //
    // 초기화
    //

    /// 물리 주소 범위 `[base, base + length)`를 FREE 상태로 표시함.
    ///
    /// 4 KiB 정렬된 범위만 해제되며, `MAX_PHYS_ADDR`을 초과하는 주소는 무시됨.
    fn mark_range_free(&mut self, base: u64, length: u64) {
        // 4 KiB 정렬: 시작 주소는 올림, 끝 주소는 내림
        let aligned_base = (base + FRAME_SIZE - 1) & !(FRAME_SIZE - 1);
        let aligned_end = (base + length) & !(FRAME_SIZE - 1);

        if aligned_end <= aligned_base {
            return; // 정렬 후 유효한 범위가 없음
        }

        let start_idx = (aligned_base / FRAME_SIZE) as usize;
        let end_idx = ((aligned_end / FRAME_SIZE) as usize).min(MAX_FRAMES);

        for frame_idx in start_idx..end_idx {
            if !self.is_free(frame_idx) {
                self.mark_free(frame_idx);
                self.free_count += 1;
            }
        }

        // 힌트 갱신: 더 낮은 영역이 해제된 경우 스캔 시작점을 당김
        let start_word = start_idx / 64;
        if start_word < self.next_free_word {
            self.next_free_word = start_word;
        }
    }

    /// 메모리 맵을 기반으로 할당자를 초기화함.
    ///
    /// `Usable` 영역만 FREE로 표시하며, 나머지는 예약 상태를 유지함.
    /// 커널이 로드된 영역은 이후 `mark_kernel_used()`로 다시 예약해야 함.
    pub fn init_from_memory_map(&mut self, map: &MemoryMap) {
        for region in map.usable_regions() {
            self.mark_range_free(region.base, region.length);
        }
    }

    /// 특정 물리 주소 범위를 USED로 강제 표시함.
    ///
    /// 커널 이미지, 커널 스택, GDT 등 이미 사용 중인 영역을 예약하는 데 사용.
    pub fn mark_range_used(&mut self, base: u64, length: u64) {
        let start_idx = (base / FRAME_SIZE) as usize;
        let end_idx = ((base + length).div_ceil(FRAME_SIZE) as usize).min(MAX_FRAMES);

        for frame_idx in start_idx..end_idx {
            if self.is_free(frame_idx) {
                self.mark_used(frame_idx);
                self.free_count = self.free_count.saturating_sub(1);
            }
        }
    }

    //
    // 할당 / 해제
    //

    /// 가용한 물리 프레임 하나를 할당하여 반환함.
    ///
    /// 64비트 워드 단위로 스캔하며, `trailing_ones()`으로 워드 내
    /// 첫 번째 FREE 비트를 O(1)에 찾음.
    ///
    /// ## 보안 소거 (EAL4+)
    /// 반환 전 프레임 전체(4 KiB)를 `zeroize::secure_zero`로 소거하여
    /// 이전 사용자의 잔류 데이터가 새 할당자에게 노출되지 않도록 보장.
    ///
    /// ## 전제 조건 (소거 시)
    /// `activate()` 이전: 물리 주소 = 가상 주소 (boot identity map 유효).
    /// `activate()` 이후: 직접 선형 매핑(PHYS_MAP_OFFSET + phys)을 통해 소거해야 함.
    /// 현재는 부팅 초기에만 호출되므로 identity map 가정이 성립함.
    pub fn alloc(&mut self) -> Option<PhysFrame> {
        for word_idx in self.next_free_word..BITMAP_WORDS {
            let word = self.bitmap[word_idx];

            if word == u64::MAX {
                continue;
            }

            let bit = word.trailing_ones() as usize;
            let frame_idx = word_idx * 64 + bit;

            if frame_idx >= MAX_FRAMES {
                break;
            }

            self.bitmap[word_idx] |= 1u64 << bit;
            self.free_count -= 1;
            self.next_free_word = word_idx;

            let frame = PhysFrame(frame_idx as u64 * FRAME_SIZE);

            // 보안 소거: 이전 사용자 잔류 데이터 제거
            // SAFETY: frame.addr()는 4 KiB 정렬된 유효한 물리 주소
            //         부팅 초기 identity map에서 phys == virt이므로 직접 접근 가능
            unsafe {
                zeroize::volatile::secure_zero(frame.addr() as *mut u8, FRAME_SIZE as usize);
            }

            return Some(frame);
        }

        None
    }

    /// 물리 프레임을 반환하여 재사용 가능한 상태로 만듦.
    ///
    /// ## 보안 소거 (EAL4+)
    /// 비트맵 해제 전 프레임 전체(4 KiB)를 `zeroize::secure_zero`로 소거.
    /// DoubleFree 검사 이후에 소거하여 이미 소거된 프레임의 이중 소거를 방지.
    pub fn dealloc(&mut self, frame: PhysFrame) -> Result<(), AllocError> {
        let idx = frame.index();

        if idx >= MAX_FRAMES {
            return Err(AllocError::InvalidFrame);
        }

        if self.is_free(idx) {
            return Err(AllocError::DoubleFree);
        }

        // 보안 소거: 해제 전 잔류 민감 데이터 완전 소거
        // 비트맵 해제 전에 소거하여 소거와 해제 사이 경쟁 창구 최소화
        // SAFETY: DoubleFree 검사 통과 후 frame.addr()는 유효한 USED 프레임
        unsafe {
            zeroize::volatile::secure_zero(frame.addr() as *mut u8, FRAME_SIZE as usize);
        }

        self.mark_free(idx);
        self.free_count += 1;

        let word_idx = idx / 64;
        if word_idx < self.next_free_word {
            self.next_free_word = word_idx;
        }

        Ok(())
    }

    /// 현재 가용 프레임 수 반환
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// 현재 가용 메모리 크기 (bytes)
    pub fn free_bytes(&self) -> u64 {
        self.free_count as u64 * FRAME_SIZE
    }
}

//
// 전역 싱글톤
//

/// 커널 전역 물리 프레임 할당자.
///
/// # 동시성 안전성
/// 현재 단일 코어 부팅 경로에서만 사용됨.
/// SMP 활성화 시에는 스핀락(spinlock)으로 보호해야 함.
// SAFETY: 부팅 초기 단일 코어 접근만 허용 (SMP 활성화 전)
static mut FRAME_ALLOCATOR: BitmapFrameAllocator = BitmapFrameAllocator::new();

/// 메모리 맵으로 전역 프레임 할당자를 초기화함.
///
/// # Safety
/// 부팅 초기 단일 코어에서, MMU 활성화 전에 반드시 한 번만 호출해야 함.
pub unsafe fn init(map: &MemoryMap) {
    // SAFETY: 호출자가 단일 코어 접근을 보장함
    // &raw mut 로 raw 포인터를 생성하여 Rust 2024 static_mut_refs 규칙을 준수
    unsafe {
        (*(&raw mut FRAME_ALLOCATOR)).init_from_memory_map(map);
    }
}

/// 물리 주소 범위 `[base, base+length)`를 USED로 강제 표시함.
///
/// `init()` 직후 커널 이미지, 부트 스택, 페이지 테이블 등
/// 이미 점유된 영역이 `alloc_frame()`으로 반환되지 않도록 보호함.
///
/// # Safety
/// 부팅 초기 단일 코어에서, MMU 활성화 전에 호출해야 함.
pub unsafe fn mark_used(base: u64, length: u64) {
    // SAFETY: 호출자가 단일 코어 접근을 보장함
    unsafe {
        (*(&raw mut FRAME_ALLOCATOR)).mark_range_used(base, length);
    }
}

/// 전역 할당자에서 물리 프레임 하나를 할당함.
///
/// # Safety
/// SMP 활성화 전 단일 코어 또는 외부 동기화가 보장된 환경에서 호출해야 함.
pub unsafe fn alloc_frame() -> Option<PhysFrame> {
    // SAFETY: 호출자가 단일 코어 접근을 보장함
    unsafe { (*(&raw mut FRAME_ALLOCATOR)).alloc() }
}

/// 전역 할당자로 물리 프레임을 반환함.
///
/// # Safety
/// SMP 활성화 전 단일 코어 또는 외부 동기화가 보장된 환경에서 호출해야 함.
pub unsafe fn free_frame(frame: PhysFrame) -> Result<(), AllocError> {
    // SAFETY: 호출자가 단일 코어 접근을 보장함
    unsafe { (*(&raw mut FRAME_ALLOCATOR)).dealloc(frame) }
}

/// 전역 할당자의 현재 가용 프레임 수를 반환함.
pub fn free_frame_count() -> usize {
    // SAFETY: 읽기 전용, 부팅 초기 단일 코어 접근
    unsafe { (*(&raw const FRAME_ALLOCATOR)).free_count() }
}
