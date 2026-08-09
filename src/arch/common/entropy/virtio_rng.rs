//! virtio-rng 어댑터 모듈 sentinel + verify-changed 의무
//!
//! # Features
//! `VirtIORng<KernelHal, PciTransport>::request_entropy` 의 단일 진입점입니다.
//! 0xFE sentinel 사전 채움 + verify-changed 로 DeviceNotReady
//! silent-pass 를 차단하며 모든 이탈 경로에서 scratch 를
//! zeroize 합니다. `KernelHal` 은 static BSS
//! DMA pool 만 사용하는 alloc-zero `virtio_drivers::Hal` 구현입니다.
//! sentinel + verify-changed 코어는 `sentinel_collect_with` 로 분리되어 host
//! 전용 테스트가 mock 주입 형태로 동일 본문을 검증합니다.

#[cfg(target_os = "none")]
use core::ptr::NonNull;

use constant_time::Choice;
use constant_time::traits::CtEqOps;
#[cfg(target_os = "none")]
use virtio_drivers::device::rng::VirtIORng;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use virtio_drivers::transport::pci::PciTransport;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
use virtio_drivers::transport::mmio::MmioTransport;
#[cfg(target_os = "none")]
use virtio_drivers::{BufferDirection, Hal, PAGE_SIZE, PhysAddr};

/// 부팅 시 활성화되는 virtio transport 타입 (arch 별 divergence).
///
/// x86_64 는 PCI ECAM 경유 `PciTransport`, aarch64 는 QEMU virt virtio-mmio window
/// 경유 `MmioTransport<'static>` 를 사용하며 `VirtIORng` 의 generic transport 파라미터로
/// 주입되어 `virtio_collect` 코어는 arch 무관하게 동일 본문을 공유합니다
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub type ActiveTransport = PciTransport;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub type ActiveTransport = MmioTransport<'static>;
use zeroize::Zeroize;

use super::EntropyError;

pub const SENTINEL: u8 = 0xFE;
// capability.rs::ENTROPY_LEN 정합
pub const VIRTIO_SCRATCH_LEN: usize = 32;

#[cfg(target_os = "none")]
#[used]
pub static mut VIRTIO_SCRATCH: [u8; VIRTIO_SCRATCH_LEN] = [SENTINEL; VIRTIO_SCRATCH_LEN];

// boot init 시점 probe_virtio_rng 결과로 채움
#[cfg(target_os = "none")]
pub static mut VIRTIO_RNG_INSTANCE: Option<VirtIORng<KernelHal, ActiveTransport>> = None;

// VirtQueue modern layout 2 page + 여유 2 page
#[cfg(target_os = "none")]
const DMA_POOL_PAGES: usize = 4;

/// PAGE_SIZE 정렬을 강제하는 DMA pool 단위 페이지 구조체.
///
/// virtio-drivers 의 `Hal::dma_alloc` 이 요구하는 4 KiB 정렬 유일 소유
/// 페이지를 static BSS 로 제공하기 위한 래퍼입니다.
#[cfg(target_os = "none")]
#[repr(C, align(4096))]
struct DmaPage([u8; PAGE_SIZE]);

#[cfg(target_os = "none")]
static mut DMA_POOL: [DmaPage; DMA_POOL_PAGES] = [const { DmaPage([0u8; PAGE_SIZE]) }; DMA_POOL_PAGES];
#[cfg(target_os = "none")]
static mut DMA_POOL_NEXT: usize = 0;

/// 커널 higher-half VMA 를 물리 주소로 변환하는 함수입니다.
///
/// # Arguments
/// `vaddr` - 변환할 가상 주소
#[cfg(target_os = "none")]
fn virt_to_phys(vaddr: usize) -> PhysAddr {
    let v = vaddr as u64;
    if v >= crate::mmu::KERNEL_VMA_BASE {
        v - crate::mmu::KERNEL_VMA_BASE
    } else {
        v
    }
}

/// 두 바이트 슬라이스의 동등 여부를 상수-시간 누산으로 판정하는 함수입니다.
///
/// CtEqOps 가 슬라이스에 미구현 (스칼라 + SecureBuffer 만 지원) 이므로
/// keystore.rs 의 per-byte ct_eq 누산 패턴을 사용합니다.
///
/// # Arguments
/// `a` - 비교 대상 슬라이스
/// `b` - 비교 기준 슬라이스
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    let mut eq = Choice::from_u8((a.len() == b.len()) as u8);
    for (x, y) in a.iter().zip(b.iter()) {
        eq &= CtEqOps::ct_eq(x, y);
    }
    eq
}

/// sentinel 사전 채움 + verify-changed + zeroize 코어 함수입니다.
///
/// 단일 정본으로 kernel 경로 (`virtio_collect`) 와 host 전용
/// 테스트 (mock 주입) 가 동일 코어를 공유합니다. request 가 scratch 를 전혀
/// 변경하지 않으면 (sentinel 전체 잔존) silent-pass 를 차단합니다.
///
/// # Arguments
/// `scratch` - sentinel 채움 대상 staging buffer
/// `buf` - 수집 결과 출력 buffer
/// `request` - scratch 를 채우는 entropy 요청 클로저
///
/// # Errors
/// `EntropyError::SourceUnavailable` - 요청 실패 / 0 옥텟 / sentinel 잔존
pub fn sentinel_collect_with<E>(
    scratch: &mut [u8; VIRTIO_SCRATCH_LEN],
    buf: &mut [u8],
    request: impl FnOnce(&mut [u8]) -> Result<usize, E>,
) -> Result<usize, EntropyError> {
    // (1) sentinel 사전 채움
    for b in scratch.iter_mut() {
        *b = SENTINEL;
    }

    // (2) request_entropy 상당 요청 실패 또는 0 옥텟 시 즉시 차단
    let n = match request(&mut scratch[..]) {
        Ok(n) if n > 0 => n,
        _ => {
            scratch.zeroize();
            return Err(EntropyError::SourceUnavailable);
        }
    };

    // (3) verify-changed sentinel 전체 잔존 시 silent-pass 차단
    let still_sentinel = [SENTINEL; VIRTIO_SCRATCH_LEN];
    if ct_eq_bytes(&scratch[..], &still_sentinel[..]).unwrap_u8() == 1 {
        scratch.zeroize();
        return Err(EntropyError::SourceUnavailable);
    }

    let take = core::cmp::min(core::cmp::min(n, VIRTIO_SCRATCH_LEN), buf.len());
    buf[..take].copy_from_slice(&scratch[..take]);
    scratch.zeroize();
    Ok(take)
}

/// virtio-drivers Hal 의 alloc-zero 구현체.
///
/// DMA 페이지는 static BSS pool 에서만 배분되어 동적 할당이 발생하지 않으며
/// pool 소진 시 paddr 0 을 반환해 `Dma::new` 가 DmaError 로 fail-stop 합니다.
#[cfg(target_os = "none")]
pub struct KernelHal;

// SAFETY: dma_alloc 은 PAGE_SIZE 정렬 + zero 화 + 유일 소유 페이지를 반환하고
// pool 재사용이 없어 (dealloc leak 정책) alias 가 발생하지 않음
#[cfg(target_os = "none")]
unsafe impl Hal for KernelHal {
    /// static BSS pool 에서 연속 DMA 페이지를 배분하는 함수입니다.
    ///
    /// # Arguments
    /// `pages` - 요청 페이지 수
    /// `_direction` - DMA 방향 (pool 정책에 영향 없음)
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        // SAFETY: BSP single-core boot 시점 단일 진입 가정
        unsafe {
            let next = *(&raw const DMA_POOL_NEXT);
            if pages == 0 || next + pages > DMA_POOL_PAGES {
                return (0, NonNull::dangling());
            }
            *(&raw mut DMA_POOL_NEXT) = next + pages;
            let base = (&raw mut DMA_POOL) as *mut DmaPage;
            let ptr = base.add(next) as *mut u8;
            core::ptr::write_bytes(ptr, 0, pages * PAGE_SIZE);
            (virt_to_phys(ptr as usize), NonNull::new_unchecked(ptr))
        }
    }

    /// pool 반납 없는 leak 정책의 dealloc 함수입니다.
    ///
    /// # Safety
    /// boot 시 1 회 초기화 전제로 반납이 없어도 pool 이 고갈되지 않음
    unsafe fn dma_dealloc(_paddr: PhysAddr, _vaddr: NonNull<u8>, _pages: usize) -> i32 {
        0
    }

    /// MMIO 물리 주소를 가상 주소로 변환하는 함수입니다.
    ///
    /// # Safety
    /// 호출자는 `paddr` 가 부트 identity map 영역 안의 유효 MMIO 임을 보장해야 함
    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(paddr as usize as *mut u8).unwrap()
    }

    /// 버퍼를 디바이스와 공유 가능한 물리 주소로 변환하는 함수입니다.
    ///
    /// # Safety
    /// 호출자는 buffer 가 호출 동안 다른 스레드에서 접근되지 않음을 보장해야 함
    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        virt_to_phys(buffer.cast::<u8>().as_ptr() as usize)
    }

    /// 공유 해제 함수입니다 (bounce buffer 부재로 no-op).
    ///
    /// # Safety
    /// share 와 동일한 단일 진입 가정
    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}

/// virtio-rng 에서 엔트로피를 수집하고 sentinel verify-changed 로 검증하는 함수입니다.
///
/// # Errors
/// `EntropyError::SourceUnavailable` - 디바이스 부재 / 요청 실패 / sentinel 잔존
///
/// # Safety
/// BSP single-core + VIRTIO_SCRATCH 와 VIRTIO_RNG_INSTANCE 의 단일 진입 가정
/// FMASK 재진입 차단으로 boot 및 reseed 경로의 단일 호출을 invariant 로 가정함
#[cfg(target_os = "none")]
#[allow(dead_code)]
pub unsafe fn virtio_collect(buf: &mut [u8]) -> Result<usize, EntropyError> {
    // SAFETY: BSP single-core VIRTIO_SCRATCH 단일 진입
    let scratch = unsafe { &mut *(&raw mut VIRTIO_SCRATCH) };

    // SAFETY: BSP single-core VIRTIO_RNG_INSTANCE 단일 진입
    let rng = match unsafe { (*(&raw mut VIRTIO_RNG_INSTANCE)).as_mut() } {
        Some(r) => r,
        None => {
            scratch.zeroize();
            return Err(EntropyError::SourceUnavailable);
        }
    };

    // sentinel + verify-changed + zeroize 코어 위임
    sentinel_collect_with(scratch, buf, |s| rng.request_entropy(s))
}

/// boot 시점 virtio-rng probe 결과를 BSS singleton 에 채우는 함수입니다.
///
/// # Safety
/// BSP single-core 부팅 1 회만 호출 VIRTIO_RNG_INSTANCE 단일 진입 갱신 가정
#[cfg(target_os = "none")]
#[allow(dead_code)]
pub unsafe fn init_virtio_rng_instance() {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: BSP single-core boot MMIO ECAM 은 identity map 영역
        let probed = unsafe { crate::arch::x86_64::entropy::virtio_transport::probe_virtio_rng() };
        // SAFETY: BSP single-core VIRTIO_RNG_INSTANCE 단일 진입 갱신
        unsafe {
            *(&raw mut VIRTIO_RNG_INSTANCE) = probed;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: BSP single-core boot virtio-mmio window 는 stage1 Device identity 매핑 영역
        let probed = unsafe { crate::arch::aarch64::entropy::probe_virtio_rng() };
        // SAFETY: BSP single-core VIRTIO_RNG_INSTANCE 단일 진입 갱신
        unsafe {
            *(&raw mut VIRTIO_RNG_INSTANCE) = probed;
        }
    }
}
