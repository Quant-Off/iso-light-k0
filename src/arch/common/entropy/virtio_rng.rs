//! virtio-rng 어댑터 모듈 ENTR-04 sentinel + verify-changed 의무 with_attest_buf prior art 정합
//!
//! # Features
//! `VirtIORng<KernelHal, PciTransport>::request_entropy` 의 단일 진입점입니다.
//! ENTR-04 명문의 0xFE sentinel 사전 채움 + verify-changed 로 DeviceNotReady
//! silent-pass 를 차단하며 (PITFALLS Pitfall 5) 모든 이탈 경로에서 scratch 를
//! zeroize 합니다 (with_attest_buf prior art 정합). `KernelHal` 은 static BSS
//! DMA pool 만 사용하는 alloc-zero `virtio_drivers::Hal` 구현입니다.

use core::ptr::NonNull;

use constant_time::{Choice, CtEqOps};
use virtio_drivers::device::rng::VirtIORng;
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::{BufferDirection, Hal, PAGE_SIZE, PhysAddr};
use zeroize::Zeroize;

use super::EntropyError;

pub const SENTINEL: u8 = 0xFE;
// capability.rs::ENTROPY_LEN 정합
pub const VIRTIO_SCRATCH_LEN: usize = 32;

#[used]
pub static mut VIRTIO_SCRATCH: [u8; VIRTIO_SCRATCH_LEN] = [SENTINEL; VIRTIO_SCRATCH_LEN];

// Wave 4 boot init 시점 probe_virtio_rng 결과로 채움
pub static mut VIRTIO_RNG_INSTANCE: Option<VirtIORng<KernelHal, PciTransport>> = None;

// VirtQueue modern layout 2 page + 여유 2 page
const DMA_POOL_PAGES: usize = 4;

/// PAGE_SIZE 정렬을 강제하는 DMA pool 단위 페이지 구조체.
///
/// virtio-drivers 의 `Hal::dma_alloc` 이 요구하는 4 KiB 정렬 유일 소유
/// 페이지를 static BSS 로 제공하기 위한 래퍼입니다.
#[repr(C, align(4096))]
struct DmaPage([u8; PAGE_SIZE]);

static mut DMA_POOL: [DmaPage; DMA_POOL_PAGES] = [const { DmaPage([0u8; PAGE_SIZE]) }; DMA_POOL_PAGES];
static mut DMA_POOL_NEXT: usize = 0;

/// 커널 higher-half VMA 를 물리 주소로 변환하는 함수입니다.
///
/// # Arguments
/// `vaddr` - 변환할 가상 주소
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
/// keystore.rs prior art 의 per-byte ct_eq 누산 패턴을 사용합니다.
///
/// # Arguments
/// `a` - 비교 대상 슬라이스
/// `b` - 비교 기준 슬라이스
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    let mut eq = Choice::from_u8((a.len() == b.len()) as u8);
    for (x, y) in a.iter().zip(b.iter()) {
        eq &= CtEqOps::eq(x, y);
    }
    eq
}

/// virtio-drivers Hal 의 alloc-zero 구현체.
///
/// DMA 페이지는 static BSS pool 에서만 배분되어 동적 할당이 발생하지 않으며
/// pool 소진 시 paddr 0 을 반환해 `Dma::new` 가 DmaError 로 fail-stop 합니다.
pub struct KernelHal;

// SAFETY: dma_alloc 은 PAGE_SIZE 정렬 + zero 화 + 유일 소유 페이지를 반환하고
// pool 재사용이 없어 (dealloc leak 정책) alias 가 발생하지 않음
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
// Wave 3 quorum 합류 전까지 호출자 부재 한시 허용
#[allow(dead_code)]
pub unsafe fn virtio_collect(buf: &mut [u8]) -> Result<usize, EntropyError> {
    // SAFETY: BSP single-core VIRTIO_SCRATCH 단일 진입
    let scratch = unsafe { &mut *(&raw mut VIRTIO_SCRATCH) };

    // (1) sentinel 사전 채움 (Pitfall 5 회피)
    for b in scratch.iter_mut() {
        *b = SENTINEL;
    }

    // SAFETY: BSP single-core VIRTIO_RNG_INSTANCE 단일 진입
    let rng = match unsafe { (*(&raw mut VIRTIO_RNG_INSTANCE)).as_mut() } {
        Some(r) => r,
        None => {
            scratch.zeroize();
            return Err(EntropyError::SourceUnavailable);
        }
    };

    // (2) request_entropy virtio-drivers 0.13 API
    let n = match rng.request_entropy(&mut scratch[..]) {
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

    let take = core::cmp::min(n, buf.len());
    buf[..take].copy_from_slice(&scratch[..take]);
    scratch.zeroize();
    Ok(take)
}
