//! virtio-rng PCI device 검출 ECAM scan D-02 transport 분리
//!
//! # Features
//! MmioCam + PciRoot::enumerate_bus 로 virtio EntropySource 디바이스를 탐지해
//! PciTransport 를 주입합니다. 본 파일은 x86_64 PCI 전용이며 aarch64 MMIO
//! transport 는 Phase 10 에서 대칭 파일로 합류합니다 (D-02 잠금 정합).

use virtio_drivers::device::rng::VirtIORng;
use virtio_drivers::transport::DeviceType;
use virtio_drivers::transport::pci::bus::{Cam, MmioCam, PciRoot};
use virtio_drivers::transport::pci::{PciTransport, virtio_device_type};

use crate::arch::common::entropy::virtio_rng::KernelHal;

// QEMU q35 default ACPI MCFG dynamic discovery 는 v2.1 이월 (RESEARCH A2)
const MCFG_ECAM_BASE: usize = 0xE000_0000;

/// PCI bus 0 을 ECAM scan 하여 virtio-rng 디바이스를 탐지하는 함수입니다.
///
/// EntropySource 디바이스 부재 시 None 을 반환하며 Wave 3 의 quorum self-test
/// 가 그 경우를 graceful fail 로 처리합니다.
///
/// # Safety
/// BSP single-core boot 시점 + MMIO ECAM 영역이 mmu.rs identity map 안에
/// 매핑되어 있다고 가정함
// Wave 4 boot init 합류 전까지 호출자 부재 한시 허용
#[allow(dead_code)]
pub unsafe fn probe_virtio_rng() -> Option<VirtIORng<KernelHal, PciTransport>> {
    // SAFETY: 호출자가 ECAM 256 MiB 영역의 identity map 유효성을 보장
    let cam = unsafe { MmioCam::new(MCFG_ECAM_BASE as *mut u8, Cam::Ecam) };
    let mut root = PciRoot::new(cam);
    for (df, info) in root.enumerate_bus(0) {
        if virtio_device_type(&info) == Some(DeviceType::EntropySource) {
            let transport = PciTransport::new::<KernelHal, _>(&mut root, df).ok()?;
            return VirtIORng::new(transport).ok();
        }
    }
    None
}
