//! mock VirtIORng silent-pass 차단 host 검증 (ENTR-04)
//!
//! kernel 의 `virtio_collect` 와 동일한 `sentinel_collect_with` 코어에 mock 을
//! 주입해 0xFE sentinel 미변경 시 SourceUnavailable 차단과 zeroize 강제를 검증함
#![cfg(not(target_os = "none"))]

use iso_light_k0::arch::common::entropy::EntropyError;
use iso_light_k0::arch::common::entropy::virtio_rng::{
    SENTINEL, VIRTIO_SCRATCH_LEN, sentinel_collect_with,
};

enum MockFailMode {
    None,
    RequestError,
    NoWrite,
}

struct MockVirtIORng {
    fill_pattern: u8,
    fail_mode: MockFailMode,
}

impl MockVirtIORng {
    fn request_entropy(&self, buf: &mut [u8]) -> Result<usize, ()> {
        match self.fail_mode {
            MockFailMode::RequestError => Err(()),
            MockFailMode::NoWrite => Ok(buf.len()),
            MockFailMode::None => {
                for b in buf.iter_mut() {
                    *b = self.fill_pattern;
                }
                Ok(buf.len())
            }
        }
    }
}

#[test]
fn sentinel_unchanged_returns_source_unavailable() {
    // 0xFE 만 채우는 device 는 sentinel 미변경과 구분 불가하므로 차단되어야 함
    let mock = MockVirtIORng {
        fill_pattern: SENTINEL,
        fail_mode: MockFailMode::None,
    };
    let mut scratch = [0u8; VIRTIO_SCRATCH_LEN];
    let mut out = [0u8; VIRTIO_SCRATCH_LEN];
    let r = sentinel_collect_with(&mut scratch, &mut out, |s| mock.request_entropy(s));
    assert!(matches!(r, Err(EntropyError::SourceUnavailable)));
    // 이탈 경로에서도 scratch zeroize 강제
    assert!(scratch.iter().all(|&b| b == 0));
}

#[test]
fn device_no_write_silent_pass_blocked() {
    // Ok(n) 을 주장하지만 실제로 쓰지 않는 DeviceNotReady 상당 race 차단 (Pitfall 5)
    let mock = MockVirtIORng {
        fill_pattern: 0,
        fail_mode: MockFailMode::NoWrite,
    };
    let mut scratch = [0u8; VIRTIO_SCRATCH_LEN];
    let mut out = [0u8; VIRTIO_SCRATCH_LEN];
    let r = sentinel_collect_with(&mut scratch, &mut out, |s| mock.request_entropy(s));
    assert!(matches!(r, Err(EntropyError::SourceUnavailable)));
    assert!(scratch.iter().all(|&b| b == 0));
}

#[test]
fn request_error_returns_source_unavailable() {
    let mock = MockVirtIORng {
        fill_pattern: 0,
        fail_mode: MockFailMode::RequestError,
    };
    let mut scratch = [0u8; VIRTIO_SCRATCH_LEN];
    let mut out = [0u8; VIRTIO_SCRATCH_LEN];
    let r = sentinel_collect_with(&mut scratch, &mut out, |s| mock.request_entropy(s));
    assert!(matches!(r, Err(EntropyError::SourceUnavailable)));
    assert!(scratch.iter().all(|&b| b == 0));
}

#[test]
fn buffer_changed_returns_ok_with_zeroize() {
    let mock = MockVirtIORng {
        fill_pattern: 0xAB,
        fail_mode: MockFailMode::None,
    };
    let mut scratch = [0u8; VIRTIO_SCRATCH_LEN];
    let mut out = [0u8; VIRTIO_SCRATCH_LEN];
    let r = sentinel_collect_with(&mut scratch, &mut out, |s| mock.request_entropy(s));
    assert!(matches!(r, Ok(n) if n == VIRTIO_SCRATCH_LEN));
    assert!(out.iter().all(|&b| b == 0xAB));
    // 성공 경로 잔재는 0xFE 가 아닌 0x00 (zeroize 강제)
    assert!(scratch.iter().all(|&b| b == 0));
}
