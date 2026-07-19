//! x86_64 entropy 어댑터 RDSEED/RDRAND + virtio PCI transport
//!
//! # Features
//! `hw` 는 capability.rs 에서 lossless move 된 RDSEED/RDRAND inline-asm 어댑터이고
//! `virtio_transport` 는 D-02 transport 분리 정합의 x86_64 PCI ECAM scan 입니다.

pub mod hw;
pub mod virtio_transport;
