use core::panic::PanicInfo;

/// 안전한 패닉 처리 로직입니다.
/// 어떠한 상황에서도 커널이 복구 불가능한 상태에 빠지면,
/// 정보 유출을 막기 위해 CPU를 즉각 정지(Halt)시킵니다.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // 향후 디버깅 모드일 때만 UART 등으로 제한적인 로깅을 수행하도록 설계해야 함
    // 현재는 공격 방어를 위해 CPU 영구 정지 (arch 표면 위임)
    crate::arch::active::cpu::halt_loop()
}
