use core::panic::PanicInfo;

/// EAL4+ 요구사항에 따른 안전한 패닉 처리 로직.
/// 어떠한 상황에서도 커널이 복구 불가능한 상태에 빠지면,
/// 정보 유출을 막기 위해 CPU를 즉각 정지(Halt)시킴.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // 향후 디버깅 모드일 때만 UART 등으로 제한적인 로깅을 수행하도록 설계해야 함
    // 현재는 공격 방어를 위해 무한 루프와 CPU Halt 명령어만 실행함
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack, preserves_flags));
        }
    }
}
