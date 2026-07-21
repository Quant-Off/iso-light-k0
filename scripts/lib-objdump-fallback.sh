#!/usr/bin/env bash
# Phase 10 ARM-11 ARM-12 objdump 폴백 체인 source 헬퍼 (bash 3.2 호환)
#
# aarch64 ELF 디스어셈은 크로스 objdump 가 필요함 GNU 크로스가 있으면 우선 없으면
# llvm-objdump (양 OS 단일 바이너리 multi-arch) 로 대체 macOS 는 Apple objdump 폴백
# nm 은 arch-agnostic 이므로 심볼 게이트는 단순 폴백 nm -> gnm 만으로 충분함
#
# OQ4 권고 체인 aarch64-linux-gnu-objdump -> aarch64-elf-objdump -> llvm-objdump -> objdump
#
# 사용법 (source 후 함수 호출)
#   . scripts/lib-objdump-fallback.sh
#   OBJDUMP="$(resolve_objdump)" || exit 1
#   NM="$(resolve_nm)" || exit 1

# aarch64 ELF 디스어셈 가능한 첫 objdump 바이너리명을 stdout 으로 echo
# 폴백 체인 전부 미존재 시 stderr 진단 후 return 1
resolve_objdump() {
    local cand
    for cand in aarch64-linux-gnu-objdump aarch64-elf-objdump llvm-objdump objdump; do
        if command -v "$cand" >/dev/null 2>&1; then
            echo "$cand"
            return 0
        fi
    done
    echo "[CI] FAIL objdump 폴백 체인 전부 미존재 (aarch64-linux-gnu-objdump aarch64-elf-objdump llvm-objdump objdump)" >&2
    echo "       binutils-aarch64-linux-gnu 또는 llvm 설치 필요" >&2
    return 1
}

# 심볼 덤프용 nm 바이너리명을 stdout 으로 echo (nm 은 arch-agnostic)
# 폴백 체인 nm -> gnm 미존재 시 stderr 진단 후 return 1
resolve_nm() {
    local cand
    for cand in nm gnm; do
        if command -v "$cand" >/dev/null 2>&1; then
            echo "$cand"
            return 0
        fi
    done
    echo "[CI] FAIL nm / gnm 미존재 binutils 설치 필요" >&2
    return 1
}
