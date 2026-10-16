# =============================================================================
# VMOS Clone — Phase 1 native build
# app/src/main/jni/CMakeLists.txt
#
# Produces:
#   libvmcontainer.so  — loaded by the Android app (JNI bridge + runtime)
#   vmos-guest-init    — static executable copied into every guest rootfs
#                        as /init (built from the same sources, no JNI deps)
#
# NDK dependencies (exact list):
#   • libc (bionic)     — clone/unshare/mount/pivot_root syscalls
#   • liblog            — __android_log_print          (target: log)
#   • libdl             — dlopen of future HAL plugins (target: dl)
#   • libm              — perf counters later          (target: m)
#   • pthread           — folded into bionic; no -lpthread on NDK
#   Pure C in Phase 1 → no STL. When display/input C++ lands (Phase 2),
#   set android.stl=c++_static in app/build.gradle.
# =============================================================================
cmake_minimum_required(VERSION 3.18.1)
project(vmcontainer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------- flags ------
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -Werror=format-security
    -fPIC
    -D_GNU_SOURCE
)
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# ------------------------------------------------------ host-facing shared lib
add_library(vmcontainer SHARED
    container/vm_container.c
    guest_init.c
    vm_jni.c
)

target_link_libraries(vmcontainer
    log        # system/liblog.so
    dl         # future virtual-HAL plugin loading
    m
)

# --------------------------------------------------------- guest /init binary
# Statically linked so it runs inside ANY guest rootfs regardless of that
# rootfs's libc. ImageManager.kt packages this to assets and installs it at
# <rootfs>/init during VM creation.
add_executable(vmos-guest-init
    guest_init.c
    container/vm_container.c
)
target_compile_definitions(vmos-guest-init PRIVATE VMC_GUEST_BUILD=1)
# Keep the JNI translation unit OUT of the guest binary:
set_source_files_properties(vm_jni.c PROPERTIES HEADER_FILE_ONLY FALSE)
target_link_libraries(vmos-guest-init log dl m)
# NOTE for NDK r26+: if your toolchain rejects implicit PIC with static-pie,
# uncomment:
# target_link_options(vmos-guest-init PRIVATE -static)

# ------------------------------------------------------------ host unit test
# On your Linux dev box (GTX-1060 machine):
#   cmake -S jni -B build/host -DVMC_HOST_SELFTEST=ON && cmake --build build/host
#   ./build/host/vmc_selftest
option(VMC_HOST_SELFTEST "Build host-side selftest binary" OFF)
if (VMC_HOST_SELFTEST AND NOT ANDROID)
    add_executable(vmc_selftest
        tests/selftest.c
        container/vm_container.c
        guest_init.c
    )
    target_compile_definitions(vmc_selftest PRIVATE VMC_HOST_TEST=1)
endif()
