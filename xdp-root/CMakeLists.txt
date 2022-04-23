# Copyright Contributors to the L3AF Project.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.10)
project(xdp-root)

set(L3AF_SRC_PATH ${CMAKE_CURRENT_LIST_DIR})

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    find_program(NUGET nuget)
    if (NOT NUGET)
        message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
    else ()
        exec_program(${NUGET} ARGS install "ebpf-for-windows" -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    endif()
endif()

#
# eBPF application configuration
#

include_directories(../windows)
include_directories(./build/packages/eBPF-for-Windows.0.1.1/build/native/include)
include_directories(./build/packages/eBPF-for-Windows.0.1.1/build/native/include/uapi)
include_directories(../external/win-c/include)
link_directories(./build/packages/eBPF-for-Windows.0.1.1/build/native/lib)
add_executable(xdp_root xdp_root.c ../external/win-c/source/getopt.c ../windows/bpf_load.c)
target_link_libraries(xdp_root PRIVATE iphlpapi)
target_link_libraries(xdp_root PRIVATE ebpfapi)
add_definitions(-D_CRT_SECURE_NO_WARNINGS) # Allow use of strerror

#
# eBPF program configuration
#

add_custom_target(xdp_root_kern ALL
                  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/build/xdp_root_kern.o)
set(CFLAGS_KERN -g -target bpf -Wall -O2 -I ${CMAKE_CURRENT_SOURCE_DIR}/build/packages/eBPF-for-Windows.0.1.1/build/native/include -I ${CMAKE_CURRENT_SOURCE_DIR}/build/packages/eBPF-for-Windows.0.1.1/build/native/include/uapi)

# We use custom commands here so that the same command will be used on
# Linux and Windows (where cmake would normally use cl instead of clang).

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/build/xdp_root_kern.o
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xdp_root_kern.c
                   COMMAND clang ${CFLAGS_KERN} -c ${L3AF_SRC_PATH}/xdp_root_kern.c -o ${L3AF_SRC_PATH}/build/xdp_root_kern.o)
