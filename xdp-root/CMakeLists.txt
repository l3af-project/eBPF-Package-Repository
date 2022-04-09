# Copyright Contributors to the L3AF Project.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.10)
project(xdp-root)

set(L3AF_SRC_PATH ${CMAKE_CURRENT_LIST_DIR})

#
# eBPF application configuration
#

include_directories(../windows)
include_directories(../external/ebpf-for-windows/include)
include_directories(../external/ebpf-for-windows/include/uapi)
include_directories(../external/ebpf-for-windows/external/win-c/include)
link_directories(../external/ebpf-for-windows/x64/Debug)
add_executable(xdp_root xdp_root.c ../external/ebpf-for-windows/external/win-c/source/getopt.c ../windows/bpf_load.c)
target_link_libraries(xdp_root PRIVATE iphlpapi)
target_link_libraries(xdp_root PRIVATE ebpfapi)
add_definitions(-D_CRT_SECURE_NO_WARNINGS) # Allow use of strerror

#
# eBPF program configuration
#

add_custom_target(xdp_root_kern ALL
                  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/build/xdp_root_kern.o)
set(CFLAGS_KERN -g -target bpf -Wall -O2 -I ../../external/ebpf-for-windows/include)

# We use custom commands here so that the same command will be used on
# Linux and Windows (where cmake would normally use cl instead of clang).

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/build/xdp_root_kern.o
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xdp_root_kern.c
                   COMMAND clang ${CFLAGS_KERN} -c ${L3AF_SRC_PATH}/xdp_root_kern.c -o ${L3AF_SRC_PATH}/build/xdp_root_kern.o)
