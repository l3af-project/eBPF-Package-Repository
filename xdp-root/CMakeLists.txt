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
        exec_program(${NUGET} ARGS install "ebpf-for-windows" -Version 0.1.4 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    endif()
endif()

#
# eBPF application configuration
#

include_directories(../windows)
include_directories(../external/win-c/include)
add_executable(xdp_root xdp_root.c ../external/win-c/source/getopt.c ../windows/bpf_load.c)
target_link_libraries(xdp_root PRIVATE iphlpapi)
target_link_libraries(xdp_root PRIVATE ebpfapi)
add_definitions(-D_CRT_SECURE_NO_WARNINGS) # Allow use of strerror
set_property(TARGET xdp_root PROPERTY VS_PROJECT_IMPORT ${CMAKE_BINARY_DIR}/packages/eBPF-for-Windows/build/native/ebpf-for-windows.props)

#
# eBPF program configuration
#

add_custom_target(xdp_root_kern ALL
                  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/build/xdp_root_kern.o)
set(CFLAGS_KERN -g -target bpf -Wall -O2 $(ClangIncludes))
set_property(TARGET xdp_root_kern PROPERTY VS_PROJECT_IMPORT ${CMAKE_BINARY_DIR}/packages/eBPF-for-Windows/build/native/ebpf-for-windows.props)

# We use custom commands here so that the same command will be used on
# Linux and Windows (where cmake would normally use cl instead of clang).

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/build/xdp_root_kern.o
                   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xdp_root_kern.c
                   COMMAND clang ${CFLAGS_KERN} -c ${L3AF_SRC_PATH}/xdp_root_kern.c -o ${L3AF_SRC_PATH}/build/xdp_root_kern.o)
