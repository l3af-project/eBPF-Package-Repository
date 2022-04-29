# Copyright Contributors to the L3AF Project.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(
    "eBPF-Package-Repository"
        LANGUAGES C
        HOMEPAGE_URL "https://github.com/l3af-project/eBPF-Package-Repository")

# Recurse through subdirectories
add_subdirectory(ratelimiting)
add_subdirectory(xdp-root)
