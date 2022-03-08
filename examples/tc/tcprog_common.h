// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)


#ifndef _TC_ROOT_COMMON_STRUCTS_H
#define _TC_ROOT_COMMON_STRUCTS_H

#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/skbuff.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

#define ROOT_ARRAY_SIZE 1
#define PIN_GLOBAL_NS 2

/* Notice: TC and iproute2 bpf-loader uses another elf map layout */
struct bpf_elf_map
{
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

#endif
