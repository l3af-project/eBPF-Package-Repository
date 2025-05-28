// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} counting_map SEC(".maps");

// /sys/kernel/tracing/events/tcp/tcp_bad_csum/format
struct tcp_bad_csum_args_t {
    __u8 padding[16];
    __u8 skbaddr_pad[4];
    __u8 saddr[28];
    __u8 daddr[28];
    char __data[0];
};

// Tracepoint pathname: /sys/kernel/tracing/events/tcp/tcp_bad_csum
SEC("tracepoint/tcp/tcp_bad_csum")
int tcp_bad_csum(struct tcp_bad_csum_args_t *args)
{
    u32 key     = 0;
    u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp) {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
