// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} counting_map SEC(".maps");

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;
    u32 key     = 0;
    u64 initval = 1, *valp;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KRETPROBE ENTRY pid = %d, ret = %ld\n", pid, ret);

    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp) {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
