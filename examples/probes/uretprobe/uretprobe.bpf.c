// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

// BPF Map for storing call counts
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} counter_map SEC(".maps");

// library path depends on the architecture
// aarch64 : SEC("uretprobe//usr/lib/aarch64-linux-gnu/libbz2.so.1:BZ2_bzReadClose")

SEC("uretprobe//lib/x86_64-linux-gnu/libbz2.so.1:BZ2_bzReadClose")
int BPF_KRETPROBE(bz2_read_close, const void *ret)
{
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    u32 pid;
    u32 key     = 0;
    u64 initval = 1, *valp;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(str, sizeof(str), ret);

    bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

    valp = bpf_map_lookup_elem(&counter_map, &key);
    if (!valp) {
        bpf_map_update_elem(&counter_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    return 0;
};

char _license[] SEC("license") = "Dual BSD/GPL";
