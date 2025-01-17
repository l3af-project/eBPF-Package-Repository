// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

// library path depends on the architecture
// aarch64 : SEC("uprobe//lib/aarch64-linux-gnu/libcurl.so:curl_version_info")

SEC("uprobe//lib/x86_64-linux-gnu/libcurl.so:curl_version_info")
int BPF_KPROBE(curl_ver_info, const void *ret)
{
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    u32 pid;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(str, sizeof(str), ret);

    bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

    return 0;
};

char _license[] SEC("license") = "Dual BSD/GPL";
