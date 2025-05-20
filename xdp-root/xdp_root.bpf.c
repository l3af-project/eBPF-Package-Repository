// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

#define ROOT_ARRAY_SIZE 1
#define PIN_GLOBAL_NS 2

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, ROOT_ARRAY_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_root_array SEC(".maps");

SEC("xdp-root")
int xdp_root(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &xdp_root_array, 0);
  return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
