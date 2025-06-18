// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

#define ARRAY_SIZE 1

/* Maintains the prog fd of the next XDP program in the chain */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, ARRAY_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_next_prog_array SEC(".maps");

SEC("xdp-prog")
int xdp_prog(struct xdp_md *ctx) {
  /*
    Add your packet processing logic here
  */

  bpf_tail_call(ctx, &xdp_next_prog_array, 0);
  
  return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
