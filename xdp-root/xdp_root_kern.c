// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#define ROOT_ARRAY_SIZE 1
#define PIN_GLOBAL_NS 2

struct bpf_map_def SEC("maps") xdp_root_pass_array = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = ROOT_ARRAY_SIZE,
};

struct bpf_map_def SEC("maps") xdp_root_array = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = ROOT_ARRAY_SIZE,
};

SEC("xdp-root")
int xdp_root(struct xdp_md *ctx) {
  bpf_tail_call(ctx, &xdp_root_pass_array, 0);
  return XDP_PASS;
}

SEC("xdp-pass-through")
int xdp_pass_through(struct xdp_md *ctx) {
	bpf_tail_call(ctx, &xdp_root_array, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
