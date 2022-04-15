// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "tc_root_common.h"

struct bpf_elf_map SEC("maps") tc_egress_root_pass_array = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .size_key = sizeof(int),
  .size_value = sizeof(int),
  .pinning = PIN_GLOBAL_NS,
  .max_elem = ROOT_ARRAY_SIZE,
};

struct bpf_elf_map SEC("maps") tc_egress_root_array = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .size_key = sizeof(int),
  .size_value = sizeof(int),
  .pinning = PIN_GLOBAL_NS,
  .max_elem = ROOT_ARRAY_SIZE,
};

SEC("tc-egress-root")
int tc_egress_root(struct __sk_buff *skb) {
  bpf_tail_call(skb, &tc_egress_root_pass_array, 0);
  return TC_ACT_OK;
}

SEC("tc-egress-pass-through")
int tc_egress_pass_through(struct __sk_buff *skb) {
  bpf_tail_call(skb, &tc_egress_root_array, 0);
  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
