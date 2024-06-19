// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "tcprog_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_egress_next_prog_array SEC(".maps");

/* SEC name should be prefixed with tc */
SEC("tc-egress")
int tc_egress(struct __sk_buff *skb) {
  /*
    Add your packet processing logic here
  */

  bpf_tail_call(skb, &tc_egress_next_prog_array, 0);
  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
