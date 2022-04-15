// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "tcprog_common.h"

struct bpf_elf_map SEC("maps") tc_ingress_next_prog_array = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .size_key = sizeof(int),
  .size_value = sizeof(int),
  .pinning = PIN_GLOBAL_NS,
  .max_elem = ROOT_ARRAY_SIZE,
};

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb) {
  /*
    Add your packet processing logic here
  */

  bpf_tail_call(skb, &tc_ingress_next_prog_array, 0);
  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
