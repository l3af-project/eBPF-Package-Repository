// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})
#define ROOT_ARRAY_SIZE 2

struct bpf_map_def SEC("maps") map_1 = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = ROOT_ARRAY_SIZE,
};

SEC("xdp_pass1")
int xdp_pass1_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP;
	int *ifindex, port = 0;
	long *value;
	u32 key = 0;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;
	bpf_printk("inside xdp_pass1\n");
	#pragma clang loop unroll(full)
        for (int i = 1; i < 16; i++) {
            //jmp.call((void *)ctx, i);
	    bpf_tail_call(ctx, &map_1, i);
        }
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
