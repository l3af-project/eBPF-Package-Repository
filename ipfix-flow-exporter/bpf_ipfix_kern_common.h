// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#ifndef BPF_IPFIX_KERN_COMMON_H
#define BPF_IPFIX_KERN_COMMON_H

typedef struct flow_key_ {
    u32 sa;
    u32 da;
    u16 sp;
    u16 dp;
    u8 prot;
}flow_key_t;


typedef struct flow_record_ {
    flow_key_t key;                 /* identifies flow by 5-tuple */
    u64 np;                         /* number of packets */
    u64 nb;                         /* number of bytes */
    u64 flow_start;                 /* flow start */
    u64 flow_end;                   /* flow end */
    u8 dir;                         /* direction of the flow */
    u16 tcp_control_bits;           /* TCP control bits */
    u8 tos;                         /* Type os service */
    u16 icmp_type;                  /* Type os service */
    u32 ingress_ifindex;            /* Ingress ifindex */
    u32 egress_ifindex;             /* Egress ifindex */
    u8 min_ttl;                     /* minimum_ttl  in this flow*/
    u8 max_ttl;                     /* maximum_ttl  in this flow*/
    u64 flow_id;                    /* flow id */
    u16 counter;                    /* flow_idle_counter */
} flow_record_t;

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

#define flow_key_hash_mask 0x000fffff

#endif
