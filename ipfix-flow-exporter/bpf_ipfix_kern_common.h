// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#ifndef BPF_IPFIX_KERN_COMMON_H
#define BPF_IPFIX_KERN_COMMON_H

#define MAX_RECORDS 30000
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

void *memset(void *b, int c, unsigned long len)
{
  if (b == NULL || len <= 0)
      return b;
  unsigned char *ptr = b;
   while(*ptr != '\0' && len--)
    {
      *ptr++ = (unsigned char)c;
    }
  return(b);
}

#define flow_key_hash_mask 0x000fffff

#endif

struct update_flow_record_args {
    flow_record_t *flow_rec_from_map;
    flow_key_t flow_key;
    u16 pckt_size;
    u16 control_bit;
    u8 tos;
    u16 icmp_type;
    u8 ttl;
    u32 hash_key;
};

struct create_flow_record_args {
    flow_key_t flow_key;
    u16 pckt_size;
    u16 control_bit;
    u8 tos;
    u16 icmp_type;
    u8 ttl;
    u32 hash_key;
};

struct parse_port_args {
    void *trans_data;
    void *data_end;
    u8 proto;
    u32 *dport;
    u32 *sport;
    u16 *control_bit;
};
