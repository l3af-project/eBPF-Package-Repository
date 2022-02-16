// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: GPL-2.0

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/pkt_cls.h>

#include "bpf_helpers.h"

#define DEBUG 1

#define EGRESS 1
#define INGRESS 0

#define ICMP 1

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})

#define flow_key_hash_mask 0x000fffff

#define PIN_GLOBAL_NS 2
#define PIN_OBJECT_NS  1

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

#define TH_FIN 0x0001
#define TH_SYN 0x0002
#define TH_RST 0x0004
#define TH_PSH 0x0008
#define TH_ACK 0x0010
#define TH_URG 0x0020
#define TH_ECE 0x0040
#define TH_CWR 0x0080

#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)

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

/* INGRESS MAP FOR FLOW RECORD INFO */
struct bpf_elf_map SEC("maps")  ingress_flow_record_info_map = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(u32),
    .size_value     = sizeof(flow_record_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 10000,
};

/* INGRESS MAP FOR LAST RECORD PACKET INFO */
struct bpf_elf_map SEC("maps")  last_ingress_flow_record_info_map = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(u32),
    .size_value     = sizeof(flow_record_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 10000,
};

/* EGRESS MAP FOR FLOW RECORD PACKET INFO */
struct bpf_elf_map SEC("maps") egress_flow_record_info_map  = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(u32),
    .size_value     = sizeof(flow_record_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 10000,
};

/* EGRESS MAP FOR LAST RECORD PACKET INFO */
struct bpf_elf_map SEC("maps")  last_egress_flow_record_info_map  = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(u32),
    .size_value     = sizeof(flow_record_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 10000 
};

static unsigned int flow_key_hash (const flow_key_t f) {
    unsigned int hash_val = (((unsigned int)f.sa * 0xef6e15aa)
                ^((unsigned int)f.da * 0x65cd52a0)
                ^ ((unsigned int)f.sp * 0x8216)
                ^ ((unsigned int)f.dp * 0xdda37)
                ^ ((unsigned int)f.prot * 0xbc06)) ;
    return hash_val;
}

static void parse_icmp_type(void *icmp_data,void *data_end, u16 *icmp_type){
    u16 icmp_type_val = 0;

    struct icmphdr *icmph;
    icmph = icmp_data;

    if (icmph + 1 > data_end) {
        return;
    }
    icmp_type_val = icmph->type | icmph->code;
    *icmp_type = icmp_type_val;
    return;
}

static void parse_port(void *trans_data, void *data_end, u8 proto,
                       u32 *dport, u32 *sport, u16 *control_bit)
{
    struct udphdr *udph;
    struct tcphdr *tcph;

    u32 dstport = 0;
    u32 srcport = 0;
    u16 controlbit = 0;

    switch (proto) {
    case IPPROTO_UDP:
        udph = trans_data;
        if (udph + 1 > data_end) {
            return;
        }
        dstport = ntohs(udph->dest);
        srcport = ntohs(udph->source);
        break;
    case IPPROTO_TCP:
        tcph = trans_data;
        if (tcph + 1 > data_end) {
            return;
        }
        dstport = ntohs(tcph->dest);
        srcport = ntohs(tcph->source);
        if (tcph->syn & TCP_FLAGS) { controlbit = controlbit | TH_SYN; }
        if (tcph->fin & TCP_FLAGS) { controlbit = controlbit | TH_FIN; }
        if (tcph->rst & TCP_FLAGS) { controlbit = controlbit | TH_RST; }
        if (tcph->psh & TCP_FLAGS) { controlbit = controlbit | TH_PSH; }
        if (tcph->ack & TCP_FLAGS) { controlbit = controlbit | TH_ACK; }
        if (tcph->urg & TCP_FLAGS) { controlbit = controlbit | TH_URG; }
        if (tcph->cwr & TCP_FLAGS) { controlbit = controlbit | TH_CWR; }
        break;
    default:
        dstport = 0;
        srcport = 0;
        break;
    }
    *dport = dstport;
    *sport = srcport;
    *control_bit = controlbit;
    return ;
}

static void update_flow_record(flow_record_t *flow_rec_from_map, flow_key_t flow_key,
                               u16 pckt_size, u16 control_bit, u8 tos, u16 icmp_type,
                               u8 ttl, u32 type,  u32 hash_key)
{
    flow_record_t flow_rec ;
    memset(&flow_rec, 0, sizeof(flow_record_t));

    flow_rec.key = flow_rec_from_map->key;
    flow_rec.np = flow_rec_from_map->np + 1 ;
    flow_rec.nb = flow_rec_from_map->nb + pckt_size;
    flow_rec.flow_end = bpf_ktime_get_ns();
    flow_rec.flow_start = flow_rec_from_map->flow_start;
    flow_rec.tcp_control_bits = control_bit | flow_rec_from_map->tcp_control_bits ;
    flow_rec.tos = tos | flow_rec_from_map->tos ;
    flow_rec.icmp_type = icmp_type | flow_rec_from_map->icmp_type ;
    flow_rec.min_ttl = flow_rec_from_map->min_ttl;
    flow_rec.max_ttl = flow_rec_from_map->max_ttl;

    if(ttl > flow_rec_from_map->max_ttl)
        flow_rec.max_ttl = ttl;
    else if (ttl < flow_rec_from_map->min_ttl)
        flow_rec.min_ttl = ttl;

    if (type == EGRESS){
        flow_rec.dir = 1;
        if(bpf_map_update_elem(&egress_flow_record_info_map, &hash_key, &flow_rec, BPF_ANY) != 0)
            return;
    }
    else if (type == INGRESS){
        flow_rec.dir = 0;
        if(bpf_map_update_elem(&ingress_flow_record_info_map, &hash_key, &flow_rec, BPF_ANY) != 0)
            return;
    }
    return;
}

static void create_flow_record(flow_key_t flow_key, u16 pckt_size, u16 control_bit, u8 tos,
                               u16 icmp_type, u8 ttl, u32 type, u32 hash_key)
{
    flow_record_t flow_rec ;
    memset(&flow_rec, 0, sizeof(flow_record_t));

    flow_rec.key = flow_key ;
    flow_rec.np = 1 ;
    flow_rec.nb = pckt_size;
    flow_rec.flow_start = bpf_ktime_get_ns();
    flow_rec.flow_end = bpf_ktime_get_ns();
    flow_rec.tcp_control_bits = control_bit;
    flow_rec.tos = tos ;
    flow_rec.icmp_type = icmp_type;
    flow_rec.min_ttl = ttl;
    flow_rec.max_ttl = ttl;
    flow_rec.counter = 0;

    if (type == INGRESS){
        flow_rec.dir = 0;
        if(bpf_map_update_elem(&ingress_flow_record_info_map, &hash_key, &flow_rec, BPF_ANY) != 0)
            return;
    }
    else if (type == EGRESS){
        flow_rec.dir = 1;
        if(bpf_map_update_elem(&egress_flow_record_info_map, &hash_key, &flow_rec, BPF_ANY) != 0)
        return;
    }
    return;
}

static __always_inline
void process_flow(flow_key_t flow_key, u16 pckt_size, u32 type,
                  u16 control_bit, u8 tos, u16 icmp_type, u8 ttl)
{
    flow_record_t flow_rec ;
    flow_record_t *flow_rec_from_map = NULL;
    u32 hash_key = 0;

    hash_key = flow_key_hash(flow_key);

    if (type == EGRESS)
        flow_rec_from_map = bpf_map_lookup_elem(&egress_flow_record_info_map, &hash_key);
    else if (type == INGRESS)
        flow_rec_from_map = bpf_map_lookup_elem(&ingress_flow_record_info_map, &hash_key);

    if(flow_rec_from_map != NULL){
        update_flow_record(flow_rec_from_map, flow_key, pckt_size, control_bit, tos, icmp_type, ttl, type, hash_key);
    }
    else{
        create_flow_record(flow_key, pckt_size, control_bit, tos, icmp_type, ttl, type, hash_key);
    }
}

static __always_inline
void parse_ipv4(struct __sk_buff *skb, u64 l3_offset, u32 type)
{
    void *data_end = NULL;
    void *data = NULL;

    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;

    if(data_end  == NULL || data == NULL)
        return;

    u16 pckt_size = data_end - data;

    struct iphdr *iph = data + l3_offset;

    if (iph  > data_end)
        return;

    struct icmphdr *icmp ;

    flow_key_t flow_key = {0};
    u32 dport = 0;
    u32 sport = 0;
    u16 control_bit = 0;
    u16 icmp_type = 0;

    /* Hint: +1 is sizeof(struct iphdr) */
    if (iph + 1 > data_end)
        return;

    if(iph->protocol == ICMP)
        parse_icmp_type(iph+1, data_end, &icmp_type);

    parse_port(iph+1, data_end, iph->protocol,  &dport, &sport, &control_bit);

    memset(&flow_key, 0, sizeof(flow_key));
    flow_key.sa = iph->saddr;
    flow_key.da = iph->daddr;
    flow_key.dp = dport;
    flow_key.sp = sport;
    flow_key.prot = iph->protocol;

    process_flow(flow_key, pckt_size, type, control_bit, iph->tos, icmp_type, iph->ttl);

    return;
}

static __always_inline int handle_egress_eth_prot(struct __sk_buff *skb, u16 eth_proto, u64 l3_offset, u32 type)
{
    switch (eth_proto) {
    case ETH_P_IP:
        parse_ipv4(skb, l3_offset, type);
        return TC_ACT_OK;
    case ETH_P_IPV6: /* Not handler for IPv6 yet*/
    case ETH_P_ARP:
        return TC_ACT_OK;
    default:
        return TC_ACT_OK; /* Not handling eth_proto */
    }
}

/*
 *
 * Returns false on error and non-supported ether-type
 */
static __always_inline bool parse_egress_eth(struct ethhdr *eth, void *data_end,
                             u16 *eth_proto, u64 *l3_offset)
{
    u16 eth_type;
    u64 offset;

    offset = sizeof(*eth);
    if ((void *)eth + offset > data_end)
        return false;

    eth_type = eth->h_proto;

    /* TODO: Handle Vlan packet */

    *eth_proto = ntohs(eth_type);
    *l3_offset = offset;
    return true;
}

SEC("egress_flow_monitoring")
int _egress_flow_monitoring(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    u16 eth_proto = 0;
    u64 l3_offset = 0;
    if (!(parse_egress_eth(eth, data_end, &eth_proto, &l3_offset)))
        return TC_ACT_OK; /* Skip */

    handle_egress_eth_prot(skb, eth_proto, l3_offset, EGRESS);
    return TC_ACT_OK;
}

SEC("ingress_flow_monitoring")
int _ingress_flow_monitoring(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    u16 eth_proto = 0;
    u64 l3_offset = 0;
    if (!(parse_egress_eth(eth, data_end, &eth_proto, &l3_offset)))
        return TC_ACT_OK; /* Skip */

    handle_egress_eth_prot(skb, eth_proto, l3_offset, INGRESS);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
