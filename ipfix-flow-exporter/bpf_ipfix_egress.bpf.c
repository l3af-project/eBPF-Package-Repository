// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#define KBUILD_MODNAME "foo"

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"
#include "bpf_ipfix_kern_common.h"
#define DEBUG 1
#define EGRESS 1
#define ICMP 1

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TC_ACT_OK 0

#define TH_FIN 0x0001
#define TH_SYN 0x0002
#define TH_RST 0x0004
#define TH_PSH 0x0008
#define TH_ACK 0x0010
#define TH_URG 0x0020
#define TH_ECE 0x0040
#define TH_CWR 0x0080

#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)

#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
/*EGRESS MAP FOR FLOW RECORD INFO */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, flow_record_t);
    __uint(max_entries, MAX_RECORDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_flow_record_info_map SEC(".maps");

/* EGRESS MAP FOR LAST RECORD PACKET INFO */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, flow_record_t);
    __uint(max_entries, MAX_RECORDS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} last_egress_flow_record_info_map SEC(".maps");

/* EGRESS MAP FOR CHAINING */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipfix_egress_jmp_table SEC(".maps");

static u32 flow_key_hash (const flow_key_t f) {
    u32 hash_val = (((u32)f.sa * 0xef6e15aa)
                ^((u32)f.da * 0x65cd52a0)
                ^ ((u32)f.sp * 0x8216)
                ^ ((u32)f.dp * 0xdda37)
                ^ ((u32)f.prot * 0xbc06));
    return hash_val;
}

static void update_flow_record(struct update_flow_record_args *args)
{
    flow_record_t flow_rec ;
    memset(&flow_rec, 0, sizeof(flow_record_t));

    flow_rec.key = args->flow_rec_from_map->key;
    flow_rec.np = args->flow_rec_from_map->np + 1 ;
    flow_rec.nb = args->flow_rec_from_map->nb + args->pckt_size;
    flow_rec.flow_end = bpf_ktime_get_ns();
    flow_rec.flow_start = args->flow_rec_from_map->flow_start;
    flow_rec.tcp_control_bits = args->control_bit | args->flow_rec_from_map->tcp_control_bits ;
    flow_rec.tos = args->tos | args->flow_rec_from_map->tos ;
    flow_rec.icmp_type = args->icmp_type | args->flow_rec_from_map->icmp_type ;
    flow_rec.min_ttl = args->flow_rec_from_map->min_ttl;
    flow_rec.max_ttl = args->flow_rec_from_map->max_ttl;

    if(args->ttl > args->flow_rec_from_map->max_ttl)
        flow_rec.max_ttl = args->ttl;
    else if (args->ttl < args->flow_rec_from_map->min_ttl)
        flow_rec.min_ttl = args->ttl;

    flow_rec.dir = EGRESS;
    if(bpf_map_update_elem(&egress_flow_record_info_map, &args->hash_key, &flow_rec, BPF_ANY) != 0)
        return;

    return;
}

static void create_flow_record(struct create_flow_record_args *args)
{
    flow_record_t flow_rec ;
    memset(&flow_rec, 0, sizeof(flow_record_t));

    flow_rec.key = args->flow_key ;
    flow_rec.np = 1 ;
    flow_rec.nb = args->pckt_size;
    flow_rec.flow_start = bpf_ktime_get_ns();
    flow_rec.flow_end = bpf_ktime_get_ns();
    flow_rec.tcp_control_bits = args->control_bit;
    flow_rec.tos = args->tos ;
    flow_rec.icmp_type = args->icmp_type;
    flow_rec.min_ttl = args->ttl;
    flow_rec.max_ttl = args->ttl;
    flow_rec.counter = 0;

    flow_rec.dir = EGRESS;

    if(bpf_map_update_elem(&egress_flow_record_info_map, &args->hash_key, &flow_rec, BPF_ANY) != 0)
            return;
    return;
}


static __always_inline
void process_flow(flow_key_t flow_key, u16 pckt_size,
                  u16 control_bit, u8 tos, u16 icmp_type, u8 ttl)
{
    flow_record_t flow_rec ;
    flow_record_t *flow_rec_from_map = NULL;
    u32 hash_key = 0;

    hash_key = flow_key_hash(flow_key);

    flow_rec_from_map = bpf_map_lookup_elem(&egress_flow_record_info_map, &hash_key);

    if(flow_rec_from_map != NULL){
        struct update_flow_record_args update_flow_args;
        update_flow_args.flow_rec_from_map = flow_rec_from_map;
        update_flow_args.flow_key = flow_key;
        update_flow_args.pckt_size = pckt_size;
        update_flow_args.control_bit = control_bit;
        update_flow_args.tos = tos;
        update_flow_args.icmp_type = icmp_type;
        update_flow_args.ttl = ttl;
        update_flow_args.hash_key = hash_key;
        update_flow_record(&update_flow_args);
    }
    else{
        struct create_flow_record_args create_flow_args;
        create_flow_args.flow_key = flow_key;
        create_flow_args.pckt_size = pckt_size;
        create_flow_args.control_bit = control_bit;
        create_flow_args.tos = tos;
        create_flow_args.icmp_type = icmp_type;
        create_flow_args.ttl = ttl;
        create_flow_args.hash_key = hash_key;
        create_flow_record(&create_flow_args);
    }
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

static void parse_port(struct parse_port_args *args)
{
    struct udphdr *udph;
    struct tcphdr *tcph;

    u32 dstport = 0;
    u32 srcport = 0;
    u16 controlbit = 0;

    switch (args->proto) {
    case IPPROTO_UDP:
        udph = args->trans_data;
        if (udph + 1 > args->data_end) {
            return;
        }
        dstport = bpf_ntohs(udph->dest);
        srcport = bpf_ntohs(udph->source);
        break;
    case IPPROTO_TCP:
        tcph = args->trans_data;
        if (tcph + 1 > args->data_end) {
            return;
        }
        dstport = bpf_ntohs(tcph->dest);
        srcport = bpf_ntohs(tcph->source);
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
    *(args->dport) = dstport;
    *(args->sport) = srcport;
    *(args->control_bit) = controlbit;
    return ;
}

static __always_inline
void parse_ipv4(struct __sk_buff *skb, u64 l3_offset)
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

    if ((void *) (iph + 1) > data_end)
        return;

    if(iph->protocol == ICMP)
        parse_icmp_type(iph+1, data_end, &icmp_type);

    struct parse_port_args port_args;
    port_args.trans_data = iph+1;
    port_args.data_end = data_end;
    port_args.proto = iph->protocol;
    port_args.dport = &dport;
    port_args.sport = &sport;
    port_args.control_bit = &control_bit;
    parse_port(&port_args);
    data_end =port_args.data_end;
    dport = *port_args.dport;
    sport = *port_args.sport;
    control_bit = *port_args.control_bit;
    memset(&flow_key, 0, sizeof(flow_key));
    flow_key.sa = iph->saddr;
    flow_key.da = iph->daddr;
    flow_key.dp = dport;
    flow_key.sp = sport;
    flow_key.prot = iph->protocol;

    process_flow(flow_key, pckt_size, control_bit, iph->tos, icmp_type, iph->ttl);

    return;
}

static __always_inline int handle_eth_prot(struct __sk_buff *skb, u16 eth_proto, u64 l3_offset)
{
    switch (eth_proto) {
    case ETH_P_IP:
        parse_ipv4(skb, l3_offset);
        return TC_ACT_OK;
    case ETH_P_IPV6: /* No handler for IPv6 yet*/
    case ETH_P_ARP:
        return TC_ACT_OK;
    default:
        return TC_ACT_OK; /* Not handling eth_proto */
    }
}

/*
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

    *eth_proto = bpf_ntohs(eth_type);
    *l3_offset = offset;
    return true;
}

SEC("tc_egress_flow_monitoring")
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

    handle_eth_prot(skb, eth_proto, l3_offset);
    bpf_tail_call(skb, &ipfix_egress_jmp_table, 0);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
