// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/*  TC (Traffic Control) eBPF redirect benchmark
 *
 *  NOTICE: TC loading is different from XDP loading. TC bpf objects
 *          use the 'tc' cmdline tool from iproute2 for loading and
 *          attaching bpf programs.
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>

#include <uapi/linux/pkt_cls.h>
#include <linux/skbuff.h>
#include "bpf_helpers.h"

#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

/* Notice: TC and iproute2 bpf-loader uses another elf map layout */
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};

struct daddr_key {
    __u32 prefix_len;
    __u8 data[4];
};

/* TODO: Describe what this PIN_GLOBAL_NS value 2 means???
 *
 * A file is automatically created here:
 *  /sys/fs/bpf/tc/globals/egress
 */
#define PIN_GLOBAL_NS 2
#define MAX_ADDRESSES 50
#define KEY_SIZE_IPV4 sizeof(struct bpf_lpm_trie_key) + sizeof(__u32)

struct bpf_elf_map SEC("maps") redirect_iface = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(int),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 2,
};

struct bpf_elf_map SEC("maps") egress_any = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(int),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 2
};

struct bpf_elf_map SEC("maps") dst_address = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .size_key = KEY_SIZE_IPV4,
    .size_value = sizeof(__u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = MAX_ADDRESSES,
    .flags = BPF_F_NO_PREALLOC,
};

struct bpf_elf_map SEC("maps") egress_src_port = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(u32),
    .size_value = sizeof(u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 50
};

struct bpf_elf_map SEC("maps") egress_dst_port = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(u32),
    .size_value = sizeof(u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 50
};

struct bpf_elf_map SEC("maps") egress_proto = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(u32),
    .size_value = sizeof(u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 50
};

struct bpf_elf_map SEC("maps") mirroring_egress_jmp_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .size_key = sizeof(u32),
    .size_value = sizeof(u32),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 1
};

/* Notice this section name is used when attaching TC filter
 *
 * Like:
 *  $TC qdisc   add dev $DEV clsact
 *  $TC filter  add dev $DEV egress bpf da obj $BPF_OBJ sec egress_redirect
 *  $TC filter show dev $DEV egress
 *  $TC filter  del dev $DEV egress
 *
 * Does TC redirect respect IP-forward settings?
 *
 */
static __always_inline int egress_redirect(struct __sk_buff *skb)
{
    bool src_addr_match = false;
    bool proto_match = false;
    bool src_port_match = false;
    bool dst_port_match = false;

    bool allow_all_ip = false;
    bool allow_all_src_ports = false;
    bool allow_all_dst_ports = false;

    int *ifindex;
    int *ifany;
    int iface_key = 1;

    /* Lookup what ifindex to redirect packets to */
    ifindex = bpf_map_lookup_elem(&redirect_iface, &iface_key);
    if (!ifindex) {
        return TC_ACT_OK;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    const int l3_off = ETH_HLEN; // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // TCP header offset

    struct ethhdr *eth = data;
    int l7_off;

    if (data + sizeof(*eth) > data_end) {
        return TC_ACT_OK;
    }
    if (eth->h_proto != htons(ETH_P_IP)) {
        return TC_ACT_OK; // Not an IPv4 packet, handover to kernel
    } else if (eth->h_proto == htons(ETH_P_ARP)) {
        return TC_ACT_OK;
    }

    if (data + l4_off > data_end) {
        return TC_ACT_OK; // Not our packet, handover to kernel
    }
    struct iphdr *iph = (struct iphdr *)(data + l3_off);

    if (iph->protocol == IPPROTO_TCP) {
        l7_off = l4_off + sizeof(struct tcphdr); // L7 (e.g. HTTP) header offset
    } else if (iph->protocol == IPPROTO_UDP) {
        l7_off = l4_off + sizeof(struct udphdr); // L7 (e.g. HTTP) header offset
    } else if (iph->protocol == IPPROTO_ICMP) {
        l7_off =
            l4_off + sizeof(struct icmphdr); // L7 (e.g. HTTP) header offset
    } else {
        return TC_ACT_OK;
    }

    if (data + l7_off > data_end) {
        return TC_ACT_OK; // Not our packet, handover to kernel
    }

    uint32_t all_ports = 0;
    uint32_t fin_srcport = 0;
    uint32_t fin_dstport = 0;

    __u32 daddr = iph->daddr;

    struct daddr_key dkey;
    dkey.prefix_len = 32;
    dkey.data[0] = daddr & 0xff;
    dkey.data[1] = (daddr >> 8) & 0xff;
    dkey.data[2] = (daddr >> 16) & 0xff;
    dkey.data[3] = (daddr >> 24) & 0xff;

    // Binary representation of ifany variable. Reading from LSB to MSB:
    //      0th bit True: allow all/any IP addresses
    //      1th bit True: allow all/any source port
    //      2th bit True: allow all/any destination port
    ifany = bpf_map_lookup_elem(&egress_any, &iface_key);
    if (ifany) {
        if (((*ifany) >> (0)) % 2 == 1) {
            allow_all_ip = true;
        }
        if (((*ifany) >> (1)) % 2 == 1) {
            allow_all_src_ports = true;
        }
        if (((*ifany) >> (2)) % 2 == 1) {
            allow_all_dst_ports = true;
        }
    }

    /* Check if the packet's destination ip falls in the remote endpoint CIDR */
    if (allow_all_ip == true || bpf_map_lookup_elem(&dst_address, &dkey)) {
        uint32_t protocol = iph->protocol;
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP
        if (bpf_map_lookup_elem(&egress_proto, &protocol)) {
            if (iph->protocol == IPPROTO_ICMP) {
                return bpf_clone_redirect(skb, *ifindex, 0);
            } else if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)(data + l4_off);
                fin_srcport = ntohs(udph->source);
                fin_dstport = ntohs(udph->dest);
            } else if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)(data + l4_off);
                fin_srcport = ntohs(tcph->source);
                fin_dstport = ntohs(tcph->dest);
            } else {
                return TC_ACT_OK;
            }

            if (allow_all_src_ports == true && allow_all_dst_ports == true) {
                return bpf_clone_redirect(skb, *ifindex, 0); // __bpf_rx_skb
            } else if (allow_all_src_ports == true &&
                       allow_all_dst_ports == false) {
                if (bpf_map_lookup_elem(&egress_dst_port, &fin_dstport)) {
                    return bpf_clone_redirect(skb, *ifindex, 0); // __bpf_rx_skb
                }
            } else if (allow_all_src_ports == false &&
                       allow_all_dst_ports == true) {
                if (bpf_map_lookup_elem(&egress_src_port, &fin_srcport)) {
                    return bpf_clone_redirect(skb, *ifindex, 0); // __bpf_rx_skb
                }
            } else if (allow_all_src_ports == false &&
                       allow_all_dst_ports == false) {
                if (bpf_map_lookup_elem(&egress_src_port, &fin_srcport) &&
                    bpf_map_lookup_elem(&egress_dst_port, &fin_dstport)) {
                    return bpf_clone_redirect(skb, *ifindex, 0); // __bpf_rx_skb
                }
            }
        }
    }
    return TC_ACT_OK;
}

SEC("egress_redirect")
int _egress_redirect(struct __sk_buff *skb)
{
    int ret;
    ret = egress_redirect(skb);
    if (ret != TC_ACT_OK) {
        return ret;
    }
    bpf_tail_call(skb, &mirroring_egress_jmp_table, 0);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
