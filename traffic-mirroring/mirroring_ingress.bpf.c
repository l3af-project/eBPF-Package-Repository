// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/*  TC (Traffic Control) eBPF redirect benchmark
 *
 *  NOTICE: TC loading is different from XDP loading. TC bpf objects
 *          use the 'tc' cmdline tool from iproute2 for loading and
 *          attaching bpf programs.
 */
#include "vmlinux.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_ARP	0x0806		/* Address Resolution packet	*/
#define ETH_HLEN	14		/* Total octets in header.	 */
#define TC_ACT_OK		0

struct saddr_key {
    __u32 prefix_len;
    __u8 data[4];
};

#define MAX_ADDRESSES 50
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
#define KEY_SIZE_IPV4 sizeof(struct bpf_lpm_trie_key) + sizeof(__u32)
#else
#define KEY_SIZE_IPV4 (sizeof(struct bpf_lpm_trie_key_hdr) + sizeof(__u32))
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_iface SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_any SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, KEY_SIZE_IPV4);
    __type(value, u32);
    __uint(max_entries, MAX_ADDRESSES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} src_address SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mirroring_ingress_jmp_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_ADDRESSES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_src_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_ADDRESSES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_dst_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_ADDRESSES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_proto SEC(".maps");

/* Notice this section name is used when attaching TC filter
 *
 * Like:
 *  $TC qdisc   add dev $DEV clsact
 *  $TC filter  add dev $DEV ingress bpf da obj $BPF_OBJ sec ingress_redirect
 *  $TC filter show dev $DEV ingress
 *  $TC filter  del dev $DEV ingress
 *
 * Does TC redirect respect IP-forward settings?
 *
 */
static __always_inline int ingress_redirect(struct __sk_buff *skb)
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
    int iface_key = 0;

    /* Lookup what ifindex to redirect packets to */
    ifindex = bpf_map_lookup_elem(&redirect_iface, &iface_key);
    if (!ifindex)
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    const int l3_off = ETH_HLEN; // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // TCP header offset

    struct ethhdr *eth = data;
    int l7_off;

    if (data + sizeof(*eth) > data_end) {
        return TC_ACT_OK;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK; // Not an IPv4 packet, handover to kernel
    } else if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
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

    __u32 saddr = iph->saddr;

    struct saddr_key skey;
    skey.prefix_len = 32;
    skey.data[0] = saddr & 0xff;
    skey.data[1] = (saddr >> 8) & 0xff;
    skey.data[2] = (saddr >> 16) & 0xff;
    skey.data[3] = (saddr >> 24) & 0xff;

    // Binary representation of ifany variable. Reading from LSB to MSB:
    //      0th bit True: allow all/any IP addresses
    //      1th bit True: allow all/any source port
    //      2th bit True: allow all/any destination port
    ifany = bpf_map_lookup_elem(&ingress_any, &iface_key);
    if (ifany) {
        if (((*ifany) >> (0)) & 1) {
            allow_all_ip = true;
        }
        if (((*ifany) >> (1)) & 1) {
            allow_all_src_ports = true;
        }
        if (((*ifany) >> (2)) & 1) {
            allow_all_dst_ports = true;
        }
    }

    /* Check if the packet's destination ip falls in the remote endpoint CIDR */
    if (allow_all_ip == true || bpf_map_lookup_elem(&src_address, &skey)) {
        uint32_t protocol = iph->protocol;
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP
        if (bpf_map_lookup_elem(&ingress_proto, &protocol)) {
            if (iph->protocol ==
                IPPROTO_ICMP) { // for ICMP, src and dest ports do not matter
                return bpf_clone_redirect(skb, *ifindex, 0);
            } else if (iph->protocol == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)(data + l4_off);
                fin_srcport = bpf_ntohs(udph->source);
                fin_dstport = bpf_ntohs(udph->dest);
            } else if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)(data + l4_off);
                fin_srcport = bpf_ntohs(tcph->source);
                fin_dstport = bpf_ntohs(tcph->dest);
            } else {
                return TC_ACT_OK;
            }

            if (allow_all_src_ports == true && allow_all_dst_ports == true) {
                return bpf_clone_redirect(skb, *ifindex, 0); // __bpf_rx_skb
            } else if (allow_all_src_ports == true &&
                       allow_all_dst_ports == false) {
                if (bpf_map_lookup_elem(&ingress_dst_port, &fin_dstport)) {
                    int temp = bpf_clone_redirect(skb, *ifindex, 0);
                    return temp; // __bpf_rx_skb
                }
            } else if (allow_all_src_ports == false &&
                       allow_all_dst_ports == true) {
                if (bpf_map_lookup_elem(&ingress_src_port, &fin_srcport)) {
                    return bpf_clone_redirect(skb, *ifindex, 0); // __bpf_rx_skb
                }
            } else if (allow_all_src_ports == false &&
                       allow_all_dst_ports == false) {
                if (bpf_map_lookup_elem(&ingress_src_port, &fin_srcport) &&
                    bpf_map_lookup_elem(&ingress_dst_port, &fin_dstport)) {
                    return bpf_clone_redirect(skb, *ifindex, 0); // __bpf_rx_skb
                }
            }
        }
    }
    return TC_ACT_OK;
}

SEC("tc_ingress_redirect")
int _ingress_redirect(struct __sk_buff *skb)
{
    int ret;
    ret = ingress_redirect(skb);
    if (ret != TC_ACT_OK) {
        return ret;
    }
    bpf_tail_call(skb, &mirroring_ingress_jmp_table, 0);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
