// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/*  TC (Traffic Control) eBPF redirect benchmark
 *
 *  NOTICE: TC loading is different from XDP loading. TC bpf objects
 *          use the 'tc' cmdline tool from iproute2 for loading and
 *          attaching bpf programs.
 *
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#include <uapi/linux/pkt_cls.h>
#include <linux/skbuff.h>
#include "bpf_helpers.h"


#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})


/* Notice this section name is used when attaching TC filter
 *
 * Like:
 *  $TC qdisc   add dev $DEV clsact
 *  $TC filter  add dev $DEV egress bpf da obj $BPF_OBJ sec trim
 *  $TC filter show dev $DEV egress
 *  $TC filter  del dev $DEV egress
 *
 * Does TC redirect respect IP-forward settings?
 *
 */
SEC("trim")
int _trim(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = data;

    switch(iph->protocol) {
        case IPPROTO_TCP:
            if (data + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
                return BPF_DROP;
            tcph = data + sizeof(struct iphdr);
            /* If this runs on gue interface it is without mac,
             * so from total packet length exclude eth header. */
            if (bpf_skb_change_tail(skb, (iph->ihl + tcph->doff)*4, 0) < 0)
                return BPF_DROP;
            break;
        case IPPROTO_UDP:
            if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
                return BPF_DROP;
            /* If this runs on gue interface it is without mac,
             * so from total packet length exclude eth header. */
            if (bpf_skb_change_tail(skb, (iph->ihl)*4 + sizeof(struct udphdr), 0) < 0)
                return BPF_DROP;
            break;
        default:
            /* Don't trim */
            return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
