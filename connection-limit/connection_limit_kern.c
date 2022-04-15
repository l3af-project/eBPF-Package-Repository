// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* TCP Connection Limit
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <net/sock.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

/* TCP flags */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)

/* First Octet for IPv4 localhost address range 127.[0-255].[0-255].[0-255] */
#define ipv4_lo_addr 0x7F
/* IPv6 localhost */
#define ipv6_lo_addr 0x1

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})

struct inet_sock_state_ctx {
    u64 __pad;              // First 8 bytes are not accessible by bpf code
    const void * skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

/* Maintains the current concurrent TCP connection count */
struct bpf_map_def SEC("maps") cl_conn_count = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(uint32_t),
    .value_size     = sizeof(uint64_t),
    .max_entries    = 1,
};

/* Holds the TCP connection limit set by the user */
struct bpf_map_def SEC("maps") cl_max_conn = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .key_size       = sizeof(uint32_t),
    .value_size     = sizeof(uint64_t),
    .max_entries    = 1,
};

/* Maintains TCP listen ports */
struct bpf_map_def SEC("maps") cl_tcp_conns = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(uint16_t),
    .value_size     = sizeof(uint32_t),
    .max_entries    = 200,
};

/* Maintains concurrent connection sockets */
struct bpf_map_def SEC("maps") cl_conn_info = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(uint64_t),
    .value_size     = sizeof(uint32_t),
    .max_entries    = 30000
};

/* Maintains the total number of connections received(TCP-SYNs)
 * Used only for metrics visibility */
struct bpf_map_def SEC("maps") cl_recv_count_map = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(uint32_t),
    .value_size     = sizeof(uint64_t),
    .max_entries    = 1
};

/* Maintains the total number of conenctions dropped as the
   connection limit is hit */
struct bpf_map_def SEC("maps") cl_drop_count_map = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(uint32_t),
    .value_size     = sizeof(uint64_t),
    .max_entries    = 1
};

/* Maintains the prog fd of the next XDP program in the chain */
struct bpf_map_def SEC("maps") xdp_cl_ingress_next_prog = {
    .type           = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size       = sizeof(int),
    .value_size     = sizeof(int),
    .max_entries    = 1
};

static __always_inline int is_ipv4_loopback(uint32_t *addr4)
{
    if ((*addr4 & 0xff) == ipv4_lo_addr)
        return 1;
    return 0;
}

static __always_inline int is_ipv6_loopback(uint32_t addr6[])
{
    if ((addr6[0] == 0) && (addr6[1] == 0) && (addr6[2] == 0) && (addr6[3] == 1))
        return 1;
    if ((addr6[0] == 0) && (addr6[1] == 0) && (addr6[2] == 0xffff0000) &&
        ((addr6[3]&0xff) == 0x7f))
        return 1;
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_state_ctx *args)
{
    uint32_t key = 0, map_val = 1, *ret_val;
    uint64_t *val;

    /* Ignore if it is not a TCP socket */
    if (args->protocol != IPPROTO_TCP)
        return 0;

    uint64_t skaddr = (uint64_t)args->skaddr;
    uint16_t sport = args->sport;

    /* Check for TCP connections being opened */
    if (args->newstate == TCP_ESTABLISHED)
    {
        /* Check for ipv4 connections being opened */
        if (args->family == AF_INET6)
        {
            struct in6_addr src_addr, dst_addr;

            /* Read source address from the probe context */
            if (bpf_probe_read(&src_addr.s6_addr32,
                    sizeof(src_addr.s6_addr32), args->saddr_v6) != 0)
                return 0;

            /* Read destination address from the probe context */
            if (bpf_probe_read(&dst_addr.s6_addr32,
                    sizeof(dst_addr.s6_addr32), args->daddr_v6) != 0)
                return 0;

            /* Ignore if it is ipv6 loopback connection */
            if (is_ipv6_loopback(src_addr.s6_addr32)) {
                return 0;
            }

            /* Ignore if it is ipv6 loopback connection */
            if (is_ipv6_loopback(dst_addr.s6_addr32)) {
                return 0;
            }
        }
        /* Check ipv4 connections being opened */
        if (args->family == AF_INET)
        {
            uint32_t src_addr, dst_addr;

            /* Read source address from the probe context */
            if (bpf_probe_read(&src_addr, sizeof(src_addr), args->saddr) != 0)
                return 0;

            /* Read source address from the probe context */
            if (bpf_probe_read(&dst_addr, sizeof(dst_addr), args->daddr) != 0)
                return 0;

            /* Ignore if it is ipv4 loopback connection */
            if (is_ipv4_loopback(&src_addr))
                return 0;

            /* Ignore if it is ipv4 loopback connection */
            if (is_ipv4_loopback(&dst_addr))
                return 0;
        }

        /* Look up for matching listen address using local port*/
        if (!bpf_map_lookup_elem(&cl_tcp_conns, &sport))
            return 0;

        if (bpf_map_update_elem(&cl_conn_info, &skaddr, &map_val, BPF_NOEXIST) == 0)
        {
            val = bpf_map_lookup_elem(&cl_conn_count, &key);
            if (val)
                __sync_fetch_and_add(val, 1);
        }
        return 0;
    }

    /* Check for TCP connections being closed */
    if (args->oldstate == TCP_ESTABLISHED)
    {
        /* Check ipv4 connections being closed */
        if (args->family == AF_INET6)
        {
            struct in6_addr src_addr, dst_addr;

            /* Read source address from the probe context */
            if (bpf_probe_read(&src_addr.s6_addr32,
                    sizeof(src_addr.s6_addr32), args->saddr_v6) != 0)
                return 0;

            /* Read destination address from the probe context */
            if (bpf_probe_read(&dst_addr.s6_addr32,
                    sizeof(dst_addr.s6_addr32), args->daddr_v6) != 0)
                return 0;

            /* Ignore if it is ipv6 loopback connection */
            if (is_ipv6_loopback(src_addr.s6_addr32))
                return 0;

            /* Ignore if it is ipv6 loopback connection */
            if (is_ipv6_loopback(dst_addr.s6_addr32))
                return 0;
        }
        /* Check ipv4 connections being closed */
        if (args->family == AF_INET)
        {
            uint32_t src_addr, dst_addr;

            /* Read source address from the probe context */
            if (bpf_probe_read(&src_addr, sizeof(src_addr), args->saddr) != 0)
                return 0;

            /* Read destination address from the probe context */
            if (bpf_probe_read(&dst_addr, sizeof(dst_addr), args->daddr) != 0)
                return 0;

            if (is_ipv4_loopback(&src_addr))
                return 0;

            if (is_ipv4_loopback(&dst_addr))
                return 0;
        }
        /* Look up for matching listen address using local port*/
        if (!bpf_map_lookup_elem(&cl_tcp_conns, &sport))
            return 0;

        if (bpf_map_lookup_elem(&cl_conn_info, &skaddr))
        {
            if (bpf_map_delete_elem(&cl_conn_info, &skaddr) == 0)
            {
                val = bpf_map_lookup_elem(&cl_conn_count, &key);
                if (val && (*val > 0))
                    __sync_fetch_and_add(val, -1);
            }
        }
    }
    return 0;
 }

SEC("xdp_limit_conn")
int _xdp_limit_conn(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Check if its valid ethernet packet */
    if (data + sizeof(struct ethhdr)+ 1 > data_end)
        return XDP_PASS;

    /* Check if its valid ip packet */
    struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    if (iph + 1 > data_end)
        return XDP_PASS;

    /* Ignore other than TCP packets */
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Check if its valid tcp packet */
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if (tcph + 1 > data_end)
        return XDP_PASS;

    /* Ignore other than TCP-SYN packets */
    if (!(tcph->syn & TCP_FLAGS))
        return XDP_PASS;

    /* Ignore TCP-SYN-ACK packets */
    if (tcph->ack & TCP_FLAGS)
        return XDP_PASS;

    /* Look up for matching listen address using local port*/
    uint16_t dstport = bpf_ntohs(tcph->dest);
    if (!bpf_map_lookup_elem(&cl_tcp_conns, &dstport))
        return XDP_PASS;

    uint32_t key = 0, rkey = 0, dkey = 0;
    uint64_t *conn_count_val, *max_conn_val, *recv_count_val, *drop_count_val;

    recv_count_val = bpf_map_lookup_elem(&cl_recv_count_map, &rkey);
    if (recv_count_val)
        (*recv_count_val)++;

    max_conn_val = bpf_map_lookup_elem(&cl_max_conn, &key);
    if (!max_conn_val)
        return XDP_PASS;

    conn_count_val = bpf_map_lookup_elem(&cl_conn_count, &key);
    if (!conn_count_val)
        return XDP_PASS;

    if (*conn_count_val > *max_conn_val)
    {
        drop_count_val = bpf_map_lookup_elem(&cl_drop_count_map, &dkey);
        if (drop_count_val) {
            (*drop_count_val)++;
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
