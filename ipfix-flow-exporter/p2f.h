/*
 *
 * Copyright (c) 2016-2018 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file p2f.h
 *
 * \brief header file for packet to flow
 *
 */
#ifndef P2F_H
#define P2F_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define TCP_OPT_LEN 24
#define NANOSEC  1000000000UL
#define MICROSEC  1000000L

typedef struct tcp_info_ {
    uint32_t ack;
    uint32_t seq;
    uint32_t retrans;
    uint32_t first_seq;
    uint16_t first_window_size;
    unsigned char flags;
    unsigned char opt_len;
    unsigned char opts[TCP_OPT_LEN];
} tcp_info_t;

typedef struct flow_key_ {
    uint32_t sa;
    uint32_t da;
    uint16_t sp;
    uint16_t dp;
    uint8_t prot;
}flow_key_t;

typedef struct flow_record_ {
    flow_key_t key;                       /* identifies flow by 5-tuple */
    uint64_t np;                          /* number of packets */
    uint64_t nb;                          /* number of bytes */
    uint64_t flow_start;                  /* flow start */
    uint64_t flow_end;                    /* flow end */
    uint8_t dir;                          /* direction of the flow */
    uint16_t tcp_control_bits;            /* TCP control bits */
    uint8_t tos;                          /* Type of service */
    uint16_t icmp_type;                   /* ICMP type */
    uint32_t ingress_ifindex;             /* Ingress ifindex */
    uint32_t egress_ifindex;              /* Egress ifindex */
    uint8_t min_ttl;                      /* minimum_ttl  in this flow*/
    uint8_t max_ttl;                      /* maximum_ttl  in this flow*/
    uint64_t flow_id;                     /* flow id */
    uint16_t counter;                     /* flow id */
} flow_record_t;

flow_record_t* update_flow_record_to_craete_ipfix(flow_record_t *flow_rec, bool first_rec,
                                                  flow_record_t last_flow_rec, int type);
bool process_record_map(int map_fd, int last_map_fd, int type);
#endif /* P2F_H */

