// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__
#define PATH_PROCNET_TCP "/proc/net/tcp"
#define PATH_PROCNET_TCP6 "/proc/net/tcp6"
#define MIN_TCP_FIELDS 10
#define IPV4_OCTETS 4
#define MAP_COUNT 6
#define ipv4_lo_addr 0x7f
#define ipv6_lo_addr 0x1


/* XDP program that is next in the chain */
const char *xdp_cl_ingress_next_prog = "/sys/fs/bpf/xdp_cl_ingress_next_prog";

/* Port separator */
const char delim[] = ",";

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	/* Now a valid state */
	TCP_NEW_SYN_RECV,
	TCP_MAX_STATES	/* Leave at the end! */
};

#endif
