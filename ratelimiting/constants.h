// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#ifndef CONSTANTS_H
#define CONSTANTS_H

#ifndef PATH_MAX
#define PATH_MAX        4096
#endif

#define DEFAULT_LOGFILE "/var/log/l3af/ratelimiting.log"

#define MAP_COUNT	6
#define MAX_PORTS       50

/* Path at which BPF maps are pinned */
const char *pin_basedir = "/sys/fs/bpf";
const char *pin_subdir	= "ratelimiting";

/* Map that stores the ratelimit configuration */
const char *rl_config_map = "rl_config_map";

/* Map that maintains the window start timestamp and the connections received
 * in this window(next 1 sec). */
const char *rl_window_map = "rl_window_map";

/* Map that mainatains total number of incoming connections */
const char *rl_recv_count_map = "rl_recv_count_map";

/* Map that maintains the total number of dropped connnections as the *
 * ratelimit hits */
const char *rl_drop_count_map = "rl_drop_count_map";

/* Map that stores the ports list */
const char *rl_ports_map = "rl_ports_map";

/* XDP program that would be injected in the kernel */
const char *xdp_prog = "ratelimiting";

/* XDP program that is next in the chain */
const char *xdp_rl_ingress_next_prog = "xdp_rl_ingress_next_prog";

/* Buffer time(in sec) to hold the map elements, after which they get deleted */
const int buffer_time = 10;

/* Port separator */
const char delim[] = ",";

#endif
