// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2016 John Fastabend <john.r.fastabend@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>

#include "bpf_load.h"
#include "bpf_util.h"
#include <bpf/bpf.h>

static int ifindex_in;

static __u32 xdp_flags;

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] IFINDEX_IN IFINDEX_OUT\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		"    -N    enforce native mode\n",
		prog);
}


int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	const char *optstr = "SN";
	char filename[256];
	int opt, key = 0;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'N':
			xdp_flags |= XDP_FLAGS_DRV_MODE;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (optind == argc) {
		printf("usage: %s IFINDEX_IN IFINDEX_OUT\n", argv[0]);
		return 1;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	ifindex_in = if_nametoindex(argv[optind]);

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	if (!prog_fd[0]) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	const char *prog_file = "/sys/fs/bpf/map_1";
	int root_fd = -1;
	root_fd = bpf_obj_get(prog_file);
        if (root_fd < 0) {
            printf("Didn't get the pinned file, creating one\n");
	    if (bpf_obj_pin(map_fd[0], prog_file)) {
                printf("bpf_obj_pin failed\n");
                goto out;
            }
        }

	const char *map_file = "/sys/fs/bpf/root_array";
	int map_fd = -1;
	map_fd = bpf_obj_get(map_file);
	if (map_fd < 0) {
		printf("Didn't get the pinned file\n");
		goto out;
	}
	int tmp_fd = prog_fd[0];
	int ret = bpf_map_update_elem(map_fd, &key, &tmp_fd, 0);
	if (ret) {
		printf("Update map failed\n");
		goto out;
	}
out:
	return 0;
}
