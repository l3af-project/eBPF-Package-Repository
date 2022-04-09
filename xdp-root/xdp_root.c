// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* XDP root program */
static const char *__doc__ =
        "  XDP: First program used to chain\n"
        "  The bpf-object gets attached via XDP\n";

#include <linux/bpf.h>
#ifdef __linux__
#include <linux/if_link.h>
#include <net/if.h>
#endif
#include <stdio.h>
#ifdef __linux__
#include <unistd.h>
#endif
#include <getopt.h>
#ifdef __linux__
#include <sys/resource.h>
#endif

#include "bpf_load.h"
#ifdef __linux__
#include "bpf_util.h"
#endif
#ifdef WIN32
#include <winsock2.h>
#include <netioapi.h>
#include <stdlib.h>
#include "bpf/libbpf.h"
#define ebpf_obj_unpin ebpf_object_unpin
#endif
#include <bpf/bpf.h>

static int ifindex_in;

static __u32 xdp_flags;

static const char *prog_root_pass_file = "/sys/fs/bpf/xdp_root_pass_array";
static const char *prog_root_file = "/sys/fs/bpf/xdp_root_array";

static const struct option long_options[] = {
        {"help",        no_argument,            NULL, 'h' },
        {"iface",      	required_argument,      NULL, 'i' },
        {"cmd",     	required_argument,      NULL, 'c' },
        {"direction",   optional_argument,      NULL, 'd'},
        {0, 0, NULL,  0 }
};

static void stop()
{
    bpf_set_link_xdp_fd(ifindex_in, -1, xdp_flags);

    // remove map file
    remove(prog_root_pass_file);
    remove(prog_root_file);

    exit(EXIT_SUCCESS);
}

static void usage(char *argv[])
{
    int i;
    printf("\nDOCUMENTATION:\n%s\n", __doc__);
    printf("\n");
    printf(" Usage: %s (options-see-below)\n", argv[0]);
    printf(" Listing options:\n");
    for (i = 0; long_options[i].name != 0; i++) {
        printf(" --%-15s", long_options[i].name);
        if (long_options[i].flag != NULL)
            printf(" flag (internal value:%d)", *long_options[i].flag);
        else
            printf("(internal short-option: -%c)", long_options[i].val);
        printf("\n");
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    char filename[256];
    int opt = 0, fd = -1;
    char *cmd = NULL;
    char *iface = NULL;
    int longindex = 0;
#ifdef __linux__
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
#endif

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq",
              long_options, &longindex)) != -1) {
        switch (opt) {
            case 'c':
                cmd = optarg;
                if (!((strcmp(cmd, "start") == 0) || (strcmp(cmd, "stop") == 0))) {
                    usage(argv);
                    return EXIT_FAILURE;
                }
                break;
            case 'i':
                iface = optarg;
                break;
            case 'd':
                break;
            default:
                usage(argv);
                return EXIT_FAILURE;
        }
    }

    if (cmd == NULL || iface == NULL) {
        usage(argv);
	    return EXIT_FAILURE;
    }

    ifindex_in = if_nametoindex(iface);
#ifdef _WIN32
    _splitpath_s(argv[0], NULL, 0, NULL, 0, filename, sizeof(filename), NULL, 0);
    strcat_s(filename, sizeof(filename), "_kern.o");
#endif
#ifdef __linux__
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    if (setrlimit(RLIMIT_MEMLOCK, &r) < 0) {
	    perror("setrlimit failed");
    }
#endif

    if (strcmp(cmd,"start") == 0) {
        if (load_bpf_file(filename)) {
            fprintf(stderr, "%s", bpf_log_buf);
            return EXIT_FAILURE;
        }
        if (!prog_fd[0]) {
            printf("load_bpf_file: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        if (bpf_set_link_xdp_fd(ifindex_in, prog_fd[0], xdp_flags) < 0) {
            fprintf(stderr, "ERROR: link set xdp fd failed on %d\n", ifindex_in);
            return EXIT_FAILURE;
        }

        fd = bpf_obj_get(prog_root_pass_file);
        if (fd < 0) {
            fprintf(stderr, "Didn't get the pinned file, creating one\n");
            if (bpf_obj_pin(map_fd[0], prog_root_pass_file)) {
                fprintf(stderr,"bpf_obj_pin - failed on map %s\n", prog_root_pass_file);
                    if (bpf_set_link_xdp_fd(ifindex_in, -1, xdp_flags) < 0) {
                        fprintf(stderr, "ERROR: unlink xdp fd failed on %d\n", ifindex_in);
                    }
                    return EXIT_FAILURE;
            }
        }

        // Verify and chain the pass through program
        if (!prog_fd[1]) {
            fprintf(stderr, "load_bpf_file pass-through: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        /* Update pass through prog fd in the root prog map fd,
         * so it can chain the current one */
         __u64 pkey = 0;
        if (bpf_map_update_elem(map_fd[0], &pkey, &(prog_fd[1]), 0)) {
            fprintf(stderr, "Failed to update root pass through fd in the chain\n");
            exit(EXIT_FAILURE);
        }

        fd = bpf_obj_get(prog_root_file);
        if (fd < 0) {
            fprintf(stderr, "Didn't get the pinned file, creating one\n");
            if (bpf_obj_pin(map_fd[1], prog_root_file)) {
                fprintf(stderr,"bpf_obj_pin - failed on map %s\n", prog_root_file);
                if (bpf_set_link_xdp_fd(ifindex_in, -1, xdp_flags) < 0) {
                    fprintf(stderr, "ERROR: unlink xdp fd failed on %d\n", ifindex_in);
                }
                // remove root pass map file
                remove(prog_root_pass_file);
                return EXIT_FAILURE;
            }
        }
   }
   else {
        stop();
   }
   return EXIT_SUCCESS;
}
