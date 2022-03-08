// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* XDP sample program */
static const char *__doc__ =
        "  Sample xdp program used to chain\n"
        "  The bpf-object gets attached via XDP\n";

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/resource.h>

#include "bpf_load.h"
#include "bpf_util.h"
#include <bpf/bpf.h>

static int ifindex_in;

static const char *xdp_next_prog_file = "/sys/fs/bpf/xdp_next_prog_array";
static char prev_prog_map[1024];
static const struct option long_options[] = {
        {"help",        no_argument,            NULL, 'h' },
        {"iface",      	required_argument,      NULL, 'i' },
        {"direction",   optional_argument,      NULL, 'd'},
        {"map-name",  optional_argument,  NULL, 'm' },
        {0, 0, NULL,  0 }
};


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

/* This method to unlink the program from the chain */
static int xdp_unlink_bpf_chain(const char *map_filename) {
    int ret = 0;
    int key = 0;
    int map_fd = bpf_obj_get(map_filename);
    if (map_fd > 0) {
       ret = bpf_map_delete_elem(map_fd, &key);
       if (ret != 0) {
           fprintf(stderr, "xdp chain remove program failed");
       }
    }
    else {
       fprintf(stderr, "Previous program's map is not found %s", map_filename);
    }

    if (remove(xdp_next_prog_file) < 0) {
        fprintf(stderr, "Failed to remove map file - xdp_next_prog_file");
    }

    return ret;
}

/* Unlink xdp kernel program on receiving KILL/INT signals */
static void signal_handler(int signal)
{
    printf("Received signal %d", signal);

    xdp_unlink_bpf_chain(prev_prog_map);
    close(map_fd[0]);

    exit(EXIT_SUCCESS);
}

static int get_length(const char *str)
{
    int len = 0;
    if (*str == '\0')
        return 0;
    while (str[len] != '\0')
       len++;

   return len;
}


int main(int argc, char **argv)
{
    char filename[256];
    int opt = 0, len=0;
    char *iface = NULL;
    int longindex = 0;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq",
              long_options, &longindex)) != -1) {
        switch (opt) {
            case 'i':
                iface = optarg;
                break;
            case 'd': /* Direction variable passed by l3afd */
                break;
            case 'm':
                if(optarg) { /* Previous ebpf program's map name to chain */
                    len = get_length(optarg);
                    strncpy(prev_prog_map, optarg, len);
                    prev_prog_map[len] = '\0';
                }
                break;

            default:
                usage(argv);
                return EXIT_FAILURE;
        }
    }

    ifindex_in = if_nametoindex(iface);
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    if (setrlimit(RLIMIT_MEMLOCK, &r) < 0) {
	    perror("setrlimit failed");
    }

    if (load_bpf_file(filename)) {
        fprintf(stderr, "%s", bpf_log_buf);
        return EXIT_FAILURE;
    }
    if (!prog_fd[0]) {
        printf("load_bpf_file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
     /* Get the previous program's map fd in the chain */
    int prev_prog_map_fd = bpf_obj_get(prev_prog_map);
    if (prev_prog_map_fd < 0) {
        fprintf(stderr, "Failed to fetch previous xdp function in the chain");
        exit(EXIT_FAILURE);
    }

    /* Update current prog fd in the last prog map fd,
     * so it can chain the current one */
    int pkey=0;
    if(bpf_map_update_elem(prev_prog_map_fd, &pkey, &(prog_fd[0]), 0)) {
        fprintf(stderr,"Failed to update prog fd in the chain");
        exit(EXIT_FAILURE);
    }
     /* closing map fd to avoid stale map */
     close(prev_prog_map_fd);

    int next_prog_map_fd = bpf_obj_get(xdp_next_prog_file);
    if (next_prog_map_fd < 0) {
        printf("Failed to fetch next prog map fd, creating one");
        if (bpf_obj_pin(map_fd[0], xdp_next_prog_file)) {
            printf("Failed to pin next prog fd map");
            exit(EXIT_FAILURE);
        }
    }

    /* Handle signals and exit clean */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    while(1)
    {
        sleep(60);
    }

   return EXIT_SUCCESS;
}
