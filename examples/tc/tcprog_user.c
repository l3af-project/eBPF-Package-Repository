// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* TC sample program */
static const char *__doc__ =
        "  Sample TC program used to chain\n"
        "  The bpf-object gets attached via TC cmdline tool\n";

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include "bpf_util.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "bpf_load.h"

#define CMD_MAX          2048
#define CMD_MAX_TC       256

#define INGRESS "ingress"
#define EGRESS  "egress"

enum iface_dir {
    INGR_N_EGR = 0,
    INGR = 1,
    EGR = 2
};

enum iface_dir direction;

#define INGRESS_SEC "tc-ingress"
#define EGRESS_SEC "tc-egress"

static char ifname[IF_NAMESIZE];
static int ifindex;
static char tc_cmd[CMD_MAX_TC] = "tc";
static char prev_prog_map[1024];

/* This method is to link the current program fd with previous program map. */
static int  tc_chain_bpf(const char *map_name, const char *bpf_obj, const char *sec) {
    char cmd[CMD_MAX];
    int ret = 0;

    memset(&cmd, 0, CMD_MAX);
    snprintf(cmd, CMD_MAX,
             "%s exec bpf graft %s key 0 obj %s sec %s",
             tc_cmd, map_name, bpf_obj, sec);

    printf(" - Run: %s\n", cmd);
    ret = system(cmd);

    if (ret) {
        fprintf(stderr, "tc chain bpf program Cmdline:%s",cmd);
    }

    return ret;
}

/* This method to unlink the bpf program from the chain */
static int tc_remove_chain(const char *map_file) {
    int ret;
    int key = 0;
    int map_fd = bpf_obj_get(map_file);
    if (map_fd < 0) {
        fprintf(stderr,"map_fd of map not found: %s\n", map_file);
        return -1;
    }

    ret = bpf_map_delete_elem(map_fd, &key);
    if (ret != 0) {
        fprintf( stderr, "tc chain remove pass through program failed");
    }

    // close map handle
    close(map_fd);
    
   // remove map file
    remove(map_file);
    return ret;
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

static bool validate_ifname(const char *input_ifname, char *output_ifname) {
    size_t len;
    int i;

    len = get_length(input_ifname);
    if (len >= IF_NAMESIZE) {
        return false;
    }
    for (i = 0; i < len; i++) {
        char c = input_ifname[i];

        if (!(isalpha(c) || isdigit(c)))
            return false;
    }
    strncpy(output_ifname, input_ifname, len);
    output_ifname[len] = '\0';
    return true;
}

static const struct option long_options[] = {
        {"help",      no_argument,       NULL, 'h'},
        {"iface",     required_argument, NULL, 'i'},
        {"direction", optional_argument, NULL, 'd'},
        {"map-name",   optional_argument, NULL, 'm'},
        {0,           0,                 NULL, 0}
};

static void usage(char *argv[]) {
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

static void signal_handler(int signo)
{
    printf("Received signal %d", signo);

    tc_remove_chain(prev_prog_map);

    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    char ingress_filename[256];
    char egress_filename[256];

    char iface_flow_dir[10]; // Store ingress or egress

    int opt = 0, long_index = 0, len = 0;

    memset(iface_flow_dir, '\0', sizeof(iface_flow_dir));
    memset(ifname, 0, IF_NAMESIZE);

    snprintf(ingress_filename, sizeof(ingress_filename), "%s_ingress_kern.o", argv[0]);
    snprintf(egress_filename, sizeof(egress_filename), "%s_egress_kern.o", argv[0]);

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq",
                              long_options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                if (!validate_ifname(optarg, (char *) &ifname)) {
                    fprintf(stderr,
                            "ERR: input --iface ifname invalid\n");
                }
                if (!(ifindex = if_nametoindex(ifname))) {
                    fprintf(stderr,
                            "ERR: --iface \"%s\" not real dev\n", ifname);
                    return EXIT_FAILURE;
                }
                break;
            case 'd': /* Direction variable passed by l3afd */
                if (!optarg) {
                    fprintf(stderr, "ERR: --direction unknown value\n");
                    return EXIT_FAILURE;
                }
                len = get_length(optarg);
                strncpy(iface_flow_dir, optarg, len);
                iface_flow_dir[len]  = '\0';

                if (strcasecmp(iface_flow_dir, INGRESS) == 0) {
                    direction = INGR;
                } else if (strcasecmp(iface_flow_dir, EGRESS) == 0) {
                    direction = EGR;
                } else {
                    fprintf(stderr, "ERR: --direction \"%s\" unknown value\n", iface_flow_dir);
                    return EXIT_FAILURE;
                }
                break;
            case 'm':
                if(optarg) { /* Previous ebpf program's map name to chain */
                     len = get_length(optarg);
                     strncpy(prev_prog_map, optarg, len);
                     prev_prog_map[len] = '\0';
                 }
                 break;
            case 'h':
            default:
                usage(argv);
                return EXIT_FAILURE;
        }
    }

    switch (direction) {
        case INGR:
           if (tc_chain_bpf(prev_prog_map, ingress_filename, INGRESS_SEC) != 0) {
                fprintf(stderr, "tc program chaining ingress failed\n");
                return EXIT_FAILURE;
            }
            break;
        case EGR:
           if (tc_chain_bpf(prev_prog_map, egress_filename, EGRESS_SEC) != 0) {
                fprintf(stderr, "tc program chaining egress failed\n");
                return EXIT_FAILURE;
            }
            break;
        default:
            printf("Unknown direction\n");
            break;
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
