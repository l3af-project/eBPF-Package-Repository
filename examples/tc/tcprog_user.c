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
#include <stdlib.h> 
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

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

        if (!(isalpha(c) || isdigit(c) || c == '-'))
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
            case 'h':
            default:
                usage(argv);
                return EXIT_FAILURE;
        }
    }

    /* Handle signals and exit clean */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    while(1)
    {
        /* business logic */
        sleep(60);
    }

    return EXIT_SUCCESS;
}
