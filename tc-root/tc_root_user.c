// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* TC root program */
static const char *__doc__ =
        "  TC: First program used to chain\n"
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
#include <sys/types.h>
#include <sys/wait.h>
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

#define INGRESS_SEC "tc-ingress-root"
#define INGRESS_PASS_SEC "tc-ingress-pass-through"
#define EGRESS_SEC "tc-egress-root"
#define EGRESS_PASS_SEC "tc-egress-pass-through"

static char ifname[IF_NAMESIZE];
static int ifindex;
static int verbose = 0;
static char tc_cmd[CMD_MAX_TC] = "tc";

static const char *tc_root_ingress_map_file = "/sys/fs/bpf/tc/globals/tc_ingress_root_array";
static const char *tc_root_egress_map_file = "/sys/fs/bpf/tc/globals/tc_egress_root_array";
static const char *tc_root_ingress_pass_map_file = "/sys/fs/bpf/tc/globals/tc_ingress_root_pass_array";
static const char *tc_root_egress_pass_map_file = "/sys/fs/bpf/tc/globals/tc_egress_root_pass_array";
int exec_cmd(char *cmd[]);
/*
 * TC require attaching the bpf-object via the TC cmdline tool.
 *
 * Manually like:
 *  $TC qdisc   add dev $DEV clsact
 *  $TC filter  add dev $DEV ingress | egress bpf da obj $BPF_OBJ sec dscp_tag_set
 *  $TC filter show dev $DEV ingress | egress
 *  $TC filter  del dev $DEV ingress | egress
 *
 * (The tc "replace" command does not seem to work as expected)
 */

static void verbose_output(char *cmd[]) {
    if (cmd == NULL || cmd[0] == NULL) {
        return;
    }

    fprintf(stdout, "Run : ");
    int i=0;
    while(cmd[i] != NULL) {
        fprintf(stdout, "%s ",cmd[i]);
        ++i;
    }
    fprintf(stdout, "\n");

    return;
}

static void tc_attach_bpf(const char *dev) {
    char *cmd[] = {tc_cmd, "qdisc", "add", "dev", dev, "clsact", (char *)0};
    int ret = 0;

    ret = exec_cmd(cmd);

    if (ret && verbose) {
        fprintf(stderr,
                "ERR(%d): tc cannot attach qdisc hook\n",
                WEXITSTATUS(ret));
    }

    return;
}

static int tc_add_filter(const char *dev, const char *flow_dir, const char *bpf_obj, const char *sec) {
    char *cmd[] = {tc_cmd,"filter", "add", "dev", (void *)dev, (void *)flow_dir, "prio","1",
                   "handle","1","bpf", "da","obj", (void *)bpf_obj,"sec",(void *)sec, (char *)0};
    int ret = 0;

    ret = exec_cmd(cmd);

    if (ret) {
        fprintf(stderr,
                "ERR(%d): tc cannot attach filter\n",
                WEXITSTATUS(ret));
    }

    return ret;
}

// This method is to link the current program fd with previous program map.
static int  tc_chain_bpf(const char *map_name, const char *bpf_obj, const char *sec) {
    char *cmd[] = {tc_cmd, "exec", "bpf", "graft", (void *)map_name, "key", "0", "obj", (void *)bpf_obj, "sec", (void *)sec,(char *)0};
    int ret = 0;

    ret = exec_cmd(cmd) ;
    if (ret) {
        fprintf(stderr, "tc chain bpf program failed");
    }

    return ret;
}

static int tc_list_filter(const char *dev, const char *flow_dir) {
    char *cmd[] = {tc_cmd, "filter", "show", "dev", (void *)dev, (void *)flow_dir, (char *)0};
    int ret = 0;

    ret = exec_cmd(cmd);
    if (ret) {
        fprintf(stderr, "ERR(%d): tc cannot list filters\n", ret);
        exit(EXIT_FAILURE);
    }
    return ret;
}

static int tc_remove_filter(const char *dev, const char *flow_dir, const char *map_file) {
    char *cmd[] = {tc_cmd, "filter", "delete", "dev", (void *)dev, (void *)flow_dir, (char *)0};
    int ret = 0;

    ret = exec_cmd(cmd);
    if (ret) {
        fprintf(stderr, "ERR(%d): tc cannot remove filters\n", ret);
        exit(EXIT_FAILURE);
    }

    // remove map file
    remove(map_file);

    return ret;
}

// This method to unlink the pass through program
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
        {"cmd",       required_argument, NULL, 'c'},
        {"direction", optional_argument, NULL, 'd'},
        {"list",      optional_argument, NULL, 'l'},
        {"verbose",   optional_argument, NULL, 'v'},
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


int exec_cmd(char *cmd[])
{
    int pid, status, ret = 0;
    if (verbose) verbose_output(cmd);

    pid = fork();
    if (pid > 0) {
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            fprintf(stderr, "Child process exited with status %d", status);
        }
    } else if (pid == 0) {
        ret = execvp(cmd[0], cmd);
        if (ret < 0) {
            perror("Command execution failed");
            return ret;
        }
    }
    return ret;
}


int main(int argc, char **argv) {
    char ingress_filename[256];
    char egress_filename[256];

    char iface_flow_dir[10]; // Store ingress or egress
    enum iface_dir direction = INGR_N_EGR;
    char *cmd = NULL;

    bool list_tc_filter = false;
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
            case 'd':
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
            case 'c' :
                cmd = optarg;
                if (!((strcmp(cmd, "start") == 0) || (strcmp(cmd, "stop") == 0))) {
                    usage(argv);
                    return EXIT_FAILURE;
                }
                break;
            case 'l':
                list_tc_filter = true;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
            default:
                usage(argv);
                return EXIT_FAILURE;
        }
    }

    if (cmd && strcmp(cmd, "start") == 0) {
        tc_attach_bpf(ifname);
        switch (direction) {
            case INGR:
                if (tc_add_filter(ifname, INGRESS, ingress_filename, INGRESS_SEC) != 0) {
                    fprintf(stderr, "ERR: tc add filter ingress failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_chain_bpf(tc_root_ingress_pass_map_file, ingress_filename, INGRESS_PASS_SEC) != 0) {
                    fprintf(stderr, "tc pass through chaining ingress failed\n");
                    return EXIT_FAILURE;
                }
                break;
            case EGR:
                if (tc_add_filter(ifname, EGRESS, egress_filename, EGRESS_SEC) != 0) {
                    fprintf(stderr, "ERR: tc add filter egress failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_chain_bpf(tc_root_egress_pass_map_file, egress_filename, EGRESS_PASS_SEC) != 0) {
                    fprintf(stderr, "tc pass through chaining egress failed\n");
                    return EXIT_FAILURE;
                }
                break;
            default:
                if (tc_add_filter(ifname, INGRESS, ingress_filename, INGRESS_SEC) != 0) {
                    fprintf(stderr, "ERR: tc add filter ingress failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_chain_bpf(tc_root_ingress_pass_map_file, ingress_filename, INGRESS_PASS_SEC) != 0) {
                    fprintf(stderr, "tc pass through chaining ingress failed\n");
                    return EXIT_FAILURE;
                }
                if (tc_add_filter(ifname, EGRESS, egress_filename, EGRESS_SEC) != 0) {
                    fprintf(stderr, "ERR: tc add filter egress failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_chain_bpf(tc_root_egress_pass_map_file, egress_filename, EGRESS_PASS_SEC) != 0) {
                    fprintf(stderr, "tc pass through chaining egress failed\n");
                    return EXIT_FAILURE;
                }
                break;
        }
    } else if (cmd && strcmp(cmd, "stop") == 0) {
        if (verbose)
            printf("TC remove %s filters on device %s\n", iface_flow_dir, ifname);
        switch (direction) {
            case INGR:
                if (tc_remove_chain(tc_root_ingress_pass_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove chain root ingress pass through failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_remove_filter(ifname, INGRESS, tc_root_ingress_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove filter ingress failed \n");
                    return EXIT_FAILURE;
                }
                break;
            case EGR:
                if (tc_remove_chain(tc_root_egress_pass_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove chain root egress pass through failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_remove_filter(ifname, EGRESS, tc_root_egress_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove filter egress failed \n");
                    return EXIT_FAILURE;
                }
                break;
            default: //both
                if (tc_remove_chain(tc_root_ingress_pass_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove chain root ingress pass through failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_remove_filter(ifname, INGRESS, tc_root_ingress_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove filter ingress failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_remove_chain(tc_root_egress_pass_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove chain root egress pass through failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_remove_filter(ifname, EGRESS, tc_root_egress_map_file) != 0) {
                    fprintf(stderr, "ERR: tc remove filter egress failed \n");
                    return EXIT_FAILURE;
                }
                break;
        }
    } else if (list_tc_filter) {
        printf("TC list %s filters on device %s\n", iface_flow_dir, ifname);
        switch (direction) {
            case INGR:
                if (tc_list_filter(ifname, INGRESS) != 0) {
                    fprintf(stderr, "ERR: tc list filter ingress failed \n");
                    return EXIT_FAILURE;
                }
                break;
            case EGR:
                if (tc_list_filter(ifname, EGRESS) != 0) {
                    fprintf(stderr, "ERR: tc list filter egress failed \n");
                    return EXIT_FAILURE;
                }
                break;
            default: // both
                if (tc_list_filter(ifname, INGRESS) != 0) {
                    fprintf(stderr, "ERR: tc list filter ingress failed \n");
                    return EXIT_FAILURE;
                }
                if (tc_list_filter(ifname, EGRESS) != 0) {
                    fprintf(stderr, "ERR: tc list filter egress failed \n");
                    return EXIT_FAILURE;
                }
                break;
        }
    } else {
        fprintf(stderr, "ERR: missing cmd option --cmd \n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
