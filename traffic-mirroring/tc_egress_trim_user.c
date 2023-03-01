// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* TC program to trim TCP/UDP packets
 */
static const char *__doc__=
 " TC redirect benchmark\n\n"
 "  The bpf-object gets attached via TC cmdline tool\n"
;

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>

#include <getopt.h>
#include <net/if.h>
#include <time.h>

#include "bpf_util.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

static int verbose = 1;

#define CMD_MAX 	2048
#define CMD_MAX_TC	256
static char tc_cmd[CMD_MAX_TC] = "tc";
static char *tc = "tc";

static const struct option long_options[] = {
    {"help",    	no_argument,		NULL, 'h' },
    {"interface",	required_argument,	NULL, 'i' },
    /* Allow specifying tc cmd via argument */
    {"tc-cmd",		required_argument,	NULL, 't' },
    /* HINT assign: optional_arguments with '=' */
    {"list",		optional_argument,	NULL, 'l' },
    {"remove",		optional_argument,	NULL, 'r' },
    {"quiet",		no_argument,		NULL, 'q' },
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

/*
 * TC require attaching the bpf-object via the TC cmdline tool.
 *
 * Manually like:
 *  $TC qdisc   del dev $DEV clsact
 *  $TC qdisc   add dev $DEV clsact
 *  $TC filter  add dev $DEV egress bpf da obj $BPF_OBJ sec trim
 *  $TC filter show dev $DEV egress
 *  $TC filter  del dev $DEV egress
 *
 * (The tc "replace" command does not seem to work as expected)
 */
static int tc_egress_attach_bpf(const char* dev, const char* bpf_obj)
{
    char cmd[CMD_MAX];
    int ret = 0;
    int pid, status, childpid; 
#if 0
    /* Step-1: Delete clsact, which also remove filters */
    /* TODO Delete only this specific filter, not the entire device */
    memset(&cmd, 0, CMD_MAX);
    snprintf(cmd, CMD_MAX,
         "%s qdisc del dev %s clsact 2> /dev/null",
         tc_cmd, dev);
    if (verbose) printf(" - Run: %s\n", cmd);
    ret = system(cmd);
    if (!WIFEXITED(ret)) {
        fprintf(stderr,
            "ERR(%d): Cannot exec tc cmd\n Cmdline:%s\n",
            WEXITSTATUS(ret), cmd);
        exit(EXIT_FAILURE);
    } else if (WEXITSTATUS(ret) == 2) {
        /* Unfortunately TC use same return code for many errors */
        if (verbose) printf(" - (First time loading clsact?)\n");
    }

    /* Step-2: Attach a new clsact qdisc */
    /* TODO Add the device only if it is not existing */
    memset(&cmd, 0, CMD_MAX);
    snprintf(cmd, CMD_MAX,
         "%s qdisc add dev %s clsact",
         tc_cmd, dev);
    if (verbose) printf(" - Run: %s\n", cmd);
    ret = system(cmd);
    if (ret) {
        fprintf(stderr,
            "ERR(%d): tc cannot attach qdisc hook\n Cmdline:%s\n",
            WEXITSTATUS(ret), cmd);
        exit(EXIT_FAILURE);
    }
#endif

    /* Step-3: Attach BPF program/object as egress filter */
    char *filter_cmd[] = {tc, "filter", "add", "dev", dev, "egress",
           "prio", "1", "handle", "1", "bpf", "da", "obj", bpf_obj, "sec", trim, (char*)0}
    pid = fork();
    if(pid > 0) {
        childpid = waitpid(pid, &status, NULL);
        if(WIFEXITED(status))  {
             log_info("Child process exited with status %d", status);
        }
    } else if(pid == 0) {
        ret = execvp(filter_cmd[0], filter_cmd) ;
        if( ret < 0) {
            /* Exit with failed status*/
            perror("tc filter attach failed");
            fprintf(stderr,
              "ERR(%d): tc cannot attach filter\n",
               WEXITSTATUS(ret));
            exit(EXIT_FAILURE);
        }
    }
    return ret;
}

static int tc_list_egress_filter(const char* dev)
{
    /* TODO: Will add tc list filter support */  
    return 0;
}

int tc_cmd_filter(const char* dev, char* action)
{
    int ret = 0;
    int pid, status, childpid;

    char *filter_cmd[] = {tc , "filter", action, "dev", dev, "egress", (char*)0};
    /* Show tc filter */
    pid = fork();
    if(pid > 0) {
        childpid = waitpid(pid, &status, NULL);
        if(WIFEXITED(status))  {
             log_info("Child process exited with status %d", status);
        }
    } else if(pid == 0) {
        ret = execvp(filter_cmd[0], filter_cmd) ;
        if( ret < 0) {
            /* Exit with failed status*/
            log_err( "ERR(%d): tc cannot %s filters", action);
            perror("tc command failed");
            close_logfile();
            exit(EXIT_FAILURE);
        }
    }
    return ret;
}

int tc_remove_filter(const char* dev)
{
    int ret;
    ret = tc_cmd_filter(dev, "del");
    return ret;
}

static char ifname[IF_NAMESIZE];
static char buf_ifname[IF_NAMESIZE] = "(unknown-dev)";

void cpy(char* dst, char* src) {
    while ((*src) != '\0') {
        *dst++ = *src++;
    }
    *dst = '\0';
}

bool validate_ifname(const char* input_ifname, char *output_ifname)
{
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
    cpy(output_ifname, input_ifname);
    return true;
}

int main(int argc, char **argv)
{
    bool list_egress_tc_filter = false, remove_egress_tc_filter = false;
    int longindex = 0, opt, fd = -1;
    int ifindex = 0;
    int ret = EXIT_SUCCESS;
    size_t len;

    char bpf_obj[256];
    snprintf(bpf_obj, sizeof(bpf_obj), "%s_kern.o", argv[0]);

    memset(ifname, 0, IF_NAMESIZE); /* Can be used uninitialized */

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq",
                  long_options, &longindex)) != -1) {
        switch (opt) {
        case 'i':
            if (!validate_ifname(optarg, (char *)&ifname)) {
                fprintf(stderr,
                  "ERR: input --interface ifname invalid\n");
            }
            if (!(ifindex= if_nametoindex(ifname))){
                fprintf(stderr,
                    "ERR: --interface \"%s\" not real dev\n",
                    ifname);
                return EXIT_FAILURE;
            }
            break;
        case 'l':
            /* --list use --egress ifname if specified */
            if (optarg && !validate_ifname(optarg,(char *)&ifname)) {
                fprintf(stderr, "ERR: input --list=ifname invalid\n");
                return EXIT_FAILURE;
            }
            if (get_length(ifname) == 0) {
                fprintf(stderr, "ERR: need input --list=ifname\n");
                return EXIT_FAILURE;
            }
            list_egress_tc_filter = true;
            break;
        case 'r':
            /* --remove use --interface ifname if specified */
            if (optarg && !validate_ifname(optarg,(char *)&ifname)) {
                fprintf(stderr, "ERR: input --remove=ifname invalid\n");
                return EXIT_FAILURE;
            }
            if (get_length(ifname) == 0) {
                fprintf(stderr, "ERR: need input --list=ifname\n");
                return EXIT_FAILURE;
            }
            remove_egress_tc_filter = true;
            break;
        case 't':
            len = get_length(optarg);
            if (len >= CMD_MAX_TC) {
                return EXIT_FAILURE;
            }
            cpy(tc_cmd, optarg);
            break;
        case 'q':
            verbose = 0;
            break;
        case 'h':
        default:
            usage(argv);
            return EXIT_FAILURE;
        }
    }

    if (ifindex) {
        if (verbose)
            printf("TC attach BPF object %s to device %s\n",
                   bpf_obj, ifname);
        if (tc_egress_attach_bpf(ifname, bpf_obj)) {
            fprintf(stderr, "ERR: TC attach failed\n");
            exit(EXIT_FAILURE);
        }
    }

    if (list_egress_tc_filter) {
        if (verbose)
            printf("TC list egress filters on device %s\n", ifname);
        tc_list_egress_filter(ifname);
    }

    if (remove_egress_tc_filter) {
        if (verbose)
            printf("TC remove egress filters on device %s\n", ifname);
        tc_remove_egress_filter(ifname);
        return EXIT_SUCCESS;
    }

    return ret;
}

char _license[] SEC("license") = "Dual BSD/GPL";
