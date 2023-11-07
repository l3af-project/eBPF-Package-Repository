// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

static const char *__doc__=" BPF IPFIX : To get packet flow data by handling the packet and create IPFIX.\n\n";

#include "bpf_ipfix_user.h"
#include <unistd.h>

#define EGRESS 1
#define MAX_FILENAME_LENGTH 256

/* Exit return codes */
#define EXIT_OK                 0
#define EXIT_FAIL               1

/* Ingress Specific variables */
char if_name[IF_NAMESIZE];
char *egress_log_file_path = "/var/log/l3af/egress_ipfix.log";

void sig_handler(int signo)
{
    log_info("Received shutdown signal, cleaning up");
    flow_record_poll(egress_fd, last_egress_fd, EGRESS);
    log_info("Cleaned up");
    close_logfile();
    exit(EXIT_SUCCESS);
}

int populate_egress_fds(void) {
    char map_file[MAP_PATH_SIZE];
    if (get_bpf_map_file(if_name, egress_bpf_map, map_file) < 0) {
        fprintf(stderr, "ERROR: map file path (%s) doesn't exists", map_file);
        return EXIT_FAILURE;
    }

    egress_fd = bpf_obj_get(map_file);
    if (egress_fd < 0) {
        fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s)",
                        egress_bpf_map);
        close_logfile();
        return EXIT_FAILURE;
    }

    if (get_bpf_map_file(if_name, last_egress_bpf_map, map_file) < 0) {
        fprintf(stderr, "ERROR: map file path (%s) doesn't exists", map_file);
        return EXIT_FAILURE;
    }
    last_egress_fd = bpf_obj_get(map_file);
    if (last_egress_fd < 0) {
        fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s)", last_egress_bpf_map);
        close_logfile();
        return EXIT_FAILURE;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int  opt = 0, long_index = 0;
    verbosity = LOG_INFO;
    long flow_timeout = 0;
    char *eptr;
    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq",
                  long_options, &long_index)) != -1) {
        switch (opt) {
            case 'q':
                if(optarg)
                    verbosity = (int)(strtol(optarg, &eptr, 10));
		break;
            case 'i':
                if (!validate_ifname(optarg, (char *)&if_name)) {
                    fprintf(stderr, "ERR: input --interface ifname invalid\n");
                    return EXIT_FAILURE;
                }
                if_idx = if_nametoindex(if_name);
                if (!(if_idx)){
                    fprintf(stderr, "ERR: --interfaces \"%s\" not real dev",
                        if_name);
                    return EXIT_FAILURE;
                }
                break;
            case 'c':
                if(optarg)
                    remote_ip = optarg;
                break;
            case 't':
                if(optarg) {
                    flow_timeout = strtol(optarg, &eptr, 10);
                    flow_timeout_counter = flow_timeout / 10;
		}
                break;
            case 'p':
                if(optarg)
                    remote_port = (int)(strtol(optarg, &eptr, 10));
                break;
            case 'd':
		break;
            case 'h':
            default:
                usage(argv, __doc__);
                return EXIT_FAILURE;
        }
    }

    info = set_logfile(egress_log_file_path);
    if(info == NULL) {
        verbosity = 0;
        fprintf(stderr, "LOG file is not set. Please verify logfile path");
        return EXIT_FAILURE;
    }

    if (populate_egress_fds() == EXIT_FAILURE) {
        fprintf(stderr, "ERR: Fetching TC EGRESS maps failed\n");
        close_logfile();
        return EXIT_FAILURE;
    }
    if (remote_ip == NULL) {
        log_err("Remote IP is not configured by user, Please provide the remote ip");
        close_logfile();
        return EXIT_FAILURE;
    }

    if (signal(SIGINT, sig_handler) ||
        signal(SIGHUP, sig_handler) ||
        signal(SIGTERM, sig_handler)) {
        perror("signal");
        return EXIT_FAIL;
    }

    while(true) {
        log_debug("Sleeping for 10 sec");
        sleep(10);
        flow_record_poll(egress_fd, last_egress_fd, EGRESS);
    }
    return EXIT_OK;
}
