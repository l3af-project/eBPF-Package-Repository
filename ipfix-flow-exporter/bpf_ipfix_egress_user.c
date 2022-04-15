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

const char egress[] = "egress_flow_monitoring";
extern FILE *info;
extern int verbosity;

/* Ingress Specific variables */
bool attach_tc_egress_filter = false;
char if_name[IF_NAMESIZE];
char *egress_log_file_path = "/var/log/tb/l3af/egress_ipfix.log";

void sig_handler(int signo)
{
    log_info("Received shutdown signal, cleaning up");
    flow_record_poll(egress_fd, last_egress_fd, EGRESS);
    if (attach_tc_egress_filter)
        tc_cleanup(chain, if_name, EGRESS, egress_bpf_map, last_egress_bpf_map, bpf_map_file_path, ipfix_egress_jmp_table);
    log_info("Cleaned up");
    close_logfile();
    exit(EXIT_SUCCESS);
}

int populate_egress_fds(void) {
    egress_fd = bpf_obj_get(egress_bpf_map);
    if (egress_fd < 0) {
        fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s)",
                        egress_bpf_map);
        close_logfile();
        return EXIT_FAILURE;
    }

    last_egress_fd = bpf_obj_get(last_egress_bpf_map);
    if (last_egress_fd < 0) {
        fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s)", last_egress_bpf_map);
        close_logfile();
        return EXIT_FAILURE;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char filename[256];
    int  opt = 0, long_index = 0, l = 0;
    bool remove_egress_tc_filter = false;
    verbosity = LOG_INFO;
    long flow_timeout = 0;
    char *eptr;
    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq",
                  long_options, &long_index)) != -1) {
        switch (opt) {
            case 'm':
                if(optarg){
                    bpf_map_file_path = (char *) malloc(1 + strnlen(optarg, MAX_FILENAME_LENGTH));
                    cpy(optarg, bpf_map_file_path);
                    if(!validate_map_name(bpf_map_file_path))
                        return EXIT_FAILURE;
                    chain = true;
                }
                break;
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
                attach_tc_egress_filter = true;
                snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
                l = get_length(filename);
                filename[l] = '\0';
                break;
            case 'c':
                if(optarg)
                    remote_ip = optarg;
                break;
            case 'r':
                if (optarg &&
                    (!validate_ifname(optarg, (char *)&if_name))) {
                    log_err("ERR: input --remove=ifname invalid");
                    return EXIT_FAILURE;
                }
                if (get_length(if_name) == 0) {
                    log_err("ERR: need input --list=ifname");
                    return EXIT_FAILURE;
                }
                remove_egress_tc_filter = true;
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

    if(attach_tc_egress_filter) {
	if(chain == true){
            if (tc_chain_bpf(bpf_map_file_path, filename, egress) != 1) {
                fprintf(stderr, "ERR: tc chain egress failed \n");
                close_logfile();
                 return EXIT_FAILURE;
            }
	}
        else {
            if (tc_attach_filter(if_name, filename, EGRESS, egress) != 1) {
                fprintf(stderr, "ERR: TC EGRESS filter attach failed\n");
                close_logfile();
                return EXIT_FAILURE;
            }
       }
       if (populate_egress_fds() == EXIT_FAILURE) {
            fprintf(stderr, "ERR: Fetching TC EGRESS maps failed\n");
            close_logfile();
            return EXIT_FAILURE;
       }
       if (remote_ip == NULL) {
                log_info("Remote IP is not configured by user, so configuring localhost as remote_ip");
                remote_ip = "127.0.0.1" ;
       }
    }

    if (remove_egress_tc_filter) {
        log_debug("TC remove egress filters on device %s",
                   if_name);
        tc_remove_filter(if_name, EGRESS);
        return EXIT_SUCCESS;
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
