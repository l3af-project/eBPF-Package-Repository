// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

static const char *__doc__=" BPF IPFIX : To get packet flow data by handling the packet and create IPFIX.\n\n";

#include "bpf_ipfix_user.h"
#include <unistd.h>

#define INGRESS 0
#define MAX_FILENAME_LENGTH 256

/* Exit return codes */
#define EXIT_OK                 0
#define EXIT_FAIL               1

extern FILE *info;
extern int verbosity;
const char ingress[] = "ingress_flow_monitoring";

/* Ingress Specific variables */
char *ingress_log_file_path = "/var/log/tb/l3af/ingress_ipfix.log";
bool attach_tc_ingress_filter = false;
char if_name[IF_NAMESIZE];

void sig_handler(int signo)
{
    log_info("Received shutdown signal, cleaning up");
    flow_record_poll(ingress_fd, last_ingress_fd, INGRESS);
    if (attach_tc_ingress_filter)
        tc_cleanup(chain, if_name, INGRESS, ingress_bpf_map, last_ingress_bpf_map, bpf_map_file_path, ipfix_ingress_jmp_table);
    close_logfile();
    exit(EXIT_SUCCESS);
}

int populate_ingress_fds(void) {
    ingress_fd = bpf_obj_get(ingress_bpf_map);
    if (ingress_fd < 0) {
        fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s)", ingress_bpf_map);
        close_logfile();
        return EXIT_FAILURE;
    }

    last_ingress_fd = bpf_obj_get(last_ingress_bpf_map);
    if (last_ingress_fd < 0) {
        fprintf(stderr, "ERROR: cannot open bpf_obj_get(%s)", last_ingress_bpf_map);
        close_logfile();
        return EXIT_FAILURE;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char filename[256];
    int  opt = 0, long_index = 0, l = 0;
    bool remove_ingress_tc_filter = false;
    verbosity = LOG_INFO;
    long flow_timeout = 0;
    char *eptr;

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq",
                  long_options, &long_index)) != -1) {
        switch (opt) {
            case 'm':
                if(optarg) {
                    bpf_map_file_path = (char *) malloc(1 + strnlen(optarg, MAX_FILENAME_LENGTH));
                    cpy(optarg, bpf_map_file_path);
                    if(!isFileExists(bpf_map_file_path))
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
                attach_tc_ingress_filter = true;
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
                    !validate_ifname(optarg, (char *)&if_name)) {
                    log_err("ERR: input --remove=ifname invalid");
                    return EXIT_FAILURE;
                }
                if (get_length(if_name) == 0) {
                    log_err("ERR: need input --list=ifname");
                    return EXIT_FAILURE;
                }
                remove_ingress_tc_filter = true;
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
		/* This option is to have consistancy across NFs */
		break;
            case 'h':
            default:
                usage(argv, __doc__);
                return EXIT_FAILURE;
        }
    }

    info = set_logfile(ingress_log_file_path);
    if(info == NULL) {
        verbosity = 0;
        fprintf(stderr, "LOG file is not set. Please verify logfile path");
        return EXIT_FAILURE;
    }

    if(attach_tc_ingress_filter) {
	if(chain == true){
            if (tc_chain_bpf(bpf_map_file_path, filename, ingress) != 1) {
                fprintf(stderr, "ERR: tc chain ingress failed \n");
                close_logfile();
                return EXIT_FAILURE;
            }
	}
        else {
            if (tc_attach_filter(if_name, filename, INGRESS, ingress) != 1) {
                fprintf(stderr, "ERR: TC INGRESS filter attach failed\n");
                close_logfile();
                return EXIT_FAILURE;
            }
       }
       if (populate_ingress_fds() == EXIT_FAILURE) {
            fprintf(stderr, "ERR: Fetching TC INGRESS maps failed\n");
            close_logfile();
            return EXIT_FAILURE;
       }
       if (remote_ip == NULL) {
                log_info("Remote IP is not configured by user, so configuring localhost as remote_ip");
                remote_ip = "127.0.0.1" ;
       }
    }

    if (remove_ingress_tc_filter) {
        log_debug("TC remove ingress filters on device %s", if_name);
        tc_remove_filter(if_name, INGRESS);
        return EXIT_SUCCESS;
    }

    if (signal(SIGINT, sig_handler) || signal(SIGHUP, sig_handler) ||
        signal(SIGTERM, sig_handler)) {
        perror("signal");
        return EXIT_FAIL;
    }

    while(true) {
        log_debug("Sleeping for 10 sec");
        sleep(10);
        flow_record_poll(ingress_fd, last_ingress_fd, INGRESS);
    }
    return EXIT_OK;
}
