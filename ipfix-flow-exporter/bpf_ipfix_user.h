// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#ifndef BPF_IPFIX_USER_H
#define BPF_IPFIX_USER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <sys/time.h>
#include <stdbool.h>
#include <unistd.h>
#include <locale.h>
#include <openssl/rand.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/stat.h>

#include "p2f.h"
#include "ipfix.h"
#include "log.h"
#include "bpf_load.h"
#include "bpf_util.h"

const char* egress_bpf_map ;
const char* last_egress_bpf_map ;
const char* ingress_bpf_map ;
const char* last_ingress_bpf_map ;
const char* ipfix_ingress_jmp_table;
const char* ipfix_egress_jmp_table;
const char* bpf_path;
const char* ingress_dir;
const char* egress_dir;

int ipfix_export_ingress_local_port, ipfix_export_egress_local_port;
bool chain;
char *remote_ip, *bpf_map_file_path, *tc_cmd;
int flow_timeout, remote_port, bpf_map_fd;
int egress_fd, last_egress_fd, ingress_fd, last_ingress_fd;
int flow_timeout_counter, if_idx;
extern const struct option long_options[];

enum iface_direction {
  INGRESS = 0,
  EGRESS  = 1,
};


unsigned long get_current_time_ns(void);
void get_random_number(unsigned int *fid);

bool validate_ifname(const char* input_ifname, char *output_ifname);

void update_packet_byte_counters(flow_record_t *flow_rec, flow_record_t last_flow_rec, bool first_rec);

bool delete_inactive_flow(int flow_idle_counter, int map_fd, int last_map_fd, unsigned int next_key);

bool process_flow_record_map(int map_fd, int last_map_fd, int type);

flow_record_t* update_flow_record_to_create_ipfix(flow_record_t *flow_rec, bool first_rec,
                                                  flow_record_t last_flow_rec, int type);
void tc_detach_bpf(const char *dev);

int tc_attach_filter(const char* dev, const char* bpf_obj, int dir, const char *sec);

int tc_list_filter(const char* dev, int dir);

int tc_remove_filter(const char* dev, int dir);

int tc_remove_bpf(const char *map_filename);

bool validate_ifname(const char* input_ifname, char *output_ifname);

void log_timestamp(char *log_ts);

FILE* set_logfile(const char *file_name);

int  tc_chain_bpf(const char *map_name, const char *bpf_obj, const char *sec);

void close_logfile(void);

void usage(char *argv[], const char *doc);

void flow_record_poll(int map_fd, int last_map_fd, int dir);

void tc_cleanup(bool chain, char *if_name, int dir, const char* bpf_map,
                 const char* last_bpf_map, char* bpf_map_file_path, const char* ipfix_jmp_table);

int check_egress_or_ingress_existed(void);

int get_port(int dir);

int get_length(const char *str);

int isFileExists(const char *path);

int validate_str(const char *str);

void sig_handler(int signo);

int populate_egress_fds(void);

int populate_ingress_fds(void);

void cpy(char *src,char *des);

bool validate_map_name(const char *path);

int exec_cmd(char* cmd[]);

int validate_filter_args(const char* dev);

bool validate_map(const char* input);

int tc_cmd_filter(const char* dev, int dir, const char* action);

int validate_chain_args(const char *map_name);
#endif
