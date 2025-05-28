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

#define IPFIX_EXPORT_INGRESS_LOCAL_PORT 4755
#define IPFIX_EXPORT_EGRESS_LOCAL_PORT 4756

extern const char* egress_bpf_map ;
extern const char* last_egress_bpf_map ;
extern const char* ingress_bpf_map ;
extern const char* last_ingress_bpf_map ;
extern const char* ipfix_ingress_jmp_table;
extern const char* ipfix_egress_jmp_table;
extern const char* ingress_dir;
extern const char* egress_dir;
static const char map_base_dir[] = "/sys/fs/bpf/tc/globals";

extern bool chain;
extern char *remote_ip, *bpf_map_file_path, *tc_cmd;
extern int flow_timeout, remote_port, bpf_map_fd;
extern int egress_fd, last_egress_fd, ingress_fd, last_ingress_fd;
extern int flow_timeout_counter, if_idx;
extern const struct option long_options[];

enum iface_direction {
  INGRESS = 0,
  EGRESS  = 1,
};

#define MAP_PATH_SIZE   1024

void get_random_number(unsigned int *fid);

bool validate_ifname(const char* input_ifname, char *output_ifname);

void update_packet_byte_counters(flow_record_t *flow_rec, flow_record_t last_flow_rec, bool first_rec);

bool delete_inactive_flow(int flow_idle_counter, int map_fd, int last_map_fd, unsigned int next_key);

bool process_flow_record_map(int map_fd, int last_map_fd, int type);

flow_record_t* update_flow_record_to_create_ipfix(flow_record_t *flow_rec, bool first_rec,
                                                  flow_record_t last_flow_rec, int type);
void log_timestamp(char *log_ts);

FILE* set_logfile(const char *file_name);

void close_logfile(void);

void usage(char *argv[], const char *doc);

void flow_record_poll(int map_fd, int last_map_fd, int dir);

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

bool validate_map(const char* input);

int get_bpf_map_file(const char *ifname, const char *map_name, char *map_file);

void close_fd(int fd);
void close_ingress_fds(void);
void close_egress_fds(void);
#endif
