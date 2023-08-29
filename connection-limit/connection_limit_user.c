// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <linux/if_link.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <string.h>
#include <linux/perf_event.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include "bpf_load.h"
#include "bpf_util.h"
#include <time.h>
#include <sys/time.h>
#include <libgen.h>
#include <bpf/libbpf.h>
#include <getopt.h>

#include "log.h"
#include "constants.h"


static const char *__doc__ =
        "Connection limit incoming TCP connections using XDP";

static int ifindex;
static char prev_prog_map[1024];

static int xdp_unlink_bpf_chain(const char *map_filename) {
    int ret = 0;
    int key = 0;
    int map_fd = bpf_obj_get(map_filename);

    if (map_fd > 0) {
        ret = bpf_map_delete_elem(map_fd, &key);
        if (ret != 0)
            log_err("Failed to remove XDP program from the chain");
    }
    else
        log_info("Failed to fetch previous XDP program in the chain");

    if (remove(xdp_cl_ingress_next_prog) < 0) {
        log_warn("Failed to remove link to next XDP program in the chain");
    }
    return ret;
}

static void signal_handler(int sig)
{
    log_info("Received signal %d", sig);
    int i = 0;
    xdp_unlink_bpf_chain(prev_prog_map);
    for (i=0; i<MAP_COUNT; i++) {
        close(map_fd[i]);
    }
    if (info != NULL)
        fclose(info);
    exit(EXIT_SUCCESS);
}

static const struct option long_options[] = {
    {"help",      no_argument,        NULL, 'h' },
    {"iface",     required_argument,  NULL, 'i' },
    {"max-conn",  required_argument,  NULL, 'c' },
    {"ports",     optional_argument,  NULL, 'p' },
    {"verbose",   optional_argument,  NULL, 'v' },
    {"direction", optional_argument,  NULL, 'd' },
    {"map-name",  optional_argument,  NULL, 'm' },
    {0,           0,                  NULL,  0  }
};

static void usage(char *argv[])
{
    int i;
    printf("\nDOCUMENTATION:\n%s\n", __doc__);
    printf("\n");
    printf(" Usage: %s (options-see-below)\n", argv[0]);
    printf(" Listing options:\n");
    for (i = 0; long_options[i].name != 0; i++)
    {
        printf(" --%-12s", long_options[i].name);
        if (long_options[i].flag != NULL)
                printf(" flag (internal value:%d)",
                        *long_options[i].flag);
        else
                printf(" short-option: -%c",
                        long_options[i].val);
        printf("\n");
    }
    printf("\n");
}

/* Set log timestamps */
void log_timestamp(char *log_ts) {
    struct timeval tv;
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[TIMESTAMP_LEN];

    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, DATE_LEN, "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(log_ts, DATE_LEN+TIMESTAMP_LEN, "%s.%06ld", tmbuf, tv.tv_usec);
}

/* Set the logging output to the default log file configured */
FILE* set_log_file(void)
{
    if (info != NULL){
        return info;
    }
    info = fopen(DEFAULT_LOGFILE, "a");
    if (info == NULL) {
        fprintf(stderr, "could not open log file ");
        return NULL;
    }
    fprintf(stderr, "writing errors/warnings/info/debug output to %s \n",
            DEFAULT_LOGFILE);
    return info;
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

static int is_ipv4_loopback(uint32_t *addr4)
{
    if ((*addr4 & 0xff) == ipv4_lo_addr)
        return 1;
    return 0;
}

static int is_ipv6_loopback(struct in6_addr *addr6)
{
    if ((addr6->s6_addr32[0] == 0) && (addr6->s6_addr32[1] == 0) &&
        (addr6->s6_addr32[2] == 0) && (addr6->s6_addr32[3] == 1))
        return 1;
    if ((addr6->s6_addr32[0] == 0) && (addr6->s6_addr32[1] == 0) &&
        (addr6->s6_addr32[2] == 0xffff0000) &&
        ((addr6->s6_addr32[3]&0xff) == 0x7f))
        return 1;
    return 0;
}

static int str_split(char *input, char *delimiter, char *word_array[])
{
    char *tmp, *ptr;
    int n = 0;
    tmp = strdup(input);
    while( (ptr = strsep(&tmp, delimiter)) != NULL )
    {
        if(get_length(ptr) > 0) {
           word_array[n++] = ptr;
        }
    }
    return 0;
}

static long strtoi(char *str, int base) {
    char *endptr;
    long long_var = strtol(str, &endptr, base);
    /* out of range, Found extra chars at end of string */
    if (*endptr != '\0' || str == endptr) {
        fprintf(stderr,
                "Failed to convert string %s to %s \n", str, endptr);
    }
    return long_var;
}

/* Function to replace sscanf to read ipv6 address */
static void addr6_parser(char *input, struct in6_addr *localaddr)
{
    char *s1 = malloc(9);
    char *s2 = malloc(9);
    char *s3 = malloc(9);
    char *s4 = malloc(9);

    /* copy every 8 hexa characters as a word */
    strncpy(s1, input, 8);
    s1[8] = '\0';
    strncpy(s2, input+8, 8);
    s2[8] = '\0';
    strncpy(s3, input+16, 8);
    s3[8] = '\0';
    strncpy(s4, input+24, 8);
    s4[8] = '\0';

    localaddr->s6_addr32[0] = (int)(strtoi(s1, 16));
    localaddr->s6_addr32[1] = (int)(strtoi(s2, 16));
    localaddr->s6_addr32[2] = (int)(strtoi(s3, 16));
    localaddr->s6_addr32[3] = (int)(strtoi(s4, 16));

    free(s1);
    free(s2);
    free(s3);
    free(s4);
}

static char* trim_space(char *str)
{
    char *end;
    /* skip leading whitespace */
    while (isspace(*str)) {
        str = str + 1;
    }
    /* remove trailing whitespace */
    end = str + get_length(str) - 1;
    while (end > str && isspace(*end)) {
        end = end - 1;
    }
    /* write null character */
    *(end+1) = '\0';
    return str;
}

/* Parse /proc/net/tcp6 and update bpf maps with needed data
   map_fd[3]-> tcp_v6_conns: Holds TCP6 sockets in listen state
   map_fd[0]->conn_count: Holds the number of concurrent inbound connections
   in ESTABLISHED state */
static int parse_tcpv6(int lnr, char *line)
{
    char localaddr_str[64];
    int local_port, state, len, ret = 0;
    uint16_t local_port_u;
    unsigned long skaddr;
    struct in6_addr localaddr;
    uint32_t key = 0, sock_val = 1, val = 1;
    uint64_t count;
    char *eptr;
    char *proc_info[30], *locals[3], *remotes[3];
    if (lnr == 0)
        return 0;

    if (!line) {
        log_err("line from /proc/net/tcp is empty");
        return 0;
    }

    str_split(line, " ", proc_info);

    /* Get local address and local port */
    if (get_length(proc_info[1]) == 0 )
        return 0;

    str_split(proc_info[1], ":", locals);
    len = get_length(locals[0]);
    strncpy(localaddr_str, locals[0], len);
    localaddr_str[len] = '\0';
    local_port = (int)(strtoi(locals[1], 16));

    if (get_length(proc_info[2]) == 0 )
        return 0;
    str_split(proc_info[2], ":", remotes);
    len = get_length(remotes[0]);

    local_port_u = local_port;

    /* Parse address string and populate ipv6 address */
    addr6_parser(localaddr_str, &localaddr);

    /* Get skaddr */
    if (get_length(proc_info[11]) == 0 )
        return 0;
    skaddr = strtoul(proc_info[11], &eptr, 16);

    /* Get state */
    if (get_length(proc_info[3]) == 0 )
        return 0;

    state = (int)(strtoi(proc_info[3], 16));
    if (state == TCP_ESTABLISHED) {
        if (is_ipv6_loopback(&localaddr)) {
            log_info("Skipping loopback ipv6 connections in established state\n");
            return 0;
        }
        if (bpf_map_lookup_elem(map_fd[2], &local_port_u, &val) == 0) {
            ret = bpf_map_update_elem(map_fd[3], &skaddr, &sock_val, 0);
            if (ret) {
                log_info("Failed to update socket in bpf map\n");
                perror("bpf_update_elem");
                return 1;
            }
            log_info("Updated ipv6 established connection: %s\n", line);
            if (bpf_map_lookup_elem(map_fd[0], &key, &count) != 0) {
                log_info("Failed to fetch current established connections\n");
                return 1;
            }
            log_info("Updated TCPv6 connection in the map: %s\n", line);;
            count++;
            if (bpf_map_update_elem(map_fd[0], &key, &count, 0) != 0) {
                log_info("Failed to update current established connections\n");
                return 1;
            }
        }
    }

    return 0;
}

/* Parse /proc/net/tcp and update bpf maps with needed data
   map_fd[2]-> tcp_v4_conns: Holds TCP sockets in listen state
   map_fd[0]->conn_count: Holds the number of concurrent inbound connections
   in ESTABLISHED state */
static int parse_tcpv4(int lnr, char *line)
{
    uint32_t local_addr = 0;
    int local_port, state;
    uint16_t local_port_u;
    int ret = 0;
    unsigned long skaddr;
    uint32_t key = 0, sock_val = 1, val = 1;
    uint64_t count;
    char *eptr;
    /* Skip first line of PATH_PROCNET_TCP that has heading */
    if (lnr == 0)
        return 0;

    char * proc_info[30];
    char *locals[3], *remotes[3];

    if (!line) {
        log_err("line from /proc/net/tcp is empty");
        return 0;
    }

    str_split(line, " ", proc_info);

    /* Get local address and local port */
    if (get_length(proc_info[1]) == 0 )
        return 0;
    str_split(proc_info[1], ":", locals);
    local_addr = (uint32_t)(strtoi(locals[0], 16));
    local_port = (int)(strtoi(locals[1], 16));

    if (get_length(proc_info[2]) == 0 )
        return 0;
    str_split(proc_info[2], ":", remotes);

    local_port_u = local_port;

    /* Get skaddr */
    if (get_length(proc_info[11]) == 0 )
        return 0;
    skaddr = strtoul(proc_info[11], &eptr, 16);

    /* Get state */
    if (get_length(proc_info[3]) == 0 )
        return 0;

    state = (int)(strtoi(proc_info[3], 16));
    if (state == TCP_ESTABLISHED) {
        if (is_ipv4_loopback(&local_addr)) {
            log_info("Skipping ipv4 loopback connections in established state\n");
            return 0;
        }

        if (bpf_map_lookup_elem(map_fd[2], &local_port_u, &val) == 0) {
            ret = bpf_map_update_elem(map_fd[3], &skaddr, &sock_val, 0);
            if (ret) {
                log_info("Failed to update socket address in the bpf map\n");
                perror("bpf_update_elem");
                return 1;
            }
            if (bpf_map_lookup_elem(map_fd[0], &key, &count) != 0) {
                log_info("Failed to fetch current established connections\n");
                return 1;
            }
            log_info("Updated TCPv4 connection in the map: %s\n", line);
            count++;
            if (bpf_map_update_elem(map_fd[0], &key, &count, 0) != 0) {
                log_info("Failed to update current established connections\n");
                return 1;
            }
            log_info("Updated ipv4 established connection: %s\n", line);
        }
    }
    return 0;
}

static void parse_tcp(char *file, int (*proc)(int, char*))
{
    FILE *procinfo;
    char *buffer = NULL;
    size_t len = 0;
    int lnr = 0;

    procinfo = fopen(file, "r");
    if (!procinfo) {
        log_info("error\n");
        return;
    }
    while (getline(&buffer, &len, procinfo) != -1) {
        if (proc(lnr++, buffer))
            log_info("bogus data on line %s\n", buffer);
        if (buffer)
            free(buffer);
        buffer = NULL;
    }
    fclose(procinfo);
}

static void update_ports(char *ports)
{
    char *tmp, *ptr;
    tmp = strdup(ports);
    uint16_t port = 0;
    int pval = 1;
    while( (ptr = strsep(&tmp, delim)) != NULL )
    {
        ptr = trim_space(ptr);
        port = (uint16_t)(strtoi(ptr, 10));
        bpf_map_update_elem(map_fd[2], &port, &pval, 0);
    }
    free(tmp);
}

int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int opt, long_index = 0, key = 0, len = 0;

    uint64_t conn_val = 0, max_conn_val = 0;

    char filename[256], ports[2048];
    verbosity = LOG_INFO;

    memset(ports,'\0',2048);

    while ((opt = getopt_long(argc, argv, "hq",
                              long_options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                ifindex = if_nametoindex(optarg);
                break;
            case 'c':
                max_conn_val = strtoi(optarg, 10);
                break;
            case 'p':
                len = get_length(optarg);
                strncpy(ports, optarg, len);
                ports[len] = '\0';
                break;
            case 'v':
                if(optarg)
                    verbosity = (int)(strtoi(optarg, 10));
                break;
            case 'm':
                if(optarg) {
                    len = get_length(optarg);
                    strncpy(prev_prog_map, optarg, len);
                    prev_prog_map[len] = '\0';
                }
                break;
            case 'd':
                /* Not honoured as of now */
                break;
            case 'h':
            default:
                usage(argv);
                return 0;
        }
    }
    set_log_file();
    setrlimit(RLIMIT_MEMLOCK, &r);
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

    if (load_bpf_file(filename)) {
        log_err("%s", bpf_log_buf);
        return 1;
    }
    log_info("loaded bpf file\n");

    if (!prog_fd[0] || !prog_fd[1]) {
        log_info("load_bpf_file: %s\n", strerror(errno));
        return 1;
    }
    /* Get the previous program's map fd in the chain */
    int pkey = 0;
    int prev_prog_map_fd = bpf_obj_get(prev_prog_map);

    if (prev_prog_map_fd < 0) {
        log_err("Failed to fetch previous xdp function in the chain");
        exit(EXIT_FAILURE);
    }
    /* Update current prog fd in the last prog map fd,
     * so it can chain the current one */
    if(bpf_map_update_elem(prev_prog_map_fd, &pkey, &(prog_fd[1]), 0)) {
        log_err("Failed to update prog fd in the chain");
        exit(EXIT_FAILURE);
    }
    /* closing map fd to avoid stale map */
    close(prev_prog_map_fd);

    int next_prog_map_fd = bpf_obj_get(xdp_cl_ingress_next_prog);
    if (next_prog_map_fd < 0) {
        log_info("Failed to fetch next prog map fd, creating one");
        if (bpf_obj_pin(map_fd[6], xdp_cl_ingress_next_prog)) {
            log_info("Failed to pin next prog fd map");
            exit(EXIT_FAILURE);
        }
    }
    log_info("Max connections value is %lu\n", max_conn_val);

    int ret = bpf_map_update_elem(map_fd[1], &key, &max_conn_val, 0);
    if (ret) {
        perror("bpf_update_elem");
        return 1;
    }
    log_info("conn value is %lu\n", conn_val);
    ret = bpf_map_update_elem(map_fd[0], &key, &conn_val, 0);
    if (ret) {
        perror("bpf_update_elem");
        return 1;
    }
    ret = bpf_map_update_elem(map_fd[4], &key, &conn_val, 0);
    if (ret) {
        perror("bpf_update_elem");
        return 1;
    }

    if (get_length(ports))
    {
        log_info("Port list is %s\n", ports);
        update_ports(ports);
    }

    ret = bpf_map_update_elem(map_fd[5], &key, &conn_val, 0);
    if (ret) {
        perror("bpf_update_elem");
        return 1;
    }

    fflush(info);
    parse_tcp(PATH_PROCNET_TCP, parse_tcpv4);
    parse_tcp(PATH_PROCNET_TCP6, parse_tcpv6);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGKILL, signal_handler);

    /* Dummy loop to make it a continuously running process */
    while(1) {
        fflush(info);
        sleep(600);
    }
    return 0;
}

static int get_length(const char *str);
static int is_ipv4_loopback(uint32_t *addr4);
static int is_ipv6_loopback(struct in6_addr *addr6);
static int str_split(char *input, char *delimiter, char *word_array[]);
static long strtoi(char *str, int base);
static void addr6_parser(char *input, struct in6_addr *localaddr);
static char* trim_space(char *str);
static void update_ports(char *ports);
