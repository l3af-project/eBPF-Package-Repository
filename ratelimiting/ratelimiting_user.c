// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* Ratelimit incoming TCP connections with sliding window approach */

#include <stdio.h>
#include <linux/bpf.h>
#include <signal.h>
#include <ctype.h>
#ifdef __linux__
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#endif
#include <getopt.h>
#ifdef __linux__
#include <net/if.h>
#endif
#include <time.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>

#include "bpf/libbpf.h"
#include "constants.h"
#include "log.h"

#ifdef __linux__
#include "bpf_util.h"
int map_fd[MAP_COUNT];
#endif
#ifdef WIN32
#include <io.h>
#include <winsock2.h>
#include <netioapi.h>
#define sleep(seconds) Sleep((seconds) * 1000)

char* strsep(char** stringp, const char* delim)
{
    static char* next_token = NULL;
    char* input = *stringp;
    *stringp = strtok_s(input, delim, &next_token);
    return input;
}
#define close _close
#define strdup _strdup
int gettimeofday(struct timeval* tv, struct timezone* tz)
{
    FILETIME ft;
    ULARGE_INTEGER ui;
    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    ui.QuadPart /= 10; // Convert to usec.
    tv->tv_sec = (long)(ui.QuadPart / 1000000);
    tv->tv_usec = ui.QuadPart % 1000000;
    return 0;
}
#include "bpf/bpf.h"
#include "bpf_load.h"
#endif

static const char *__doc__ =
        "Ratelimit incoming TCP connections using XDP";

static int ifindex;
FILE *info;
static char prev_prog_map[1024];
static const struct option long_options[] = {
    {"help",      no_argument,        NULL, 'h' },
    {"iface",     required_argument,  NULL, 'i' },
    {"rate",      required_argument,  NULL, 'r' },
    {"ports",     optional_argument,  NULL, 'p' },
    {"verbose",   optional_argument,  NULL, 'v' },
    {"direction", optional_argument,  NULL, 'd'},
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

static int get_length(const char *str)
{
    int len = 0;
    if (*str == '\0')
        return 0;
    while (str[len] != '\0')
       len++;

   return len;
}

/* Set the logging output to the default log file configured */
static FILE* set_logfile(void)
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

// This method to unlink the program
static int xdp_unlink_bpf_chain(const char *map_filename) {
    int ret = 0;
    int key = 0;
    int prog_map_fd = bpf_obj_get(map_filename);
    if (prog_map_fd > 0) {
       ret = bpf_map_delete_elem(prog_map_fd, &key);
       if (ret != 0) {
           log_err("Failed to remove XDP program from the chain");
       }
    }
    else {
       log_err("Failed to fetch previous XDP program in the chain");
    }

    if (remove(xdp_rl_ingress_next_prog) < 0) {
        log_warn("Failed to remove link to next XDP program in the chain");
    }

    return ret;
}


/* Unlink xdp kernel program on receiving KILL/INT signals */
static void signal_handler(int signal)
{
    log_info("Received signal %d", signal);
    int i = 0;
    xdp_unlink_bpf_chain(prev_prog_map);
    for(i=0; i<MAP_COUNT;i++) {
       close(map_fd[i]);
    }
    if (info != NULL)
        fclose(info);
    exit(EXIT_SUCCESS);
}

/* Get monotonic clock time in ns */
static __u64 time_get_ns(void)
{
#ifdef __linux__
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ull + ts.tv_nsec;
#endif
#ifdef WIN32
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (1000000000 * counter.QuadPart) / frequency.QuadPart;
#endif
}

static char* trim_space(char *str) {
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

static int strtoi(const char *str) {
  char *endptr;
  errno = 0;

  long long_var = strtol(str, &endptr, 10);
  //out of range, extra chars at end
  if (errno == ERANGE || *endptr != '\0' || str == endptr) {
     fprintf(stderr, "out of range");
  }

  return (int) long_var;
}

static void update_ports(char *ports)
{
    char *ptr,*tmp ;
    uint16_t port = 0;
    uint8_t pval = 1;
    tmp = strdup(ports);
    while((ptr = strsep(&tmp, delim)) != NULL)
    {
        ptr = trim_space(ptr);
        port = (uint16_t)(strtoi(ptr));
        bpf_map_update_elem(map_fd[4], &port, &pval, 0);
    }
    free(tmp);
}

#ifdef __linux__
static int load_maps(struct bpf_object *obj) {
    map_fd[0] = bpf_map__fd(bpf_object__find_map_by_name(obj, rl_config_map));
    if (map_fd[0] < 0)
    {
        fprintf(stderr, "Failed to get rl_config_map FD\n");
        return 1;
    }
    map_fd[1] = bpf_map__fd(bpf_object__find_map_by_name(obj, rl_window_map));
    if (map_fd[1] < 0)
    {
        fprintf(stderr, "Failed to get rl_window_map FD\n");
        return 1;
    }
    map_fd[2] = bpf_map__fd(bpf_object__find_map_by_name(obj, rl_recv_count_map));
    if (map_fd[1] < 0)
    {
        fprintf(stderr, "Failed to get rl_recv_count_map FD\n");
        return 1;
    }
    map_fd[3] = bpf_map__fd(bpf_object__find_map_by_name(obj, rl_drop_count_map));
    if (map_fd[1] < 0)
    {
        fprintf(stderr, "Failed to get rl_drop_count_map FD\n");
        return 1;
    }
    map_fd[4] = bpf_map__fd(bpf_object__find_map_by_name(obj, rl_ports_map));
    if (map_fd[4] < 0)
    {
        fprintf(stderr, "Failed to get rl_ports_map FD\n");
        return 1;
    }
    map_fd[5] = bpf_map__fd(bpf_object__find_map_by_name(obj, xdp_rl_ingress_next_prog));
    if (map_fd[5] < 0)
    {
        fprintf(stderr, "Failed to get xdp_rl_ingress_next_prog FD\n");
        return 1;
    }
    return 0;
}

static struct bpf_object* load_bpf_programs(const char *bpf_file, int prog_fd[1])
{
    struct bpf_object *bpf_obj;
    struct bpf_program *bpf_prog;

    struct bpf_object_open_attr open_attr = {
            .file = bpf_file,
            .prog_type = BPF_PROG_TYPE_UNSPEC,
    };
    bpf_obj = bpf_object__open_xattr(&open_attr);
    if (!bpf_obj)
    {
        fprintf(stderr, "ERR: failed to open object %s\n", bpf_file);
        return NULL;
    }

    if (bpf_object__load(bpf_obj))
    {
        fprintf(stderr, "Failed to load BPF Object\n");
        return NULL;
    }
    bpf_prog = bpf_program__next(NULL, bpf_obj);
    if (!bpf_prog)
    {
        fprintf(stderr, "Couldn't find a program trace_inet_sock_set_state in the BPF file %s\n", bpf_file);
        return NULL;
    }

    prog_fd[0] = bpf_program__fd(bpf_prog);
    if (prog_fd[0] <= 0) {
        fprintf(stderr, "Failed to get program FD\n");
        return NULL;
    }

    return bpf_obj;
}
#endif

int main(int argc, char **argv)
{
    int longindex = 0, rate = 0, opt;
    int ret = EXIT_SUCCESS;
    char bpf_obj_file[256];
    char ports[2048];
    verbosity = LOG_INFO;
    char map_file_path[2048];
#ifdef __linux__
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
#endif
    int len = 0;
    struct bpf_object *obj;
    int prog_fd[2];

    snprintf(bpf_obj_file, sizeof(bpf_obj_file), "%s_kern.o", argv[0]);

    memset(&ports, 0, 2048);
    memset(&map_file_path, 0, 2048);

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "h", long_options, &longindex)) != -1)
    {
        switch (opt) {
            case 'r':
                rate = strtoi(optarg);
                break;
            case 'i':
                ifindex = if_nametoindex(optarg);
                break;
            case 'v':
                if(optarg) {
                    verbosity = strtoi(optarg);
                }
                break;
            case 'm':
                if(optarg) {
                    len = get_length(optarg);
                    strncpy(prev_prog_map, optarg, len);
                    prev_prog_map[len] = '\0';
                }
                break;
            case 'p':
                if(optarg) {
                    len = get_length(optarg);
                    strncpy(ports, optarg, len);
                    ports[len] = '\0';
                }
                break;
            case 'd':
                /* Not honoured as of now */
                break;
            case 'h':
            default:
                usage(argv);
                return EXIT_FAILURE;
        }
    }
#ifdef __linux__
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(EXIT_FAILURE);
    }
#endif
    set_logfile();

    __u64 ckey = 0, rkey = 0, dkey = 0, pkey = 0;
    __u64 recv_count = 0, drop_count = 0;
#ifdef __linux__
    obj = load_bpf_programs(bpf_obj_file,prog_fd);
    if (obj == NULL) {
        log_err("load_bpf_programs failed\n");
        return 1;
    }
#else
    if (load_bpf_file(bpf_obj_file)) {
        log_err("Failed to load bpf program");
        return 1;
    }
#endif
    if (!prog_fd[0]) {
        log_err("Failed to get bpf program fd")
        return 1;
    }

    log_info("loaded bpf file\n");

    /* Get the previous program's map fd in the chain */
    int prev_prog_map_fd = bpf_obj_get(prev_prog_map);
    if (prev_prog_map_fd < 0) {
        log_err("Failed to fetch previous xdp function in the chain");
        exit(EXIT_FAILURE);
    }
    /* Update current prog fd in the last prog map fd,
     * so it can chain the current one */
    if(bpf_map_update_elem(prev_prog_map_fd, &pkey, &(prog_fd[0]), 0)) {
        log_err("Failed to update prog fd in the chain");
        exit(EXIT_FAILURE);
    }
     /* closing map fd to avoid stale map */
     close(prev_prog_map_fd);

#ifdef __linux__
     /* load map fds into map_fd array */
    if (load_maps(obj) != 0) {
        log_err("Failed to load bpf maps");
        exit(EXIT_FAILURE);
    }
#endif

    int next_prog_map_fd = bpf_obj_get(xdp_rl_ingress_next_prog);
    if (next_prog_map_fd < 0) {
        log_info("Failed to fetch next prog map fd, creating one %s", xdp_rl_ingress_next_prog);
        sprintf(map_file_path,"%s/%s",pin_basedir,xdp_rl_ingress_next_prog);
        int errorno = bpf_obj_pin(map_fd[5], map_file_path);
        if (errorno) {
            log_info("Failed to pin next prog fd map %d map name %s error %s", map_fd[5], map_file_path, strerror(errorno));
            exit(EXIT_FAILURE);
        }
    }

    /* Map FDs are sequenced same as they are defined in the bpf program ie.,
     * map_fd[0] = rl_config_map, map_fd[1] = rl_window_map
     * map_fd[2] = rl_recv_count_map, map_fd[3] = rl_drop_count_map
     * map_fd[4] = rl_ports_map
     * map_fd[5] = xdp_rl_ingress_next_prog*/
    if (!map_fd[0]){
        log_err("Failed to fetch config map");
        return -1;
    }
    ret = bpf_map_update_elem(map_fd[0], &ckey, &rate, 0);
    if (ret) {
        perror("Failed to update config map");
        return 1;
    }

    if (!map_fd[2]) {
        log_err("Failed to fetch receive count map");
        return -1;
    }
    ret = bpf_map_update_elem(map_fd[2], &rkey, &recv_count, 0);
    if (ret) {
        perror("Failed to update receive count map");
        return 1;
    }

    if (!map_fd[3]) {
        log_err("Failed to fetch drop count map");
        return -1;
    }
    ret = bpf_map_update_elem(map_fd[3], &dkey, &drop_count, 0);
    if (ret) {
            perror("Failed to update drop count map");
            return 1;
    }
    if (get_length(ports)) {
        log_info("Configured port list is %s\n", ports);
        update_ports(ports);
    }

    fflush(info);
    /* Handle signals and exit clean */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifdef __linux__
    signal(SIGHUP, signal_handler);
    pause();
#elif WIN32
    Sleep(INFINITE);
#endif
}