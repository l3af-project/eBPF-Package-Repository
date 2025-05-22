// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

// #include "bpf_util.h"
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/perf_event.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "constants.h"
#include "log.h"

static const char *__doc__ =
    "Connection limit incoming TCP connections using XDP";

static int ifindex;

int conn_count_map_fd = -1, tcp_conns_map_fd = -1, conn_info_map_fd = -1;

static int get_length(const char *str);
static int is_ipv4_loopback(uint32_t *addr4);
static int is_ipv6_loopback(struct in6_addr *addr6);
static int str_split(char *input, char *delimiter, char *word_array[]);
static long strtoi(char *str, int base);
static void addr6_parser(char *input, struct in6_addr *localaddr);
int get_bpf_map_file(const char *ifname, const char *map_name, char *map_file);
void close_fd(int fd);
void close_all_fds(void);

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"iface", required_argument, NULL, 'i'},
    {"verbose", optional_argument, NULL, 'v'},
    {"direction", optional_argument, NULL, 'd'},
    {0, 0, NULL, 0}};

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
      printf(" flag (internal value:%d)", *long_options[i].flag);
    else
      printf(" short-option: -%c", long_options[i].val);
    printf("\n");
  }
  printf("\n");
}

/* Set log timestamps */
void log_timestamp(char *log_ts)
{
  struct timeval tv;
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[TIMESTAMP_LEN];

  gettimeofday(&tv, NULL);
  nowtime = tv.tv_sec;
  nowtm = localtime(&nowtime);
  strftime(tmbuf, DATE_LEN, "%Y-%m-%d %H:%M:%S", nowtm);
  snprintf(log_ts, DATE_LEN + TIMESTAMP_LEN, "%s.%06ld", tmbuf, tv.tv_usec);
}

/* Set the logging output to the default log file configured */
FILE *set_log_file(void)
{
  if (info != NULL)
  {
    return info;
  }
  info = fopen(DEFAULT_LOGFILE, "a");
  if (info == NULL)
  {
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

void close_fd(int fd)
{
  if (fd >= 0)
  {
    close(fd);
  }
  return;
}
void close_all_fds()
{
  close_fd(conn_count_map_fd);
  close_fd(tcp_conns_map_fd);
  close_fd(conn_info_map_fd);
}

void close_log_file(void)
{
  if (info != NULL)
  {
    fflush(info);
    fclose(info);
    return;
  }
  return;
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
      ((addr6->s6_addr32[3] & 0xff) == 0x7f))
    return 1;
  return 0;
}

static int str_split(char *input, char *delimiter, char *word_array[])
{
  char *tmp, *ptr;
  int n = 0;
  tmp = strdup(input);
  while ((ptr = strsep(&tmp, delimiter)) != NULL)
  {
    if (get_length(ptr) > 0)
    {
      word_array[n++] = ptr;
    }
  }
  return 0;
}

static long strtoi(char *str, int base)
{
  char *endptr;
  long long_var = strtol(str, &endptr, base);
  /* out of range, Found extra chars at end of string */
  if (*endptr != '\0' || str == endptr)
  {
    fprintf(stderr, "Failed to convert string %s to %s \n", str, endptr);
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
  strncpy(s2, input + 8, 8);
  s2[8] = '\0';
  strncpy(s3, input + 16, 8);
  s3[8] = '\0';
  strncpy(s4, input + 24, 8);
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

/* Parse /proc/net/tcp6 and update bpf maps with needed data
   conn_info_map_fd-> tcp_v6_conns: conn_info_map_fd: Holds TCP6 sockets in
   listen state conn_count_map_fd->conn_count: conn_count_map_fd: Holds the
   number of concurrent inbound connections in ESTABLISHED state */
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

  if (!line)
  {
    log_err("line from /proc/net/tcp is empty");
    return 0;
  }

  str_split(line, " ", proc_info);

  /* Get local address and local port */
  if (get_length(proc_info[1]) == 0)
    return 0;

  str_split(proc_info[1], ":", locals);
  len = get_length(locals[0]);
  strncpy(localaddr_str, locals[0], len);
  localaddr_str[len] = '\0';
  local_port = (int)(strtoi(locals[1], 16));

  if (get_length(proc_info[2]) == 0)
    return 0;
  str_split(proc_info[2], ":", remotes);
  len = get_length(remotes[0]);

  local_port_u = local_port;

  /* Parse address string and populate ipv6 address */
  addr6_parser(localaddr_str, &localaddr);

  /* Get skaddr */
  if (get_length(proc_info[11]) == 0)
    return 0;
  skaddr = strtoul(proc_info[11], &eptr, 16);

  /* Get state */
  if (get_length(proc_info[3]) == 0)
    return 0;

  state = (int)(strtoi(proc_info[3], 16));
  if (state == TCP_ESTABLISHED)
  {
    if (is_ipv6_loopback(&localaddr))
    {
      log_info("Skipping loopback ipv6 connections in established state\n");
      return 0;
    }
    if (bpf_map_lookup_elem(tcp_conns_map_fd, &local_port_u, &val) == 0)
    {
      ret = bpf_map_update_elem(conn_info_map_fd, &skaddr, &sock_val, 0);
      if (ret)
      {
        log_info("Failed to update socket in bpf map\n");
        perror("bpf_update_elem");
        return 1;
      }
      log_info("Updated ipv6 established connection: %s\n", line);
      if (bpf_map_lookup_elem(conn_count_map_fd, &key, &count) != 0)
      {
        log_info("Failed to fetch current established connections\n");
        return 1;
      }
      log_info("Updated TCPv6 connection in the map: %s\n", line);
      ;
      count++;
      if (bpf_map_update_elem(conn_count_map_fd, &key, &count, 0) != 0)
      {
        log_info("Failed to update current established connections\n");
        return 1;
      }
    }
  }

  return 0;
}

/* Parse /proc/net/tcp and update bpf maps with needed data
   tcp_conns_map_fd->tcp_v4_conns: Holds TCP4 sockets in listen state
   conn_count_map_fd->conn_count: Holds the number of concurrent inbound
   connections in ESTABLISHED state */
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

  char *proc_info[30];
  char *locals[3], *remotes[3];

  if (!line)
  {
    log_err("line from /proc/net/tcp is empty");
    return 0;
  }

  str_split(line, " ", proc_info);

  /* Get local address and local port */
  if (get_length(proc_info[1]) == 0)
    return 0;
  str_split(proc_info[1], ":", locals);
  local_addr = (uint32_t)(strtoi(locals[0], 16));
  local_port = (int)(strtoi(locals[1], 16));

  if (get_length(proc_info[2]) == 0)
    return 0;
  str_split(proc_info[2], ":", remotes);

  local_port_u = local_port;

  /* Get skaddr */
  if (get_length(proc_info[11]) == 0)
    return 0;
  skaddr = strtoul(proc_info[11], &eptr, 16);

  /* Get state */
  if (get_length(proc_info[3]) == 0)
    return 0;

  state = (int)(strtoi(proc_info[3], 16));
  if (state == TCP_ESTABLISHED)
  {
    if (is_ipv4_loopback(&local_addr))
    {
      log_info("Skipping ipv4 loopback connections in established state\n");
      return 0;
    }

    if (bpf_map_lookup_elem(tcp_conns_map_fd, &local_port_u, &val) == 0)
    {
      ret = bpf_map_update_elem(conn_info_map_fd, &skaddr, &sock_val, 0);
      if (ret)
      {
        log_info("Failed to update socket address in the bpf map\n");
        perror("bpf_update_elem");
        return 1;
      }
      if (bpf_map_lookup_elem(conn_count_map_fd, &key, &count) != 0)
      {
        log_info("Failed to fetch current established connections\n");
        return 1;
      }
      log_info("Updated TCPv4 connection in the map: %s\n", line);
      count++;
      if (bpf_map_update_elem(conn_count_map_fd, &key, &count, 0) != 0)
      {
        log_info("Failed to update current established connections\n");
        return 1;
      }
      log_info("Updated ipv4 established connection: %s\n", line);
    }
  }
  return 0;
}

static void parse_tcp(char *file, int (*proc)(int, char *))
{
  FILE *procinfo;
  char *buffer = NULL;
  size_t len = 0;
  int lnr = 0;

  procinfo = fopen(file, "r");
  if (!procinfo)
  {
    log_info("error\n");
    return;
  }
  while (getline(&buffer, &len, procinfo) != -1)
  {
    if (proc(lnr++, buffer))
      log_info("bogus data on line %s\n", buffer);
    if (buffer)
      free(buffer);
    buffer = NULL;
  }
  fclose(procinfo);
}

/* Validate map filepath */
int get_bpf_map_file(const char *ifname, const char *map_name, char *map_file)
{
  snprintf(map_file, MAP_PATH_SIZE, "%s/%s/%s", map_base_dir, ifname, map_name);
  log_info("map path filename %s", map_file);
  struct stat st = {0};
  if (stat(map_file, &st) != 0)
  {
    return -1;
  }
  return 0;
}

static bool validate_ifname(const char *input_ifname, char *output_ifname)
{
  size_t len;
  int i;

  len = get_length((void *)input_ifname);
  if (len >= IF_NAMESIZE)
  {
    return false;
  }
  for (i = 0; i < len; i++)
  {
    char c = input_ifname[i];

    if (!(isalpha(c) || isdigit(c) || c == '-'))
    {
      return false;
    }
  }
  strncpy(output_ifname, input_ifname, len);
  output_ifname[len] = '\0';
  return true;
}

int main(int argc, char **argv)
{
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  int opt, long_index = 0;
  char ports[PORT_LENGTH];
  char map_file[MAP_PATH_SIZE];
  char ifname[IF_NAMESIZE];

  verbosity = LOG_INFO;

  memset(ports, '\0', PORT_LENGTH);
  memset(ifname, '\0', IF_NAMESIZE);
  while ((opt = getopt_long(argc, argv, "hq", long_options, &long_index)) !=
         -1)
  {
    switch (opt)
    {
    case 'i':
      if (!validate_ifname(optarg, (char *)&ifname))
      {
        fprintf(stderr, "ERR: input ifname invalid\n");
      }
      if (!(ifindex = if_nametoindex(ifname)))
      {
        fprintf(stderr, "ERR: ifname \"%s\" not real dev\n", ifname);
        return EXIT_FAILURE;
      }
      break;
    case 'v':
      if (optarg)
        verbosity = (int)(strtoi(optarg, 10));
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

  memset(map_file, '\0', MAP_PATH_SIZE);
  if (get_bpf_map_file(ifname, conn_count_map_name, map_file) < 0)
  {
    log_err("ERROR: map file path (%s) doesn't exists\n", map_file);
    close_log_file();
    return EXIT_FAILURE;
  }
  conn_count_map_fd = bpf_obj_get(map_file);
  if (conn_count_map_fd < 0)
  {
    log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)\n", map_file,
            strerror(errno), errno);
  }
  memset(map_file, '\0', MAP_PATH_SIZE);
  if (get_bpf_map_file(ifname, tcp_conns_map_name, map_file) < 0)
  {
    close_log_file();
    close_all_fds();
    log_err("ERROR: map file path (%s) doesn't exists\n", map_file);
    return EXIT_FAILURE;
  }
  tcp_conns_map_fd = bpf_obj_get(map_file);
  if (tcp_conns_map_fd < 0)
  {
    log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)\n", map_file,
            strerror(errno), errno);
  }
  memset(map_file, '\0', MAP_PATH_SIZE);
  if (get_bpf_map_file(ifname, conn_info_map_name, map_file) < 0)
  {
    close_log_file();
    close_all_fds();
    log_err("ERROR: map file path (%s) doesn't exists\n", map_file);
    return EXIT_FAILURE;
  }
  conn_info_map_fd = bpf_obj_get(map_file);
  if (conn_info_map_fd < 0)
  {
    close_all_fds();
    log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)\n", map_file,
            strerror(errno), errno);
  }
  fflush(info);
  parse_tcp(PATH_PROCNET_TCP, parse_tcpv4);
  parse_tcp(PATH_PROCNET_TCP6, parse_tcpv6);

  close_log_file();
  close_all_fds();

  return 0;
}
