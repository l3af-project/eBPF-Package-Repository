// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

/* TC program to filter and mirror the ingress traffic on a given interface
 */
static const char *__doc__ =
    " TC redirect benchmark\n\n"
    "  The bpf-object gets attached via TC cmdline tool\n";

#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "bpf/bpf.h"
#include "log.h"
#include "mirroring.h"

#define MAX_LENGTH 256

static int redirect_iface_fd = -1, src_fd = -1, dst_fd = -1,
           ingress_dst_port_fd = -1, ingress_src_port_fd = -1,
           egress_dst_port_fd = -1, egress_src_port_fd = -1,
           ingress_proto_fd = -1, egress_proto_fd = -1, ingress_any_fd = -1,
           egress_any_fd = -1;
static int any_rep_ingress = 0, any_rep_egress = 0;
static struct route_config r = {0};

int get_length(char *str)
{
    int len = 0;
    if (*str == '\0')
        return 0;
    while (str[len] != '\0')
    {
        len++;
    }
    return len;
}

void closeFd(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
    return;
}

void close_logfile(void)
{
    if (info != NULL)
    {
        fflush(info);
        fclose(info);
        return;
    }
    return;
}

void cleanup(void)
{
    close_logfile();
    closeFd(redirect_iface_fd);
    closeFd(src_fd);
    closeFd(dst_fd);
    closeFd(ingress_dst_port_fd);
    closeFd(ingress_src_port_fd);
    closeFd(egress_dst_port_fd);
    closeFd(egress_src_port_fd);
    closeFd(ingress_proto_fd);
    closeFd(egress_proto_fd);
    closeFd(ingress_any_fd);
    closeFd(egress_any_fd);
}
int read_addr(const char *addr, _inet_addr *res)
{
    res->family = AF_INET;
    res->bitlen = 32;
    return inet_pton(res->family, addr, res->data);
}

void cpy(char *dst, char *src)
{
    while ((*src) != '\0')
    {
        *dst++ = *src++;
    }
    *dst = '\0';
}

int rtattr_add(struct nlmsghdr *n, int maxlen, int type, const void *data,
               int alen)
{
    int len = RTA_LENGTH(alen); // data(alen(bytes))+header
    struct rtattr *rta;
    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
    {
        fprintf(stderr, "rtattr_add error: message exceeded bound of %d\n",
                maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen)
    {
        struct rtattr *ptr = RTA_DATA(rta);
        struct rtattr *d = (struct rtattr *)data;
        while (alen--)
        {
            *ptr++ = *d++;
        }
    }
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return 0;
}

int do_route(int socket, int cmd, int flags, _inet_addr *remote_ip,
             _inet_addr *gateway_ip, int nic_id)
{
    nl_request.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nl_request.n.nlmsg_flags = NLM_F_REQUEST | flags;
    nl_request.n.nlmsg_type = cmd;
    nl_request.r.rtm_table = RT_TABLE_MAIN;
    nl_request.r.rtm_scope = RT_SCOPE_LINK;
    nl_request.r.rtm_family = remote_ip->family;
    nl_request.r.rtm_dst_len = remote_ip->bitlen;

    /* Set additional flags if NOT deleting route */
    if (cmd != RTM_DELROUTE)
    {
        nl_request.r.rtm_protocol = RTPROT_BOOT;
        nl_request.r.rtm_type = RTN_UNICAST;
    }

    if (gateway_ip->bitlen != 0)
    {
        rtattr_add(&nl_request.n, sizeof(nl_request), RTA_GATEWAY,
                   &gateway_ip->data, gateway_ip->bitlen / 8);
        nl_request.r.rtm_scope = 0;
        nl_request.r.rtm_family = gateway_ip->family;
    }
    rtattr_add(&nl_request.n, sizeof(nl_request), RTA_DST, &remote_ip->data,
               remote_ip->bitlen / 8);
    rtattr_add(&nl_request.n, sizeof(nl_request), RTA_OIF, &nic_id,
               sizeof(int));

    return send(socket, &nl_request, sizeof(nl_request), 0);
}

int open_netlink(void)
{
    struct sockaddr_nl saddr;
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0)
    {
        fprintf(stderr, "Failed to open netlink socket");
        return EXIT_FAILURE;
    }
    memset(&saddr, 0, sizeof(saddr));
    return sock;
}

int nl_update_route(struct route_config r, int c)
{
    _inet_addr remote_ip = {0};
    _inet_addr gateway_ip = {0};

    int socket;
    int nl_command = 0;
    int nl_flags = 0;
    int send_ret;

    if (c == 0)
    { // adding a route
        nl_command = RTM_NEWROUTE;
        nl_flags = NLM_F_CREATE | NLM_F_EXCL;
    } // deleting a route
    else if (c == 1)
    {
        nl_command = RTM_DELROUTE;
        nl_flags = 0;
    }
    else
    {
        log_info("Unknown netlink-route operation");
    }

    if (read_addr(r.remote_ip, &remote_ip) != 1)
    {
        fprintf(stderr, "Failed to parse destination address %s\n", r.local_ip);
        return EXIT_FAILURE;
    }
    if (r.gateway_ip != NULL)
    {
        if (read_addr(r.gateway_ip, &gateway_ip) != 1)
        {
            fprintf(stderr, "No gateway or incorrect gateway address %s\n",
                    r.gateway_ip);
        }
    }
    socket = open_netlink();
    if (socket == EXIT_FAILURE)
    {
        return EXIT_FAILURE;
    }
    send_ret = do_route(socket, nl_command, nl_flags, &remote_ip, &gateway_ip,
                        r.nic_id);
    if (send_ret == -1)
    {
        log_err("Netlink message for updating the route failed, errno:%d",
                errno);
    }
    else
    {
        log_info(
            "Netlink message for updating the route was sent successfully. "
            "Length of message: %d",
            send_ret);
    }
    close(socket);
    return send_ret;
}

bool validate_netlink(struct route_config *r)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa, *nm;
    char *addr, *nmaddr;
    bool check = false;

    if (r == NULL)
    {
        fprintf(stderr, "ERR: No routing information provided\n");
        return false;
    }
    r->name = "tunnelRoute";

    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        // Sanity checks for the interface
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
            ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET)
        {
            if (strcmp(ifa->ifa_name, r->nic_name) != 0)
            {
                continue;
            }
            sa = (struct sockaddr_in *)ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            char *tmp = calloc(get_length(addr), 1);
            cpy(tmp, addr);
            r->local_ip = tmp;
            nm = (struct sockaddr_in *)ifa->ifa_netmask;
            nm->sin_addr.s_addr =
                ntohl(htonl(sa->sin_addr.s_addr & nm->sin_addr.s_addr) + 1);
            nmaddr = inet_ntoa(nm->sin_addr);
            if (r->gateway_ip)
            {
                log_info(" Gateway address manually specified %s\n",
                         r->gateway_ip);
            }
            else
            {
                r->gateway_ip = nmaddr;
                log_info("Default Gateway address automatically selected: %s\n",
                         r->gateway_ip);
            }
            check = true;
        }
    }

    if (!check)
    {
        fprintf(stderr, "Error in fetching the gateway/local_ip for %s\n",
                r->nic_name);
        return false;
    }
    return true;
}

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"iface", required_argument, NULL, 'i'},
    {"redirect-to", required_argument, NULL, 'e'},
    /* HINT assign: optional_arguments with '=' */
    { "direction", optional_argument, NULL, 't' },
    { "src-address", optional_argument, NULL, 's' },
    { "dst-address", optional_argument, NULL, 'd' },
    { "gtw-address", optional_argument, NULL, 'g' },
    { "src-port", optional_argument, NULL, 'u' },
    { "dst-port", optional_argument, NULL, 'U' },
    { "protocol", optional_argument, NULL, 'r' },
    { "tunnel-remote-address", optional_argument, NULL, 'D' },
    { "tunnel-interface-name", optional_argument, NULL, 'T' },
    { "tunnel-local-port", optional_argument, NULL, 'p' },
    { "tunnel-remote-port", optional_argument, NULL, 'P' },
    { "quiet", no_argument, NULL, 'q' },
    { 0, 0, NULL, 0 }
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
        printf(" --%-15s", long_options[i].name);
        if (long_options[i].flag != NULL)
        {
            printf(" flag (internal value:%d)", *long_options[i].flag);
        }
        else
        {
            printf("(internal short-option: -%c)", long_options[i].val);
        }
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
    strftime(tmbuf, TIMESTAMP_LEN, "%Y-%m-%d %H:%M:%S", nowtm);
#ifdef DARWIN
    snprintf(log_ts, TIMESTAMP_LEN, "%s.%06d", tmbuf, tv.tv_usec);
#else
    snprintf(log_ts, TIMESTAMP_LEN, "%s.%06ld", tmbuf, tv.tv_usec);
#endif
}

/* Set the logging output to the default log file configured */
FILE *set_log_file()
{
    if (info != NULL)
    {
        return info;
    }
    struct stat st = {0};
    // Creates LOG_PATH directory if not present
    if (stat(LOG_PATH, &st) == -1)
    {
        mkdir(LOG_PATH, 0755);
    }
    fprintf(stdout, "logfile is %s\n", DEFAULT_LOGFILE);
    info = fopen(DEFAULT_LOGFILE, "a");
    if (info == NULL)
    {
        fprintf(stderr, "could not open log file \n");
        return NULL;
    }
    fprintf(stderr, "writing errors/warnings/info/debug output to %s \n",
            DEFAULT_LOGFILE);
    return info;
}

char *trim_space(char *str)
{
    char *end;
    /* skip leading whitespace */
    while (isspace(*str))
    {
        str = str + 1;
    }
    /* remove trailing whitespace */
    end = str + get_length(str) - 1;
    while (end > str && isspace(*end))
    {
        end = end - 1;
    }
    /* write null character */
    *(end + 1) = '\0';
    return str;
}

bool validate_str(const char *input)
{
    size_t len;
    int i;

    len = get_length((void *)input);
    if (len >= MAX_LENGTH)
    {
        return false;
    }
    for (i = 0; i < len; i++)
    {
        char c = input[i];
        if (!(isalpha(c) || isdigit(c)))
        {
            return false;
        }
    }
    return true;
}

bool validate_map_name(char *path)
{
    if (get_length(path) == 0)
        return false;
    char *tmp, *ptr;
    int n = 0;
    char *word_array[20], *map_array[10];
    tmp = strdup(path);
    int i;
    while ((ptr = strsep(&tmp, "/")) != NULL)
    {
        if (get_length(ptr) > 0)
        {
            word_array[n++] = ptr;
        }
    }
    for (i = 0; i < n - 1; i++)
    {
        if (!validate_str(word_array[i]))
        {
            return false;
        }
    }
    tmp = NULL;
    ptr = NULL;
    tmp = strdup(word_array[n - 1]);
    n = 0;
    while ((ptr = strsep(&tmp, "_")) != NULL)
    {
        if (get_length(ptr) > 0)
        {
            map_array[n++] = ptr;
        }
    }
    for (i = 0; i < n; i++)
    {
        if (!validate_str(map_array[i]))
        {
            return false;
        }
    }
    return true;
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
    cpy(output_ifname, (void *)input_ifname);
    return true;
}

static int strtoi(const char *str)
{
    char *endptr;

    // Resetting errno
    errno = 0;

    long long_var = strtol(str, &endptr, 10);
    // out of range, extra chars at end
    if (errno == 0 && str && *endptr != 0)
    {
        log_info("valid  (but additional characters remain)\n");
    }
    else if (errno == 0 && str && !*endptr)
    {
        log_info("valid  (and represents all characters read) str: %s\n", str);
    }
    else if (errno != 0)
    {
        log_info(
            "is out of range String to int conversion not successful errno: "
            "%d, str: %s, val: %ld\n",
            errno, str, long_var);
    }
    return (int)long_var;
}

static bool validate_address(char *input_address,
                             network_addr_t output_address[], int *count)
{
    char *ptr, *tmp;
    char *prefixstr = NULL;
    long int prefix = MAX_IPV4_PREFIX;
    network_addr_t net_addr;
    tmp = strdup(input_address);
    while ((ptr = strsep(&tmp, delim)) != NULL)
    {
        ptr = trim_space(ptr);
        log_info("addr is %s\n", ptr);
        if ((prefixstr = strchr(ptr, '/')))
        {
            *prefixstr = '\0';
            prefixstr++;
            prefix = strtol(prefixstr, (char **)NULL, DECIMAL_BASE);
            prefix = (uint16_t)(strtoi(prefixstr));
            if ((*prefixstr == '\0') || (prefix < 0) ||
                (prefix > MAX_IPV4_PREFIX))
            {
                fprintf(stdout, "Invalid prefix %s. Please fix the config\n",
                        ptr);
                return false;
            }
        }
        net_addr.pfx = (int)prefix;
        cpy(net_addr.addr, ptr);
        cpy(output_address[*count].addr, net_addr.addr);
        output_address[*count].pfx = net_addr.pfx;
        (*count)++;
    }
    fprintf(stdout, "Address count is %d\n", *count);
    return true;
}

static bool validate_ports(const char *input)
{
    size_t len;
    int i;

    char *ptr, *tmp;
    len = get_length((void *)input);
    if (len >= MAX_LENGTH)
    {
        return false;
    }

    tmp = strdup(input);

    while ((ptr = strsep(&tmp, delim)) != NULL)
    {
        ptr = trim_space(ptr);

        for (i = 0; i < get_length((void *)ptr); i++)
        {
            char c = ptr[i];
            if (!(isdigit(c)))
                return false;
        }
    }
    return true;
}

// function to set the kth bit
static int setKthBit(int n, int k)
{
    // kth from lsb, starts with 0
    // kth bit of n is being set by this operation
    return ((1 << k) | n);
}

static void update_ports(int map_fd, char *ports, char *prog_type,
                         char *port_type)
{
    char *ptr, *tmp;
    uint32_t port = 0;
    uint32_t pval = 1;
    tmp = strdup(ports);
    int temp = -555;
    while ((ptr = strsep(&tmp, delim)) != NULL)
    {
        ptr = trim_space(ptr);
        port = (uint16_t)(strtoi(ptr));
        if (port == 0)
        {
            if (strcmp(prog_type, INGRESS) == 0 &&
                strcmp(port_type, "src") == 0)
            {
                any_rep_ingress = setKthBit(any_rep_ingress, 1);
            }
            else if (strcmp(prog_type, INGRESS) == 0 &&
                     strcmp(port_type, "dst") == 0)
            {
                any_rep_ingress = setKthBit(any_rep_ingress, 2);
            }
            else if (strcmp(prog_type, EGRESS) == 0 &&
                     strcmp(port_type, "src") == 0)
            {
                any_rep_egress = setKthBit(any_rep_egress, 1);
            }
            else if (strcmp(prog_type, EGRESS) == 0 &&
                     strcmp(port_type, "dst") == 0)
            {
                any_rep_egress = setKthBit(any_rep_egress, 2);
            }
        }
        else
        {
            temp = bpf_map_update_elem(map_fd, &port, &pval, BPF_ANY);
        }
    }
    free(tmp);
}

static void update_proto(int map_fd, char *protocols)
{
    char *ptr, *tmp;
    uint32_t proto_num = 0;
    uint32_t pval = 1;
    tmp = strdup(protocols);
    int temp = -555;
    while ((ptr = strsep(&tmp, delim)) != NULL)
    {
        ptr = trim_space(ptr);
        if (strcmp(ptr, "udp") == 0)
        {
            proto_num = (uint16_t)(strtoi("17"));
            temp = bpf_map_update_elem(map_fd, &proto_num, &pval, BPF_ANY);
        }
        else if (strcmp(ptr, "tcp") == 0)
        {
            proto_num = (uint16_t)(strtoi("6"));
            temp = bpf_map_update_elem(map_fd, &proto_num, &pval, BPF_ANY);
        }
        else if (strcmp(ptr, "icmp") == 0)
        {
            proto_num = (uint16_t)(strtoi("1"));
            temp = bpf_map_update_elem(map_fd, &proto_num, &pval, BPF_ANY);
        }
        else
        {
            log_err("Specified protocol not valid\n");
        }
    }
    free(tmp);
}

/* validate map file path */
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

int main(int argc, char **argv)
{
    char ifname[IF_NAMESIZE];
    char redirect_ifname[IF_NAMESIZE];
    bool src_addr_filter = false, dst_addr_filter = false;
    bool src_port_filter = false, dst_port_filter = false;
    bool proto_filter = false;

    char src_ports[2048];
    char dst_ports[2048];
    char protos[2048];

    int len = 0;

    int longindex = 0, opt, l;
    int tunnel_ifindex = -1, redirect_ifindex = -1, ifindex = -1;
    char *direction = NULL;
    network_addr_t src_addr[MAX_ADDRESSES], dst_addr[MAX_ADDRESSES], tmp[MAX_ADDRESSES], gtw_addr[MAX_ADDRESSES];
    int slen = 0, dlen = 0, tmplen = 0, glen = 0;
    int ret = EXIT_SUCCESS;
    char map_file[MAP_PATH_SIZE];

    memset(ifname, 0, IF_NAMESIZE); /* Can be used uninitialized */
    fprintf(stdout, "DEFAULT_LOGFILE is %s\n", DEFAULT_LOGFILE);
    set_log_file();
    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hq", long_options, &longindex)) !=
           -1)
    {
        switch (opt)
        {
        case 'e':
            if (!validate_ifname(optarg, (char *)&redirect_ifname))
            {
                fprintf(stderr, "ERR: input --egress ifname invalid\n");
            }
            redirect_ifindex = if_nametoindex(redirect_ifname);
            if (!(redirect_ifindex))
            {
                fprintf(stderr, "ERR: --egress \"%s\" not real dev\n",
                        redirect_ifname);
                return EXIT_FAILURE;
            }
            r.nic_name = redirect_ifname;
            r.nic_id = redirect_ifindex;
            break;
        case 'i':
            if (!validate_ifname(optarg, (char *)&ifname))
            {
                fprintf(stderr, "ERR: input --ingress ifname invalid\n");
            }
            if (!(ifindex = if_nametoindex(ifname)))
            {
                fprintf(stderr, "ERR: --ingress \"%s\" not real dev\n", ifname);
                return EXIT_FAILURE;
            }
            break;
        case 's':
            if (optarg && !validate_address(optarg, src_addr, &slen))
            {
                fprintf(stderr,
                        "ERR: input --src-address=source address invalid\n");
                return EXIT_FAILURE;
            }
            src_addr_filter = true;
            break;
        case 'd':
            if (optarg && !validate_address(optarg, dst_addr, &dlen))
            {
                fprintf(
                    stderr,
                    "ERR: input --dst-address=destination address invalid\n");
                return EXIT_FAILURE;
            }
            dst_addr_filter = true;
            break;
        case 'D':
            if (optarg && !validate_address(optarg, tmp, &tmplen))
            {
                fprintf(stderr, "ERR: input --tunnel-dst-address=destination "
                                "address invalid\n");
                return EXIT_FAILURE;
            }
            r.remote_ip = optarg;
            break;
        case 'g':
            if (optarg && !validate_address(optarg, gtw_addr, &glen))
            {
                fprintf(stderr,
                        "ERR: input --gtw-address=gateway address invalid\n");
                return EXIT_FAILURE;
            }
            r.gateway_ip = optarg;
            break;
        case 'u':
            if (optarg && !validate_ports(optarg))
            {
                fprintf(stderr, "ERR: list of src ports is invalid\n");
                return EXIT_FAILURE;
            }
            len = get_length(optarg);
            strncpy(src_ports, optarg, len);
            src_ports[len] = '\0';
            src_port_filter = true;
            printf("src_ports found %s\n", src_ports);
            break;
        case 'U':
            if (optarg && !validate_ports(optarg))
            {
                fprintf(stderr, "ERR: list of dst ports is invalid\n");
                return EXIT_FAILURE;
            }
            len = get_length(optarg);
            strncpy(dst_ports, optarg, len);
            dst_ports[len] = '\0';
            dst_port_filter = true;
            fprintf(stdout, "dst_ports found %s\n", dst_ports);
            break;
        case 't':
            if (optarg)
            {
                direction = trim_space(optarg);
            }
            break;
        case 'r':
            if (optarg)
            {
                len = get_length(optarg);
                strncpy(protos, optarg, len);
                protos[len] = '\0';
                proto_filter = true;
                fprintf(stdout, "protos found %s\n", protos);
            }
            break;
        case 'p':
            if (optarg)
            {
                r.sport = optarg;
                l = get_length(r.sport);
                r.sport[l] = '\0';
            }
            break;
        case 'P':
            if (optarg)
            {
                r.dport = optarg;
                l = get_length(r.dport);
                r.dport[l] = '\0';
            }
            break;
	case 'T':
	    if (optarg) {
                r.encap_interface_name = optarg;
                l = get_length(r.encap_interface_name);
                r.encap_interface_name[l] = '\0';
            }
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
    bool vn = validate_netlink(&r);
    if (!vn)
    {
        fprintf(stderr, "Not able to validate args for netlink\n");
        cleanup();
        exit(EXIT_FAILURE);
    }
    if (nl_update_route(r, 0) == -1)
    {
        log_err("Not able update the route for the tunnel interface");
        cleanup();
        exit(EXIT_FAILURE);
    }
    fflush(info);

    memset(map_file, '\0', MAP_PATH_SIZE);
    if (get_bpf_map_file(ifname, redirect_mapfile, map_file) < 0)
    {
        log_err("ERROR: map file path (%s) doesn't exists", map_file);
        cleanup();
        return EXIT_FAILURE;
    }
    log_info("Path file name redirect_mapfile %s", map_file);
    redirect_iface_fd = bpf_obj_get(map_file);
    if (redirect_iface_fd < 0)
    {
        log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                map_file, strerror(errno), errno);
        usage(argv);
        ret = EXIT_FAILURE;
    }

    if (strcmp(direction, INGRESS) == 0)
    {
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, src_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        src_fd = bpf_obj_get(map_file);
        if (src_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)", map_file,
                    strerror(errno), errno);
            usage(argv);
            cleanup();
            ret = EXIT_FAILURE;
        }
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, ingress_src_port_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        ingress_src_port_fd = bpf_obj_get(map_file);
        if (ingress_src_port_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            cleanup();
            ret = EXIT_FAILURE;
        }
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, ingress_dst_port_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        ingress_dst_port_fd = bpf_obj_get(map_file);
        if (ingress_dst_port_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            ret = EXIT_FAILURE;
        }
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, ingress_proto_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        ingress_proto_fd = bpf_obj_get(map_file);
        if (ingress_proto_fd < 0 && (strcmp(direction, INGRESS) == 0))
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            cleanup();
            ret = EXIT_FAILURE;
        }
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, ingress_any_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        ingress_any_fd = bpf_obj_get(map_file);
        log_info("ingress_any_fd: %d \n", ingress_any_fd);
        if (ingress_any_fd < 0 && (strcmp(direction, INGRESS) == 0))
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            ret = EXIT_FAILURE;
        }
    }
    else if (strcmp(direction, EGRESS) == 0)
    {
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, dst_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        dst_fd = bpf_obj_get(map_file);
        if (dst_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)", map_file,
                    strerror(errno), errno);
            usage(argv);
            ret = EXIT_FAILURE;
        }

        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, egress_src_port_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        egress_src_port_fd = bpf_obj_get(map_file);
        if (egress_src_port_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            cleanup();
            ret = EXIT_FAILURE;
        }
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, egress_dst_port_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        egress_dst_port_fd = bpf_obj_get(map_file);
        if (egress_dst_port_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            ret = EXIT_FAILURE;
        }
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, egress_proto_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        egress_proto_fd = bpf_obj_get(map_file);
        if (egress_proto_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            ret = EXIT_FAILURE;
        }
        memset(map_file, '\0', MAP_PATH_SIZE);
        if (get_bpf_map_file(ifname, egress_any_mapfile, map_file) < 0)
        {
            log_err("ERROR: map file path (%s) doesn't exists", map_file);
            cleanup();
            return EXIT_FAILURE;
        }
        egress_any_fd = bpf_obj_get(map_file);
        log_info("egress_any_fd: %d \n", egress_any_fd);
        if (egress_any_fd < 0)
        {
            log_err("ERROR: cannot open bpf_obj_get(%s): %s(%d)",
                    map_file, strerror(errno), errno);
            usage(argv);
            ret = EXIT_FAILURE;
        }
    }

    // reset errno
    errno = 0;

    tunnel_ifindex = if_nametoindex(r.encap_interface_name);
    /* Only update/set egress port when set via cmdline */
    int redirect_iface_key = 0;
    if (tunnel_ifindex != -1)
    {
        ret = bpf_map_update_elem(redirect_iface_fd, &redirect_iface_key,
                                  &tunnel_ifindex, 0);
        if (ret)
        {
            perror("ERROR: bpf_map_update_elem");
            cleanup();
            return EXIT_FAILURE;
        }
        if (verbose)
        {
            log_info("Change egress redirect ifindex to: %d", tunnel_ifindex);
        }
    }

    if (src_addr_filter)
    {
        log_info("Source address filter is set");
        if (strcmp(direction, EGRESS) == 0)
        {
            log_info("Cannot use source filter for egress mirroring");
            cleanup();
            return (EXIT_FAILURE);
        }
        uint32_t src_val = 1;
        int i = 0;
        for (i = 0; i < slen; i++)
        {
            log_info("src_addr[i].addr is %s\n", src_addr[i].addr);
            log_info("src_addr[i].pfx is %d\n", src_addr[i].pfx);
            size_t src_key_size;

            bpf_lpm_trie_key_t *src_key = NULL;
            src_key_size = sizeof(*src_key) + sizeof(__u32);
            src_key = malloc(src_key_size);

            src_key->prefixlen = src_addr[i].pfx;

            // check for any src IP
            if (strcmp(src_addr[i].addr, "0.0.0.0") == 0)
            {
                log_info("found 0/0/0/0, i.e., IP: 0.0.0.0");
                any_rep_ingress = setKthBit(any_rep_ingress, 0);
            }
            else
            {
                // 0/0/0/0 IP not found
                if (inet_pton(AF_INET, src_addr[i].addr, src_key->data) <= 0)
                {
                    log_err("Error converting source address to network "
                            "address %s",
                            src_addr[i].addr);
                    free(src_key);
                    cleanup();
                    return (EXIT_FAILURE);
                }
                if (bpf_map_update_elem(src_fd, src_key, &src_val, 0) < 0)
                {
                    log_err("Failed to update source endpoint bpf map");
                    perror("ERROR: bpf_map_update_elem");
                    free(src_key);
                    cleanup();
                    return (EXIT_FAILURE);
                }
            }
            free(src_key);
        }
    }

    if (dst_addr_filter)
    {
        log_info("Destination address filter is set");
        if (strcmp(direction, INGRESS) == 0)
        {
            log_info("Cannot use destination filter for ingress mirroring");
            cleanup();
            return (EXIT_FAILURE);
        }
        uint32_t dst_val = 1;
        int i = 0;
        for (i = 0; i < dlen; i++)
        {
            log_info("dst_addr[i].addr is %s", dst_addr[i].addr);
            log_info("dst_addr[i].pfx is %d", dst_addr[i].pfx);
            size_t dst_key_size;

            bpf_lpm_trie_key_t *dst_key = NULL;
            dst_key_size = sizeof(*dst_key) + sizeof(__u32);
            dst_key = malloc(dst_key_size);

            dst_key->prefixlen = dst_addr[i].pfx;

            if (strcmp(dst_addr[i].addr, "0.0.0.0") == 0)
            {
                any_rep_egress = setKthBit(any_rep_egress, 0);
            }
            else
            {
                if (inet_pton(AF_INET, dst_addr[i].addr, dst_key->data) <= 0)
                {
                    log_err("Failed to convert destination address to network "
                            "address %s",
                            dst_addr[i].addr);
                    free(dst_key);
                    cleanup();
                    return (EXIT_FAILURE);
                }
                if (bpf_map_update_elem(dst_fd, dst_key, &dst_val, 0) < 0)
                {
                    log_err("Failed to update destination endpoint bpf map");
                    perror("ERROR: bpf_map_update_elem");
                    free(dst_key);
                    cleanup();
                    return (EXIT_FAILURE);
                }
            }
            free(dst_key);
        }
    }
    int key = 0;
    if (strcmp(direction, INGRESS) == 0)
    {
        if (src_port_filter)
        {
            update_ports(ingress_src_port_fd, src_ports, INGRESS, "src");
        }
        // destination port might not be there
        if (dst_port_filter)
        {
            update_ports(ingress_dst_port_fd, dst_ports, INGRESS, "dst");
        }
        if (proto_filter == true)
        {
            update_proto(ingress_proto_fd, protos);
        }
        ret = bpf_map_update_elem(ingress_any_fd, &key, &any_rep_ingress, 0);
        if (ret)
        {
            perror("ERROR: bpf_map_update_elem");
            cleanup();
            return EXIT_FAILURE;
        }
    }
    else if (strcmp(direction, EGRESS) == 0)
    {
        if (src_port_filter)
        {
            update_ports(egress_src_port_fd, src_ports, EGRESS, "src");
        }
        if (dst_port_filter)
        {
            update_ports(egress_dst_port_fd, dst_ports, EGRESS, "dst");
        }
        if (proto_filter == true)
        {
            update_proto(egress_proto_fd, protos);
        }
        ret = bpf_map_update_elem(egress_any_fd, &key, &any_rep_egress, 0);
        if (ret)
        {
            perror("ERROR: bpf_map_update_elem");
            cleanup();
            return EXIT_FAILURE;
        }
    }

    log_info("any_rep_ingress %d", any_rep_ingress);
    log_info("any_rep_ingress bin");
    log_info("any_rep_egress %d", any_rep_egress);
    log_info("any_rep_egress bin");
    cleanup();
    return ret;
}
