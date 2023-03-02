// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#ifndef MIRRORING_H
#define MIRRORING_H

#define PATH_MAX          4096
#define CMD_MAX           2048
#define CMD_MAX_TC        256
#define MAX_IPV4_PREFIX   32
#define DECIMAL_BASE      10
#define MAP_PATH_MAX      1024
#define INGRESS           "ingress"
#define EGRESS            "egress"
#define DEFAULT_LOGFILE   "/var/log/l3af/mirroring.log"
#define LOG_PATH          "/var/log/l3af/"
#define NLMSG_TAIL(nmsg) ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

typedef struct network_addr {
    char addr[20];
    int pfx;

} network_addr_t;

typedef struct {
    char family;
    char bitlen;
    unsigned char data[sizeof(struct in_addr)];
} _inet_addr;

typedef struct bpf_lpm_trie_key bpf_lpm_trie_key_t;

struct {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[4096];
} nl_request;

struct route_config {
    char *name;
    char *sport;
    char *dport;
    char *local_ip;
    char *remote_ip;
    char *gateway_ip;
    char *nic_name;
    int nic_id;
    char *type;
    char *encap_type;
};

static const char *redirect_mapfile = "/sys/fs/bpf/tc/globals/redirect_iface";
static const char *src_mapfile = "/sys/fs/bpf/tc/globals/src_address";
static const char *dst_mapfile = "/sys/fs/bpf/tc/globals/dst_address";

static const char *ingress_src_port_mapfile = "/sys/fs/bpf/tc/globals/ingress_src_port";
static const char *ingress_dst_port_mapfile = "/sys/fs/bpf/tc/globals/ingress_dst_port";

static const char *egress_src_port_mapfile = "/sys/fs/bpf/tc/globals/egress_src_port";
static const char *egress_dst_port_mapfile = "/sys/fs/bpf/tc/globals/egress_dst_port";

static const char *ingress_proto_mapfile = "/sys/fs/bpf/tc/globals/ingress_proto";
static const char *egress_proto_mapfile = "/sys/fs/bpf/tc/globals/egress_proto";

static const char *ingress_any_mapfile = "/sys/fs/bpf/tc/globals/ingress_any";
static const char *egress_any_mapfile = "/sys/fs/bpf/tc/globals/egress_any";

static char map_file[MAP_PATH_MAX];
static bool chain = false;
static int verbose = 1;

static int tc_attach_bpf(char* dev, char* bpf_obj, char* dir);
static bool validate_ifname(const char* input_ifname, char *output_ifname);
static bool validate_address(char* input_address, network_addr_t output_address[], int *count);


/* Port separator */
const char delim[] = ",";

char * trim_space(char *str);
FILE* set_log_file(void);
int get_length(char *str);
int read_addr(const char *addr, _inet_addr *res);
void cpy(char* dst, char* src);
int rtattr_add(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen);
int do_route(int socket, int cmd, int flags, _inet_addr *remote_ip, _inet_addr *gateway_ip, int nic_id);
int open_netlink(void);
int exec_cmd(char *cmd[]);
int exec_shell(struct route_config *r);
int nl_update_route(struct route_config r, int c);
bool validate_netlink(struct route_config *r);
bool validate_str(const char* input);
bool validate_map_name(char *path);
#endif
