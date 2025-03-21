// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "bpf_ipfix_user.h"
#include <sys/wait.h>

#define CMD_MAX 2048
#define MAX_LENGTH 256

const char* egress_bpf_map = "egress_flow_record_info_map";
const char* last_egress_bpf_map = "last_egress_flow_record_info_map";
const char* ingress_bpf_map = "ingress_flow_record_info_map";
const char* last_ingress_bpf_map = "last_ingress_flow_record_info_map";
const char* ipfix_ingress_jmp_table = "ipfix_ingress_jmp_table";
const char* ipfix_egress_jmp_table = "ipfix_egress_jmp_table";

bool chain = false;
char* remote_ip = NULL;
char* bpf_map_file_path = NULL;
int flow_timeout = 30;
int remote_port = 49279;
int bpf_map_fd = -1;
int egress_fd = -1, last_egress_fd = -1, ingress_fd = -1, last_ingress_fd = -1;
int flow_timeout_counter = 3;
char *tc_cmd = "tc";
int if_idx;

const struct option long_options[] = {
    {"help",         no_argument, NULL, 'h' },
    {"iface",        required_argument, NULL, 'i' },
    {"collector_ip", required_argument, NULL, 'c' },
    {"direction", required_argument, NULL, 'd' },
    {"collector_port", required_argument, NULL, 'p' },
    {"flow-timeout", optional_argument, NULL, 't' },
    {"verbose (allowed 0-4, 0-NO_LOG,1-LOG_DEBUG,2-LOG_INFO,3-LOG_WARN,4-LOG_ERR,5-LOG_CRIT)", optional_argument, NULL, 'q' },
    {0, 0, NULL,  0 }
};

const char* ingress_sec = "ingress_flow_monitoring";
const char* egress_sec =  "egress_flow_monitoring";

FILE *info;
int verbosity;

static flow_record_t *flow_rec_to_create_ipfix = NULL;

void get_random_number(unsigned int *fid)
{
    uint8_t rand_buf[4];
    memset(rand_buf, 0, 4*sizeof(rand_buf[0]));
    int ret = RAND_bytes(rand_buf, sizeof(rand_buf));;
    if (ret != 1) {
        log_err("Random number generation failed");
    }  else {
        *fid = bytes_to_u32(rand_buf);
    }
}

void update_packet_byte_counters(flow_record_t *flow_rec, flow_record_t last_flow_rec, bool first_rec)
{
    if (!first_rec)
    {
        log_debug("Updating packet and byte delta count");
        flow_rec->np = flow_rec->np - last_flow_rec.np;
        flow_rec->nb = flow_rec->nb - last_flow_rec.nb;
        log_debug("Updating packet and byte source port %lu and %u",flow_rec->np, flow_rec->key.sp);
    }
}

flow_record_t* update_flow_record_to_create_ipfix(flow_record_t *flow_rec, bool first_rec,
                                                  flow_record_t last_flow_rec, int dir)
{
    log_debug("Updating interface index and flow id");
    if (!first_rec)
    {
        flow_rec->ingress_ifindex = last_flow_rec.ingress_ifindex;
	flow_rec->egress_ifindex = last_flow_rec.egress_ifindex;
        flow_rec->flow_id = last_flow_rec.flow_id;
    }
    else {
        unsigned int fid = 0;
        get_random_number(&fid);
        flow_rec->flow_id = fid;
        if(dir == EGRESS) {
            flow_rec->ingress_ifindex = if_idx;
            flow_rec->egress_ifindex = 0;
        }
        else if (dir == INGRESS){
            flow_rec->ingress_ifindex = if_idx;
            flow_rec->egress_ifindex = 0;
        }
    }
    return flow_rec;
}

bool delete_inactive_flow(int flow_idle_counter, int map_fd, int last_map_fd, unsigned int next_key) {
    /* If flow is inactive for more than 3 iterations (30 secs),
        Deleting flow_record from map */
    if(flow_idle_counter >= flow_timeout_counter)
    {
        log_debug("Flow is Idle.. Deleting flow from BPF map");
         bpf_map_delete_elem(map_fd,  &next_key);
         bpf_map_delete_elem(last_map_fd,  &next_key);
         return true;
    }
    else
        log_debug("Flow is active");
    return false;
}

int get_port(int dir) {
    int port = 0;
    if (dir == INGRESS)
	 port = IPFIX_EXPORT_INGRESS_LOCAL_PORT ;
    else if (dir == EGRESS)
	 port = IPFIX_EXPORT_EGRESS_LOCAL_PORT ;

    return port;
}

bool process_flow_record_map(int map_fd, int last_map_fd, int dir)
{
    unsigned int first_key = 0;
    unsigned int next_key = 0;
    bool ipfix_required = false, first_rec = false;
    int template_type = 1;
    int counter = 0;
    int local_port =  get_port(dir);

    while (!bpf_map_get_next_key(map_fd, &first_key, &next_key)) {
        template_type = 1;
        flow_record_t flow_rec, last_flow_rec;
        first_rec = false;
        flow_rec_to_create_ipfix = NULL;
       	bpf_map_lookup_elem(map_fd, &next_key, &flow_rec);

        /* Check if record already existed with same key */
        if (bpf_map_lookup_elem(last_map_fd, &next_key, &last_flow_rec) == -1)
            first_rec = true;
	/* If no new packets since last sent, IPFIX message sent is false. Not required to send IPFIX */
        if (!first_rec && flow_rec.np == last_flow_rec.np) {
            counter = last_flow_rec.counter ;
	    if(!delete_inactive_flow(counter, map_fd, last_map_fd, next_key))
            {
	        last_flow_rec.counter = counter + 1;
		bpf_map_update_elem(last_map_fd, &next_key, &last_flow_rec, 0);
	    }
            first_key = next_key;
            continue;
        }

        flow_rec_to_create_ipfix = update_flow_record_to_create_ipfix(&flow_rec,
                                                first_rec, last_flow_rec, dir);

        /* Update BPF last record info in map */
        bpf_map_update_elem(last_map_fd, &next_key, &flow_rec, 0);

        update_packet_byte_counters(flow_rec_to_create_ipfix,
                                    last_flow_rec,
                                    first_rec);

        /* If protocol is TCP and INGRESS use template_type 1(256) */
        /* If protocol is TCP and EGRESS use template_type 2(257) */
        /* If protocol is ICMP and INGRESS use template_type 3(258) */
        /* If protocol is ICMP and EGRESS use template_type 4(259) */
        if (flow_rec_to_create_ipfix->key.prot == 1 && flow_rec_to_create_ipfix->dir == 0)
            template_type = 3;
	else if (flow_rec_to_create_ipfix->key.prot == 1 && flow_rec_to_create_ipfix->dir == 1)
            template_type = 4;
	else if (flow_rec_to_create_ipfix->dir == 1)
            template_type = 2;
	else if (flow_rec_to_create_ipfix->dir == 0)
            template_type = 1;
        ipfix_create_template_data_set(flow_rec_to_create_ipfix, template_type,
			remote_ip, remote_port, local_port);
        ipfix_required = true ;
        first_key = next_key;
    }
    return ipfix_required;
}

bool validate_ifname(const char* input_ifname, char *output_ifname)
{
    size_t len;
    int i;
    char *iface;

    len = strnlen(input_ifname, IF_NAMESIZE);
    if (len >= IF_NAMESIZE) {
        return false;
    }
    for (i = 0; i < len; i++) {
        char c = input_ifname[i];

        if (!(isalpha(c) || isdigit(c) || c == '-'))
            return false;
    }
    iface = (void *)input_ifname;
    cpy(iface, output_ifname);

    return true;
}

int validate_str(const char *str) {
   int i;
   int l = get_length(str);
   if(l == 0 || l > MAX_LENGTH)
       return 0;
   for (i = 0; i < l; i++) {
        char c = str[i];

        if (!(isalpha(c) || isdigit(c)))
            return 0;
   }
   return 1;
}

bool validate_map(const char* input)
{
    size_t len;
    int i;

    len = get_length(input);
    if (len >= MAX_LENGTH) {
        return false;
    }
    for (i = 0; i < len; i++) {
        char c = input[i];
        if (!(isalpha(c) || isdigit(c) || c == '_'))
            return false;
    }
    return true;
}

bool validate_map_name(const char *path)
{
   int l = get_length(path);
   if(l == 0 && l > MAX_LENGTH)
       return false;
    char *tmp, *ptr;
    int n = 0, i;
    char *word_array[20], *map_array[10];
    tmp = strdup(path);
    while( (ptr = strsep(&tmp, "/")) != NULL )
    {
        if(get_length(ptr) > 0) {
            word_array[n++] = ptr;
        }
    }
    for(i = 0; i < n-1; i++) {
        if(!validate_str(word_array[i])) {
            return false;
        }
    }

    tmp = NULL;
    ptr = NULL;
    tmp = strdup(word_array[n-1]);
    n = 0;
    while( (ptr = strsep(&tmp, "_")) != NULL )
    {
        if(get_length(ptr) > 0) {
            map_array[n++] = ptr;
        }
    }
    for(i = 0; i < n; i++) {
        if(!validate_str(map_array[i])) {
            return false;
        }
    }
    return true;
}

int isFileExists(const char *path)
{
    fprintf(stdout, "Validating file path \n");
    // Check for file existence
    if (access(path, F_OK) == -1) {
       fprintf(stdout, "Not a valid file \n");
       return 0;

    }
    return 1;
}

void close_logfile(void)
{
    if (info != NULL) {
	fflush(info);
        fclose(info);
	return;
    }
    return;
}

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

void cpy(char *src, char *des)
{
     while((*(des++) = *(src++)));
     *des = '\0';
}

/**
 * Brief set the logging output to a file if given by user.
 *
 * return  file_ptr on success, NULL on  failure
 */
FILE* set_logfile(const char *file_name) {
    size_t len;
    len = strnlen(file_name, MAX_LENGTH);
    if (len >= MAX_LENGTH) {
        fprintf(stderr, "File name is not valid");
    }
    if (info != NULL){
        return info;
    }

    info = fopen(file_name, "a");
    if (info == NULL) {
        fprintf(stderr, "could not open log file ");
        return NULL;
    }

    fprintf(stderr, "writing errors/warnings/info/debug output to %s \n",file_name);
    return info;
}

void flow_record_poll(int map_fd, int last_map_fd, int dir)
{
    bool ipfix_required = false;

    /* Process IPFIX MAP */
    ipfix_required = process_flow_record_map(map_fd, last_map_fd, dir);

    if(ipfix_required)
        ipfix_export_send_message();
    else
        log_debug("No new flow is observed");

    fflush(info);
}

void usage(char *argv[], const char *doc)
{
    int i;
    printf("\nDOCUMENTATION:\n%s\n", doc);
    printf("\n");
    printf(" Usage: %s (options-see-below)\n", argv[0]);
    printf(" Listing options:\n");
    for (i = 0; long_options[i].name != 0; i++) {
        printf(" --%-15s", long_options[i].name);
        if (long_options[i].flag != NULL)
            printf(" flag (internal value:%d)", *long_options[i].flag);
        else
            printf("(internal short-option: -%c)", long_options[i].val);
        printf("\n");
    }
    printf("\n");
}

int get_length(const char *str)
{
    int len = 0;
    if (*str == '\0')
        return 0;
    while (str[len] != '\0')
       len++;

   return len;
}

/* Map filepath is created by l3afd */
int get_bpf_map_file(const char *ifname, const char *map_name, char *map_file)
{
    snprintf(map_file, MAP_PATH_SIZE, "%s/%s/%s", map_base_dir, ifname, map_name);
    log_info("map path filename %s", map_file);
    struct stat st = {0};
    if (stat(map_file, &st) != 0) {
        return -1;
    }
    return 0;
}

/* Close a file fd */
void close_fd(int fd){
  if(fd >= 0){
     close(fd);
  }
  return;
}
