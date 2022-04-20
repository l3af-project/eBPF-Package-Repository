// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

#include "bpf_ipfix_user.h"
#include <sys/wait.h>

#define CMD_MAX 2048
#define MAX_LENGTH 256

const char* egress_bpf_map = "/sys/fs/bpf/tc/globals/egress_flow_record_info_map";
const char* last_egress_bpf_map = "/sys/fs/bpf/tc/globals/last_egress_flow_record_info_map";
const char* ingress_bpf_map = "/sys/fs/bpf/tc/globals/ingress_flow_record_info_map";
const char* last_ingress_bpf_map = "/sys/fs/bpf/tc/globals/last_ingress_flow_record_info_map";
const char* ipfix_ingress_jmp_table = "/sys/fs/bpf/tc/globals/ipfix_ingress_jmp_table";
const char* ipfix_egress_jmp_table = "/sys/fs/bpf/tc/globals/ipfix_egress_jmp_table";
const char* bpf_path = "/sys/fs/bpf/";
const char* ingress_dir = "ingress";
const char* egress_dir = "egress";

int ipfix_export_ingress_local_port = 4755;
int ipfix_export_egress_local_port = 4756;
bool chain = false;
char* remote_ip = NULL;
char* bpf_map_file_path = NULL;
int flow_timeout = 30;
int remote_port = 49279;
int bpf_map_fd = -1;
int egress_fd = -1, last_egress_fd = -1, ingress_fd = -1, last_ingress_fd = -1;
int flow_timeout_counter = 3;
char *tc_cmd = "tc";

const struct option long_options[] = {
    {"help",         no_argument, NULL, 'h' },
    {"iface",        required_argument, NULL, 'i' },
    {"collector_ip", required_argument, NULL, 'c' },
    {"direction", required_argument, NULL, 'd' },
    {"collector_port", required_argument, NULL, 'p' },
    {"tc-remove",    optional_argument, NULL, 'r' },
    {"flow-timeout", optional_argument, NULL, 't' },
    {"map-name", optional_argument, NULL, 'm' },
    {"verbose (allowed 0-4, 0-NO_LOG,1-LOG_DEBUG,2-LOG_INFO,3-LOG_WARN,4-LOG_ERR,5-LOG_CRIT)", optional_argument, NULL, 'q' },
    {0, 0, NULL,  0 }
};

const char* ingress_sec = "ingress_flow_monitoring";
const char* egress_sec =  "egress_flow_monitoring";

extern FILE *info;
extern int verbosity;

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
	 port = ipfix_export_ingress_local_port;
    else if (dir == EGRESS)
	 port = ipfix_export_egress_local_port;

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

int exec_cmd(char* cmd[]) {
    int pid, status, ret = 0;
    pid = fork();
    if(pid > 0) {
        waitpid(pid, &status, 0);
        if(WIFEXITED(status))  {
            log_info("Child process exited with status %d", status);
        }
    } else if(pid == 0) {
        ret = execvp(cmd[0], cmd) ;
        if( ret < 0) {
            perror("Command execution failed");
            return ret;
        }
    }
    return ret;
}

int validate_filter_args(const char* dev)
{
    int ret = 1;
    if (!validate_str(dev))
        return 0;
    return ret;
}

int tc_attach_filter(const char* dev, const char* bpf_obj, int dir, const char* sec)
{
    int ret = 1;
    char *direction;
    /* If chaining is not enabled, add qdisc */
    ret = validate_filter_args(dev);
    if (!ret)
        return 0;

    if(chain != true) {
        char *qdisc_cmd[] = {tc_cmd , "qdisc", "add", "dev", (void *)dev, "clsact", (char*)0};
        ret = exec_cmd(qdisc_cmd) ;
        /* Ignoring error, in case qdisc already added by any other process*/
        if( ret < 0)
            log_err("tc qdisc add failed");
    }

    if(dir == INGRESS) {
        direction = (void *)ingress_dir;
    } else {
        direction = (void *)egress_dir;
    }

    char *filter_cmd[] = {tc_cmd, "filter", "add", "dev", (void *)dev, direction,
                          "prio", "1", "handle", "1", "bpf", "da", "obj",
                           (void *)bpf_obj, "sec", (void *)sec, (char*)0};

    /* Attach tc filter */
    ret = exec_cmd(filter_cmd) ;
    if( ret < 0) {
        /* Exit with failed status*/
        perror("tc filter attach failed");
	close_logfile();
        exit(EXIT_FAILURE);
    }
    return 1;
}

int tc_cmd_filter(const char* dev, int dir, const char* action)
{
    int ret = 0;
    const char *direction;

    if(dir == INGRESS) {
        direction = ingress_dir;
    } else {
        direction = egress_dir;
    }
    if (!validate_str(direction))
        return 0;

    char* filter_cmd[] = {tc_cmd, "filter", (void *)action, "dev", (void *)dev, (void *)direction, (char*)0};
    /* Attach tc filter */
    ret = exec_cmd(filter_cmd) ;
    if( ret < 0) {
        /* Exit with failed status*/
        perror("tc filter attach failed");
        close_logfile();
        exit(EXIT_FAILURE);
    }
    return ret;
}

int tc_remove_filter(const char* dev, int dir)
{
    int ret = 0;
    const char *act = "del";
    ret = tc_cmd_filter(dev, dir, act);
    return ret;
}

// This method to unlink the program
int tc_remove_bpf(const char *map_filename) {
     int ret;
     int key = 0;
     int map_fd = bpf_obj_get(map_filename);
     if (map_fd < 0) {
         fprintf(stderr, "ERROR: map_fd of map not found: %s\n", strerror(map_fd));
         return -1;
     }

     ret = bpf_map_delete_elem(map_fd, &key);
     if (ret != 0) {
         fprintf(stderr, "ERROR(%d): tc chain remove program failed \n", ret);
     }
     return ret;
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

        if (!(isalpha(c) || isdigit(c)))
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

int validate_chain_args(const char *map_name) {
    int ret = 1;
    if (!validate_map_name(map_name)) {
        return 0;
    }
    return ret;
}

int  tc_chain_bpf(const char *map_name, const char *bpf_obj, const char *sec) {
    int ret = 1;
    ret = validate_chain_args(map_name);
    if(!ret)
        return 0;

    char *cmd[] = {"/sbin/tc" , "exec", "bpf", "graft", (void *)map_name, "key",
                   "0", "obj", (void *)bpf_obj, "sec", (void *)sec, (char*)0};

    /* Attach tc graft */
    ret = exec_cmd(cmd) ;
    if( ret < 0) {
        /* Exit with failed status*/
        perror("tc exec bpf graft failed");
        close_logfile();
        exit(EXIT_FAILURE);
    }
    return 1;
}

void tc_cleanup( bool chain, char *if_name, int dir,
		 const char* bpf_map,
		 const char* last_bpf_map,
		 char* bpf_map_file_path,
		 const char* ipfix_jmp_table) {
    int ret = 0;
    if (remove(last_bpf_map) < 0)
        fprintf(stderr, "Failed to remove map file - last_bpf_map\n");
    if (remove(bpf_map) < 0)
        fprintf(stderr, "Failed to remove map file - bpf_map\n");
    if (remove(ipfix_jmp_table) < 0)
        fprintf(stderr, "Failed to remove map file - ipfix_jmp_table\n");

    if (!chain) {
        ret = tc_remove_filter(if_name, dir);
        if(ret) {
	    fprintf(stderr,"ERR(%d): tc remove filter failed \n",
                WEXITSTATUS(ret));
	}
    }
    else {
        ret = tc_remove_bpf(bpf_map_file_path);
        if(ret) {
	    fprintf(stderr,"ERR(%d): tc remove filter failed \n",
                WEXITSTATUS(ret));
	}
    }
    if (bpf_map_file_path != NULL)
        free(bpf_map_file_path);
    return;
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
