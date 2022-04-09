extern int prog_fd[2];
extern int map_fd[2];
extern char* bpf_log_buf;
int load_bpf_file(const char* filename);
