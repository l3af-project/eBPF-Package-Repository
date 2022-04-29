// Copyright Contributors to the L3AF Project.
// SPDX-License-Identifier: Apache-2.0

#include "bpf/libbpf.h"
#include "bpf_load.h"

int prog_fd[2];
int map_fd[2];
char* bpf_log_buf;
int // 0 on success and sets prog_fd and map_fd, non-zero on failure and sets bpf_log_buf.
load_bpf_file(const char* filename)
{
    struct bpf_object_open_opts opts = { 0 };
    struct bpf_object* object = bpf_object__open_file(filename, &opts);
    if (object == 0) {
        return -1;
    }
    struct bpf_program* program = bpf_object__next_program(object, NULL);
    prog_fd[0] = bpf_program__fd(program);
    program = bpf_object__next_program(object, program);
    prog_fd[1] = bpf_program__fd(program);

    struct bpf_map* map = bpf_object__next_map(object, NULL);
    map_fd[0] = bpf_map__fd(map);
    map = bpf_object__next_map(object, map);
    map_fd[1] = bpf_map__fd(map);

    bpf_object__close(object);

    return 0;
}