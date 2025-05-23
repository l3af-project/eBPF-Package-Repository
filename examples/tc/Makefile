# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
BPF_CLANG    ?= clang
BPF_OBJCOPY  ?= llvm-objcopy
BPF_PROG     := tcprog_ingress.bpf.c tcprog_egress.bpf.c
USER_PROG    := tcprog_user.c

BPF_OBJ      := tcprog_ingress.bpf.o tcprog_egress.bpf.o
USER_OBJ     := tcprog


KERNEL_RELEASE := $(shell uname -r)
LIB_PATH     := /usr/src/linux-headers-$(KERNEL_RELEASE)
BPF_CFLAGS   := -g -O2 -target bpf  -I.
BPF_CFLAGS += -I$(LIB_PATH)/tools/testing/selftests/bpf/
BPF_CFLAGS += -I$(LIB_PATH)/tools/lib/
BPF_CFLAGS += -I$(LIB_PATH)/tools/include
BPF_CFLAGS += -I$(LIB_PATH)/tools/perf
BPF_CFLAGS += -I$(LIB_PATH)/tools/
BPF_CFLAGS += -I$(LIB_PATH)/tools/bpf/resolve_btfids/libbpf
BPF_CFLAGS += -I$(LIB_PATH)/tools/bpf/resolve_btfids/libbpf/include

ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
    BPF_CFLAGS += -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
    BPF_CFLAGS += -D__TARGET_ARCH_arm64
endif

ifeq ($(ARCH),aarch64)
    BPF_CFLAGS += -D__LINUX_ARM_ARCH__=8
else ifeq ($(ARCH),armv7l)
    BPF_CFLAGS += -D__LINUX_ARM_ARCH__=7
else
    BPF_CFLAGS += 
endif


USER_CFLAGS  := -g -O2 -Wall -I. -I/usr/include/bpf  -Wunused-but-set-variable  -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -fno-asynchronous-unwind-tables
USER_CFLAGS += -I$(LIB_PATH)/tools/testing/selftests/bpf
USER_CFLAGS += -I$(LIB_PATH)/tools/lib
USER_CFLAGS += -I$(LIB_PATH)/tools/include
USER_CFLAGS += -I$(LIB_PATH)/tools/perf 
USER_LDFLAGS := -lbpf -lelf -lz

L3AF_SRC_PATH := $(CURDIR)

TOOLS_PATH := $(LIB_PATH)/tools

all: $(BPF_OBJ) $(USER_OBJ)

$(LIB_PATH)/tools/vmlinux.h: 
		@echo " Generating vmlinux.h" $@ 
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@;

$(BPF_OBJ): $(BPF_PROG) $(LIB_PATH)/tools/vmlinux.h
		$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_OBJ): $(USER_PROG)
		$(BPF_CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)


clean:
	@find $(CURDIR) -type f -name '*~' -delete
	@rm -f ./*.o
	@rm -f tcprog
