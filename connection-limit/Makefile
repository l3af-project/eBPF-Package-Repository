# Copyright Contributors to the L3AF Project.
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
BPF_CLANG    ?= clang
USER_PROG    := connection_limit_user.c
USER_OBJ     := connection_limit
L3AF_SRC_PATH := $(CURDIR)
KERNEL_RELEASE := $(shell uname -r)
LIB_PATH     := /usr/src/linux-headers-$(KERNEL_RELEASE)
BPF_OBJ := connection_limit.bpf.o
# BPF FlAGS
BPF_CFLAGS   := -g -O2 -target bpf  -I.
BPF_CFLAGS += -I$(LIB_PATH)/tools/testing/selftests/bpf/
BPF_CFLAGS += -I$(LIB_PATH)/tools/lib/
BPF_CFLAGS += -I$(LIB_PATH)/tools/include
BPF_CFLAGS += -I$(LIB_PATH)/tools/perf
BPF_CFLAGS += -I$(LIB_PATH)/tools/
BPF_CFLAGS += -I$(LIB_PATH)/tools/bpf/resolve_btfids/libbpf
BPF_CFLAGS += -I$(LIB_PATH)/tools/bpf/resolve_btfids/libbpf/include
BPF_CFLAGS += -emit-llvm
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


# USER PROGRAM FLAGS
USER_CFLAGS  := -g -O2 -Wall -I. -I/usr/include/bpf  -Wunused-but-set-variable  -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -fno-asynchronous-unwind-tables
USER_CFLAGS += -I$(LIB_PATH)/tools/testing/selftests/bpf
USER_CFLAGS += -I$(LIB_PATH)/tools/lib
USER_CFLAGS += -I$(LIB_PATH)/tools/include
USER_CFLAGS += -I$(LIB_PATH)/tools/perf 
USER_LDFLAGS := -lbpf -lelf -lz


all: $(BPF_OBJ) $(USER_OBJ) tar.zip

$(LIB_PATH)/tools/vmlinux.h: 
		@echo " Generating vmlinux.h" $@ 
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@;

%.bpf.o: %.bpf.c $(LIB_PATH)/tools/vmlinux.h
	@echo "Compiling BPF program: $< -> $@"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o - | llc -march=bpf -filetype=obj -o $@

$(USER_OBJ): $(USER_PROG)
		$(BPF_CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

tar.zip:
	@rm -rf l3af_connection_limit 
	@rm -f l3af_connection_limit.tar.gz
	@mkdir l3af_connection_limit
	@cp $(L3AF_SRC_PATH)/connection_limit.bpf.o l3af_connection_limit/
	@cp $(L3AF_SRC_PATH)/connection_limit l3af_connection_limit/
	@tar -cvf l3af_connection_limit.tar ./l3af_connection_limit
	@gzip l3af_connection_limit.tar

clean:
	@find $(CURDIR) -type f -name '*~' -delete
	@rm -f ./*.o
	@rm -f connection_limit
	@rm -f l3af_connection_limit.tar.gz
	@rm -rf l3af_connection_limit
