# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
BPF_CLANG    ?= clang
BPF_OBJCOPY  ?= llvm-objcopy
BPF_PROG     := bpf_ipfix_ingress.bpf.c bpf_ipfix_egress.bpf.c
USER_PROG_INGRESS    := bpf_ipfix_ingress_user.c bpf_ipfix_user.c ipfix.c
USER_PROG_EGRESS     := bpf_ipfix_egress_user.c bpf_ipfix_user.c ipfix.c

BPF_OBJ      := bpf_ipfix_ingress.bpf.o bpf_ipfix_egress.bpf.o
USER_OBJ_INGRESS     :=  bpf_ipfix_ingress 
USER_OBJ_EGRESS      :=  bpf_ipfix_egress

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
USER_LDFLAGS := -lbpf -lelf -lz -lcrypto

L3AF_SRC_PATH := $(CURDIR)

TOOLS_PATH := $(LIB_PATH)/tools

all: $(BPF_OBJ) $(USER_OBJ_INGRESS) $(USER_OBJ_EGRESS) tar.zip

$(LIB_PATH)/tools/vmlinux.h: 
		@echo " Generating vmlinux.h" $@ 
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@;

$(BPF_OBJ): $(BPF_PROG) $(LIB_PATH)/tools/vmlinux.h
		$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_OBJ_INGRESS): $(USER_PROG_INGRESS)
		$(BPF_CLANG) $(USER_CFLAGS) $(USER_PROG_INGRESS) -o $@ $(USER_LDFLAGS)

$(USER_OBJ_EGRESS): $(USER_PROG_EGRESS)
		$(BPF_CLANG) $(USER_CFLAGS) $(USER_PROG_EGRESS) -o $@ $(USER_LDFLAGS)

tar.zip:
	@rm -rf l3af_bpf_ipfix
	@rm -f l3af_bpf_ipfix.tar.gz
	@mkdir l3af_bpf_ipfix
	@cp $(L3AF_SRC_PATH)/bpf_ipfix_ingress l3af_bpf_ipfix/
	@cp $(L3AF_SRC_PATH)/bpf_ipfix_ingress.bpf.o l3af_bpf_ipfix/
	@cp $(L3AF_SRC_PATH)/bpf_ipfix_egress.bpf.o l3af_bpf_ipfix/
	@cp $(L3AF_SRC_PATH)/bpf_ipfix_egress l3af_bpf_ipfix/
	@tar -cvf l3af_bpf_ipfix.tar ./l3af_bpf_ipfix
	@gzip l3af_bpf_ipfix.tar

clean:
	@find $(CURDIR) -type f -name '*~' -delete
	@rm -f ./*.o
	@rm -f l3af_bpf_ipfix.tar.gz
	@rm -f bpf_ipfix_ingress bpf_ipfix_egress
