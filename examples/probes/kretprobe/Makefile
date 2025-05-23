# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
BPF_CLANG    ?= clang
BPF_OBJCOPY  ?= llvm-objcopy
L3AF_SRC_PATH := $(CURDIR)
KERNEL_RELEASE := $(shell uname -r)
LIB_PATH     := /usr/src/linux-headers-$(KERNEL_RELEASE)
BPF_OBJ := kretprobe.bpf.o
# BPF FLAGS
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

all: $(BPF_OBJ) tar.zip

$(LIB_PATH)/tools/vmlinux.h: 
		@echo " Generating vmlinux.h" $@ 
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@;

%.bpf.o: %.bpf.c $(LIB_PATH)/tools/vmlinux.h
	@echo "Compiling BPF program: $< -> $@"
	$(BPF_CLANG) $(BPF_CFLAGS) -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

tar.zip:
	@rm -rf l3af_kretprobe
	@rm -f l3af_kretprobe.tar.gz
	@mkdir l3af_kretprobe
	@cp $(L3AF_SRC_PATH)/kretprobe.bpf.o ./l3af_kretprobe
	@tar -cvf l3af_kretprobe.tar ./l3af_kretprobe
	@gzip l3af_kretprobe.tar

clean:
	@find $(CURDIR) -type f -name '*~' -delete
	@rm -f ./*.o
	@rm -f l3af_kretprobe.tar.gz
	@rm -rf l3af_kretprobe
