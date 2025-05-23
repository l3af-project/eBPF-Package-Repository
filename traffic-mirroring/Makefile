# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
BPF_CLANG    ?= clang
BPF_OBJCOPY  ?= llvm-objcopy
BPF_PROG     := mirroring_ingress.bpf.c mirroring_egress.bpf.c
USER_PROG    := mirroring.c

BPF_OBJ      := mirroring_ingress.bpf.o mirroring_egress.bpf.o
USER_OBJ     := mirroring


KERNEL_RELEASE := $(shell uname -r)
LIB_PATH     := /usr/src/linux-headers-$(KERNEL_RELEASE)
BPF_CFLAGS   := -g -O2 -target bpf -I.
BPF_CFLAGS += -I$(LIB_PATH)/tools/testing/selftests/bpf/
BPF_CFLAGS += -I$(LIB_PATH)/tools/lib/
BPF_CFLAGS += -I$(LIB_PATH)/tools/include
BPF_CFLAGS += -I$(LIB_PATH)/tools/perf
BPF_CFLAGS += -I$(LIB_PATH)/tools/
BPF_CFLAGS += -I$(LIB_PATH)/tools/bpf/resolve_btfids/libbpf
BPF_CFLAGS += -I$(LIB_PATH)/tools/bpf/resolve_btfids/libbpf/include
KERNEL_RELEASE := $(shell uname -r)
KERNEL_MAJOR := $(shell echo $(KERNEL_RELEASE) | cut -d. -f1)
KERNEL_MINOR := $(shell echo $(KERNEL_RELEASE) | cut -d. -f2)
KERNEL_PATCH := $(shell echo $(KERNEL_RELEASE) | cut -d. -f3 | sed 's/[^0-9].*//')
# Default patch to 0 if empty
ifeq ($(KERNEL_PATCH),)
  KERNEL_PATCH := 0
endif

LINUX_VERSION_CODE := $(shell echo "$$(( ($(KERNEL_MAJOR) << 16) + ($(KERNEL_MINOR) << 8) + $(KERNEL_PATCH) ))")

# Optional: print it
$(info Detected kernel version: $(KERNEL_MAJOR).$(KERNEL_MINOR).$(KERNEL_PATCH))
$(info Computed LINUX_VERSION_CODE: $(LINUX_VERSION_CODE))

BPF_CFLAGS += -DLINUX_VERSION_CODE=$(LINUX_VERSION_CODE)



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

all: $(BPF_OBJ) $(USER_OBJ) tar.zip

$(LIB_PATH)/tools/vmlinux.h: 
		@echo " Generating vmlinux.h" $@ 
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@;

$(BPF_OBJ): $(BPF_PROG) $(LIB_PATH)/tools/vmlinux.h
		$(BPF_CLANG) $(BPF_CFLAGS) -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

$(USER_OBJ): $(USER_PROG)
		$(BPF_CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

tar.zip:
	@rm -rf l3af_traffic_mirroring
	@rm -f l3af_traffic_mirroring.tar.gz
	@mkdir l3af_traffic_mirroring
	@cp $(L3AF_SRC_PATH)/mirroring l3af_traffic_mirroring/
	@cp $(L3AF_SRC_PATH)/mirroring_ingress.bpf.o l3af_traffic_mirroring/
	@cp $(L3AF_SRC_PATH)/mirroring_egress.bpf.o l3af_traffic_mirroring/
	@tar -cvf l3af_traffic_mirroring.tar ./l3af_traffic_mirroring
	@gzip l3af_traffic_mirroring.tar

clean:
	@find $(CURDIR) -type f -name '*~' -delete
	@rm -f ./*.o
	@rm -f $(L3AF_SRC_PATH)/mirroring
	@rm -f  $(L3AF_SRC_PATH)/l3af_traffic_mirroring.tar.gz
	@rm -rf $(L3AF_SRC_PATH)/l3af_traffic_mirroring





