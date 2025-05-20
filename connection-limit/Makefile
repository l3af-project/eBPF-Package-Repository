# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
BPF_CLANG    ?= clang
BPF_OBJCOPY  ?= llvm-objcopy
BPF_PROG     := connection_limit.bpf
USER_PROG    := connection_limit_user

BPF_OBJ      := $(BPF_PROG).o
USER_OBJ     := $(USER_PROG)

BPF_CFLAGS   := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I.
USER_CFLAGS  := -g -O2 -Wall -I. -I/usr/include/bpf -I/usr/include
USER_LDFLAGS := -lbpf -lelf -lz

L3AF_SRC_PATH := $(CURDIR)


all: $(BPF_OBJ) $(USER_OBJ) tar.zip

vmlinux.h: 
		@echo " Generating vmlinux.h" $@ 
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@;

$(BPF_OBJ): $(BPF_PROG).c vmlinux.h
		$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
		$(BPF_OBJCOPY) --strip-unneeded $@

$(USER_OBJ): $(USER_PROG).c
		$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

tar.zip:
	@rm -rf l3af_connection_limit 
	@rm -f l3af_connection_limit.tar.gz
	@mkdir l3af_connection_limit
	@cp $(L3AF_SRC_PATH)/connection_limit.bpf.o l3af_connection_limit/
	@cp $(L3AF_SRC_PATH)/connection_limit l3af_connection_limit/
	@tar -cvf l3af_connection_limit.tar ./l3af_connection_limit
	@gzip l3af_connection_limit.tar

clean:
	$(MAKE) -C $(LINUX_SRC_PATH) M=$(L3AF_SRC_PATH) clean
	@find $(CURDIR) -type f -name '*~' -delete
	@rm -f ./*.o
	@rm -f l3af_connection_limit.tar.gz
	@rm -rf l3af_connection_limit





