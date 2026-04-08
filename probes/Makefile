# Makefile
CLANG    := clang
# Detect host arch and map to the name expected by bpf_tracing.h
ARCH     := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
CFLAGS   := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I/usr/include/bpf

all: vmlinux.h probes.bpf.o generate build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

probes.bpf.o: probes.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) $(INCLUDES) -c probes.bpf.c -o probes.bpf.o

generate:
	go generate ./...   # runs bpf2go, produces probes_bpfel.go + probes_bpfeb.go

build:
	go build -o collector ./collector/

run:
	sudo ./collector

clean:
	rm -f vmlinux.h probes.bpf.o collector
