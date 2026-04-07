# Makefile
CLANG    := clang
CFLAGS   := -g -O2 -target bpf -D__TARGET_ARCH_x86
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
