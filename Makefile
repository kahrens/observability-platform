# eBPF Observability Platform - Root Makefile
#
# Build requirements:
#   - clang 14+ (BPF compilation)
#   - bpftool (vmlinux.h generation)
#   - Go 1.22+
#   - linux-headers or kernel-devel matching running kernel
#
# On a new machine, run: make vmlinux.h
# Then: make build

CLANG      ?= clang
BPFTOOL    ?= bpftool
GO         ?= go

# Directories
PROBES_DIR := probes
COLLECTOR_DIR := collector

# Output
BINARY := collector

.PHONY: all vmlinux.h generate build clean run check-deps

all: build

# Check for required tools
check-deps:
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "Error: clang not found"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "Error: bpftool not found"; exit 1; }
	@command -v $(GO) >/dev/null 2>&1 || { echo "Error: go not found"; exit 1; }
	@test -f /sys/kernel/btf/vmlinux || { echo "Error: BTF not available (need CONFIG_DEBUG_INFO_BTF=y)"; exit 1; }

# Generate vmlinux.h from running kernel's BTF data
# This must be done on the target machine (or one with matching kernel)
vmlinux.h: check-deps
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(PROBES_DIR)/vmlinux.h
	@echo "Generated $(PROBES_DIR)/vmlinux.h"

# Run bpf2go to compile BPF C and generate Go bindings
# Requires vmlinux.h to exist
generate: $(PROBES_DIR)/vmlinux.h
	cd $(COLLECTOR_DIR) && $(GO) generate ./...
	@echo "Generated BPF Go bindings in $(COLLECTOR_DIR)/"

# Build the collector binary
build: generate
	$(GO) build -o $(BINARY) ./$(COLLECTOR_DIR)/
	@echo "Built $(BINARY)"

# Run with required privileges
run: build
	sudo ./$(COLLECTOR_DIR)/$(BINARY)

# Clean generated files
clean:
	rm -f $(PROBES_DIR)/vmlinux.h
	rm -f $(COLLECTOR_DIR)/probes_bpf*.go
	rm -f $(COLLECTOR_DIR)/probes_bpf*.o
	rm -f $(BINARY)

# Ensure vmlinux.h exists (for generate target dependency)
$(PROBES_DIR)/vmlinux.h:
	@echo "vmlinux.h not found. Run 'make vmlinux.h' first on a Linux system with BTF."
	@exit 1

# Download Go dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy
