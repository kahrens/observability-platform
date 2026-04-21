# Makefile for libbpf-based eBPF project
# Handles compilation of eBPF programs, skeleton generation, and user-space app

# Compiler settings
# CLANG is used for eBPF programs (required for BPF target)
CLANG := clang

# CC is used for user-space programs (can be gcc or clang)
CC := gcc

# Target architecture - detect automatically
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Include paths for headers
INCLUDES := -Iinclude -Ibuild

# Compiler flags for eBPF programs
# -g: Include debug info (required for BTF)
# -O2: Optimization level (required for some BPF features)
# -target bpf: Generate BPF bytecode
# -D__TARGET_ARCH_$(ARCH): Define target architecture for CO-RE
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Compiler flags for user-space program
# -Wall -Wextra: Enable warnings
# -g: Debug info for debugging
USER_CFLAGS := -Wall -Wextra -g $(INCLUDES)

# Libraries for user-space program
# -lbpf: libbpf library
# -lelf: Required by libbpf
# -lz: Compression library (required by libbpf)
USER_LIBS := -lbpf -lelf -lz

# Output directories and files
BUILD_DIR := build
SRC_DIR := src
BPF_OBJ := $(BUILD_DIR)/observer.bpf.o
SKEL_H := $(BUILD_DIR)/observer.skel.h
USER_BIN := $(BUILD_DIR)/observer

# Default target: build everything
.PHONY: all
all: $(USER_BIN)

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h from kernel BTF
# This only needs to be done once per kernel version
$(BUILD_DIR)/vmlinux.h: | $(BUILD_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Compile the eBPF program to object file
# Dependencies: the source file and vmlinux.h
$(BPF_OBJ): $(SRC_DIR)/observer.bpf.c $(BUILD_DIR)/vmlinux.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -I$(BUILD_DIR) \
        -c $< -o $@

# Generate the skeleton header from the BPF object file
# The skeleton provides type-safe access to maps and programs
$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# Compile the user-space program
# Links against libbpf and includes the generated skeleton
$(USER_BIN): $(SRC_DIR)/main.c $(SKEL_H)
	$(CC) $(USER_CFLAGS) -I$(BUILD_DIR) \
        $< -o $@ $(USER_LIBS)

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Generate compile_commands.json for IDE support
.PHONY: compile_commands
compile_commands:
	bear -- make clean all

# Install to /usr/local/bin (requires root)
.PHONY: install
install: $(USER_BIN)
	install -m 755 $(USER_BIN) /usr/local/bin/

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all     - Build everything (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  install - Install binary to /usr/local/bin"
	@echo "  help    - Show this help message"