// +build ignore

/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Maps

// Ring buffer map for sending data events to user-mode
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // 256 * 1024 = 256KB, enough for ~1000 events in buffer
    __uint(max_entries, 256 * 1024);
} socket_data_events SEC(".maps");

// Ring buffer map for sending open events to user-mode
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // 256 * 1024 = 256KB, enough for ~1000 events in buffer
    __uint(max_entries, 256 * 1024);
} socket_open_events SEC(".maps");

// Ring buffer map for sending close events to user-mode
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // 256 * 1024 = 256KB, enough for ~1000 events in buffer
    __uint(max_entries, 256 * 1024);
} socket_close_events SEC(".maps");

// A map of the active connections. The name of the map is conn_info_map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128 * 1024);
    __type(key, __u64);
    __type(value, struct conn_info_t);
} conn_info_map SEC(".maps");

// An helper map that will help us cache the input arguments of the accept syscall
// between the entry hook and the return hook.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10 * 1024);
    __type(key, __u64);
    __type(value, struct accept_args_t);
} active_accept_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u64);
    __type(value, struct socket_data_event_t);
} socket_data_event_buffer_heap SEC(".maps");

// Helper map to store write syscall arguments between entry and exit hooks.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10 * 1024);
    __type(key, __u64);
    __type(value, struct data_args_t);
} active_write_args_map SEC(".maps");

// Helper map to store read syscall arguments between entry and exit hooks.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10 * 1024);
    __type(key, __u64);
    __type(value, struct data_args_t);
} active_read_args_map SEC(".maps");

// An helper map to store close syscall arguments between entry and exit syscalls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10 * 1024);
    __type(key, __u64);
    __type(value, struct close_args_t);
} active_close_args_map SEC(".maps");


// Helper functions

// Generates a unique identifier using a tgid (Thread Global ID) and a fd (File Descriptor).
static __inline uint64_t gen_tgid_fd(uint32_t tgid, int fd) {
    return ((uint64_t)tgid << 32) | (uint32_t)fd;
}

// An helper function that checks if the syscall finished successfully and if it did
// saves the new connection in a dedicated map of connections
static __inline void process_syscall_accept(struct pt_regs* ctx, uint64_t id, const struct accept_args_t* args) {
    // Extracting the return code, and checking if it represent a failure,
    // if it does, we abort the as we have nothing to do.
    int ret_fd = PT_REGS_RC(ctx);
    if (ret_fd <= 0) {
        return;
    }

    struct conn_info_t conn_info = {};
    uint32_t pid = id >> 32;
    conn_info.conn_id.pid = pid;
    conn_info.conn_id.fd = ret_fd;
    conn_info.conn_id.tsid = bpf_ktime_get_ns();

    uint64_t pid_fd = ((uint64_t)pid << 32) | (uint32_t)ret_fd;
    // Saving the connection info in a global map, so in the other syscalls
    // (read, write and close) we will be able to know that we have seen
    // the connection
    bpf_map_update_elem(&conn_info_map, &pid_fd, &conn_info, 0);

    // Sending an open event to the user mode, to let the user mode know that we
    // have identified a new connection.
    struct socket_open_event_t* open_event = bpf_ringbuf_reserve(&socket_open_events, sizeof(struct socket_open_event_t), 0);
    if (open_event == NULL) {
        // If we can't reserve space in the ring buffer, we can't send the event, but
        // we can still keep tracking the connection, so we just return.
        return;
    }   
    open_event->timestamp_ns = bpf_ktime_get_ns();
    open_event->conn_id = conn_info.conn_id;
	bpf_probe_read(&open_event->addr, sizeof(open_event->addr), args->addr);
    bpf_ringbuf_submit(&socket_open_events, 0);
}

static inline __attribute__((__always_inline__)) void process_syscall_close(struct pt_regs* ctx, uint64_t id,
                                                                            const struct close_args_t* close_args) {
    int ret_val = PT_REGS_RC(ctx);
    if (ret_val < 0) {
        return;
    }

    uint32_t tgid = id >> 32;
    uint64_t tgid_fd = gen_tgid_fd(tgid, close_args->fd);
    struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info == NULL) {
        // The FD being closed does not represent an IPv4 socket FD.
        return;
    }

    // Send to the user mode an event indicating the connection was closed.
    struct socket_close_event_t *close_event = bpf_ringbuf_reserve(&socket_close_events, sizeof(struct socket_close_event_t), 0);
    close_event->timestamp_ns = bpf_ktime_get_ns();
    close_event->conn_id = conn_info->conn_id;
    close_event->rd_bytes = conn_info->rd_bytes;
    close_event->wr_bytes = conn_info->wr_bytes;

    bpf_ringbuf_submit(&socket_close_events, 0);

    // Remove the connection from the mapping.
    bpf_map_delete_elem(&conn_info_map, &tgid_fd);
}

static inline __attribute__((__always_inline__)) bool is_http_connection(struct conn_info_t* conn_info, const char* buf, size_t count) {
    // If the connection was already identified as HTTP connection, no need to re-check it.
    if (conn_info->is_http) {
        return true;
    }

    // The minimum length of http request or response.
    if (count < 16) {
        return false;
    }

    bool res = false;
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        res = true;
    }
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
        res = true;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
        res = true;
    }

    if (res) {
        conn_info->is_http = true;
    }

    return res;
}

static __inline void perf_submit_buf(struct pt_regs* ctx, const enum traffic_direction_t direction,
                                     const char* buf, size_t buf_size, size_t offset,
                                     struct conn_info_t* conn_info) {

    // Reserve space in the ring buffer upfront
    struct socket_data_event_t *event;
    event = (struct socket_data_event_t *)bpf_ringbuf_reserve(&socket_data_events, sizeof(*event), 0);
    if (!event)
        return;

    switch (direction) {
        case kEgress:
            event->attr.pos = conn_info->wr_bytes + offset;
            break;
        case kIngress:
            event->attr.pos = conn_info->rd_bytes + offset;
            break;
    }

    // Note that buf_size_minus_1 will be positive due to the if-statement above.
    size_t buf_size_minus_1 = buf_size - 1;

    // Clang is too smart for us, and tries to remove some of the obvious hints we are leaving for the
    // BPF verifier. So we add this NOP volatile statement, so clang can't optimize away some of our
    // if-statements below.
    // By telling clang that buf_size_minus_1 is both an input and output to some black box assembly
    // code, clang has to discard any assumptions on what values this variable can take.
    asm volatile("" : "+r"(buf_size_minus_1) :);

    buf_size = buf_size_minus_1 + 1;

    // 4.14 kernels reject bpf_probe_read with size that they may think is zero.
    // Without the if statement, it somehow can't reason that the bpf_probe_read is non-zero.
    size_t amount_copied = 0;
    if (buf_size_minus_1 < MAX_MSG_SIZE) {
        bpf_probe_read(&event->msg, buf_size, buf);
        amount_copied = buf_size;
    } else {
        bpf_probe_read(&event->msg, MAX_MSG_SIZE, buf);
        amount_copied = MAX_MSG_SIZE;
    }

    // If-statement is redundant, but is required to keep the 4.14 verifier happy.
    if (amount_copied > 0) {
        event->attr.msg_size = amount_copied;
        // Submit only the bytes actually used, not the full struct
        bpf_ringbuf_submit(event, 0);
    } else {
        // Must discard if we're not submitting, to release the reservation
        bpf_ringbuf_discard(event, 0);
    }
}

static __inline void perf_submit_wrapper(struct pt_regs* ctx,
                                         const enum traffic_direction_t direction, const char* buf,
                                         const size_t buf_size, struct conn_info_t* conn_info,
                                         struct socket_data_event_t* event) {
    int bytes_sent = 0;
    unsigned int i;
#pragma unroll
    for (i = 0; i < CHUNK_LIMIT; ++i) {
        const int bytes_remaining = buf_size - bytes_sent;
        const size_t current_size = (bytes_remaining > MAX_MSG_SIZE && (i != CHUNK_LIMIT - 1)) ? MAX_MSG_SIZE : bytes_remaining;
        perf_submit_buf(ctx, direction, buf + bytes_sent, current_size, bytes_sent, conn_info);
        bytes_sent += current_size;
        if (buf_size == bytes_sent) {
            return;
        }
    }
}

static inline __attribute__((__always_inline__)) void process_data(struct pt_regs* ctx, uint64_t id,
                                                                   enum traffic_direction_t direction,
                                                                   const struct data_args_t* args, ssize_t bytes_count) {
    // Always check access to pointer before accessing them.
    if (args->buf == NULL) {
        return;
    }

    // For read and write syscall, the return code is the number of bytes written or read, so zero means nothing
    // was written or read, and negative means that the syscall failed. Anyhow, we have nothing to do with that syscall.
    if (bytes_count <= 0) {
        return;
    }

    uint32_t pid = id >> 32;
    uint64_t pid_fd = ((uint64_t)pid << 32) | (uint32_t)args->fd;
    struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &pid_fd);
    if (conn_info == NULL) {
        // The FD being read or written does not represent an IPv4 socket FD.
        return;
    }

    // Check if the connection is already HTTP, or check if that's a new connection, check protocol and return true if that's HTTP.
    if (is_http_connection(conn_info, args->buf, bytes_count)) {
        // allocate new event.
        uint32_t kZero = 0;
        struct socket_data_event_t* event = bpf_map_lookup_elem(&socket_data_event_buffer_heap, &kZero);
        if (event == NULL) {
            return;
        }

        // Fill the metadata of the data event.
        event->attr.timestamp_ns = bpf_ktime_get_ns();
        event->attr.direction = direction;
        event->attr.conn_id = conn_info->conn_id;

        perf_submit_wrapper(ctx, direction, args->buf, bytes_count, conn_info, event);
    }

	// Update the conn_info total written or read bytes.
	switch (direction) {
        case kEgress:
            conn_info->wr_bytes += bytes_count;
            break;
        case kIngress:
            conn_info->rd_bytes += bytes_count;
            break;
    }
}

// Hooks
int syscall__probe_entry_accept(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Keep the addr in a map to use during the exit method.
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)addr;
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);

    return 0;
}

int syscall__probe_ret_accept(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Pulling the addr from the map.
    struct accept_args_t* accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);
    if (accept_args != NULL) {
        process_syscall_accept(ctx, id, accept_args);
    }

    bpf_map_delete_elem(&active_accept_args_map, &id);
    return 0;
}


// Hooking the entry of accept4
// the signature of the syscall is int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int syscall__probe_entry_accept4(struct pt_regs* ctx, int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    // Getting a unique ID for the relevant thread in the relevant pid.
    // That way we can link different calls from the same thread.
    uint64_t id = bpf_get_current_pid_tgid();

    // Keep the addr in a map to use during the accpet4 exit hook.
    struct accept_args_t accept_args = {};
    accept_args.addr = (struct sockaddr_in *)addr;
    bpf_map_update_elem(&active_accept_args_map, &id, &accept_args, BPF_ANY);

    return 0;
}

// Hooking the exit of accept4
int syscall__probe_ret_accept4(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Pulling the addr from the map.
    struct accept_args_t* accept_args = bpf_map_lookup_elem(&active_accept_args_map, &id);
    // If the id exist in the map, we will get a non empty pointer that holds
    // the input address argument from the entry of the syscall.
    if (accept_args != NULL) {
        process_syscall_accept(ctx, id, accept_args);
    }

    // Anyway, in the end clean the map.
    bpf_map_delete_elem(&active_accept_args_map, &id);
    return 0;
}

// original signature: ssize_t write(int fd, const void *buf, size_t count);
int syscall__probe_entry_write(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args_t write_args = {};
    write_args.fd = fd;
    write_args.buf = buf;
    bpf_map_update_elem(&active_write_args_map, &id, &write_args, BPF_ANY);

    return 0;
}

int syscall__probe_ret_write(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    ssize_t bytes_count = PT_REGS_RC(ctx); // Also stands for return code.

    // Unstash arguments, and process syscall.
    struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_map, &id);
    if (write_args != NULL) {
        process_data(ctx, id, kEgress, write_args, bytes_count);
    }

    bpf_map_delete_elem(&active_write_args_map, &id);
    return 0;
}

// original signature: ssize_t read(int fd, void *buf, size_t count);
int syscall__probe_entry_read(struct pt_regs* ctx, int fd, char* buf, size_t count) {
    uint64_t id = bpf_get_current_pid_tgid();

    // Stash arguments.
    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.buf = buf;
    bpf_map_update_elem(&active_read_args_map, &id, &read_args, BPF_ANY);

    return 0;
}

int syscall__probe_ret_read(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    // The return code the syscall is the number of bytes read as well.
    ssize_t bytes_count = PT_REGS_RC(ctx);
    struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_map, &id);
    if (read_args != NULL) {
        // kIngress is an enum value that let's the process_data function
        // to know whether the input buffer is incoming or outgoing.
        process_data(ctx, id, kIngress, read_args, bytes_count);
    }

    bpf_map_delete_elem(&active_read_args_map, &id);
    return 0;
}
// original signature: int close(int fd)
int syscall__probe_entry_close(struct pt_regs* ctx, int fd) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct close_args_t close_args;
    close_args.fd = fd;
    bpf_map_update_elem(&active_close_args_map, &id, &close_args, BPF_ANY);

    return 0;
}

int syscall__probe_ret_close(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    const struct close_args_t* close_args = bpf_map_lookup_elem(&active_close_args_map, &id);
    if (close_args != NULL) {
        process_syscall_close(ctx, id, close_args);
    }

    bpf_map_delete_elem(&active_close_args_map, &id);
    return 0;
}