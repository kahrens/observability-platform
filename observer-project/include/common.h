// include/common.h
// Common definitions shared between eBPF and user-space programs
// This file is included by both program.bpf.c and main.c

#ifndef __COMMON_H
#define __COMMON_H

#include <stdbool.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>

// Defines

#define socklen_t __u64

// Data buffer message size. BPF can submit at most this amount of data to a perf buffer.
// Kernel size limit is 32KiB. See https://github.com/iovisor/bcc/issues/2519 for more details.
#define MAX_MSG_SIZE 30720  // 30KiB

// This defines how many chunks a perf_submit can support.
// This applies to messages that are over MAX_MSG_SIZE,
// and effectively makes the maximum message size to be CHUNK_LIMIT*MAX_MSG_SIZE.
#define CHUNK_LIMIT 4

// Maximum length for command name storage
// Linux TASK_COMM_LEN is 16, we use the same
#define TASK_COMM_LEN 16

// Maximum length for filename storage
// Keep this reasonable to avoid stack overflow in eBPF
#define MAX_FILENAME_LEN 256

enum traffic_direction_t {
    kEgress,
    kIngress,
};

// Structs

// A struct representing a unique ID that is composed of the pid, the file
// descriptor and the creation time of the struct.
struct conn_id_t {
    // Process ID
    __u32 pid;
    // The file descriptor to the opened network connection.
    __s32 fd;
    // Timestamp at the initialization of the struct.
    __u64 tsid;
};

// This struct contains information collected when a connection is established,
// via an accept4() syscall.
struct conn_info_t {
    // Connection identifier.
    struct conn_id_t conn_id;

    // The number of bytes written/read on this connection.
    __s64 wr_bytes;
    __s64 rd_bytes;

    // A flag indicating we identified the connection as HTTP.
    bool is_http;
};

// An helper struct that hold the addr argument of the syscall.
struct accept_args_t {
    struct sockaddr_in* addr;
};

// An helper struct to cache input argument of read/write syscalls between the
// entry hook and the exit hook.
struct data_args_t {
    __s32 fd;
    const char* buf;
};

// An helper struct that hold the input arguments of the close syscall.
struct close_args_t {
    __s32 fd;
};

// A struct describing the event that we send to the user mode upon a new connection.
struct socket_open_event_t {
    // The time of the event.
    __u64 timestamp_ns;
    // A unique ID for the connection.
    struct conn_id_t conn_id;
    // The address of the client.
    struct sockaddr_in addr;
};

// Struct describing the close event being sent to the user mode.
struct socket_close_event_t {
    // Timestamp of the close syscall
    __u64 timestamp_ns;
    // The unique ID of the connection
    struct conn_id_t conn_id;
    // Total number of bytes written on that connection
    __s64 wr_bytes;
    // Total number of bytes read on that connection
    __s64 rd_bytes;
};

struct socket_data_event_t {
  // We split attributes into a separate struct, because BPF gets upset if you do lots of
  // size arithmetic. This makes it so that it's attributes followed by message.
  struct attr_t {
    // The timestamp when syscall completed (return probe was triggered).
    __u64 timestamp_ns;

    // Connection identifier (PID, FD, etc.).
    struct conn_id_t conn_id;

    // The type of the actual data that the msg field encodes, which is used by the caller
    // to determine how to interpret the data.
    enum traffic_direction_t direction;

	// The size of the original message. We use this to truncate msg field to minimize the amount
    // of data being transferred.
    __s32 msg_size;

    // A 0-based position number for this event on the connection, in terms of byte position.
    // The position is for the first byte of this message.
    __u64 pos;
  } attr;
  char msg[MAX_MSG_SIZE];
};


#endif /* __COMMON_H */