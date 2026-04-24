// probes.bpf.c — unified eBPF probes for TCP session observability
//
// Symmetric design: both client (connect) and server (accept) paths flow
// through tracepoint/sock/inet_sock_set_state so every connection is
// recorded the same way regardless of role.
//
// Per-connection data collected:
//   - 4-tuple, role, pid, comm
//   - RTT estimate (tcp_sock.srtt_us >> 3) at ESTABLISHED time
//   - Session duration (close_ts - open_ts, computed in kernel)
//   - Bytes sent and received (accumulated by fexit/tcp_sendmsg+recvmsg)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ── Event types ────────────────────────────────────────────────
#define EVENT_PROCESS   1
#define EVENT_TCP_OPEN  2
#define EVENT_TCP_CLOSE 3

// TCP states (stable Linux UAPI values)
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3

// Not in vmlinux.h BTF section — stable UAPI
#define AF_INET     2
#define IPPROTO_TCP 6

// ── exec_event: one per execve syscall ────────────────────────
struct exec_event {
    __u8  type;           // EVENT_PROCESS
    __u8  _pad[3];
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 _pad1;          // align timestamp_ns to 8 bytes
    __u64 timestamp_ns;
    char  comm[16];
    char  filename[128];
};

_Static_assert(sizeof(struct exec_event) == 176,
    "exec_event size mismatch — update Go ExecEvent struct");

// ── conn_event: TCP open and close ────────────────────────────
// On EVENT_TCP_OPEN:  all fields set; duration_ns/tx_bytes/rx_bytes are 0.
// On EVENT_TCP_CLOSE: all fields set including duration and byte counts.
struct conn_event {
    __u8  type;           // EVENT_TCP_OPEN or EVENT_TCP_CLOSE
    __u8  role;           // 0 = client (connect), 1 = server (accept)
    __u8  _pad[2];
    __u32 pid;            // 0 for server-side opens (softirq context)
    __u64 sock_id;        // kernel sock pointer — unique connection ID
    __u64 ts_ns;          // ESTABLISHED time (open) or close time
    __u32 saddr;          // local IPv4 (host byte order)
    __u32 daddr;          // remote IPv4 (host byte order)
    __u16 sport;          // local port (host byte order)
    __u16 dport;          // remote port (host byte order)
    __u8  _pad2[4];
    char  comm[16];       // empty for server-side opens (softirq has no user context)
    __u32 rtt_us;         // smoothed RTT in µs (srtt_us>>3); may be 0 at SYN_SENT→ESTABLISHED
    __u32 _pad3;
    __u64 duration_ns;    // session duration; 0 on open events
    __u64 tx_bytes;       // bytes sent via tcp_sendmsg; 0 on open events
    __u64 rx_bytes;       // bytes received via tcp_recvmsg; 0 on open events
};

_Static_assert(sizeof(struct conn_event) == 88,
    "conn_event size mismatch — update Go ConnEvent struct");

// ── conn_open_info: live connection state in active_conns ─────
struct conn_open_info {
    __u64 open_ts_ns;
    __u64 tx_bytes;       // accumulated by fexit/tcp_sendmsg
    __u64 rx_bytes;       // accumulated by fexit/tcp_recvmsg
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  role;
    __u8  _pad[3];
    __u32 rtt_us;
    char  comm[16];
};

// ── pre_conn: scratch stashed at fentry/tcp_connect ───────────
// Consumed by inet_sock_set_state when the connection reaches ESTABLISHED.
struct pre_conn {
    __u64 ts_ns;
    __u32 pid;
    __u8  _pad[4];
    char  comm[16];
};

// ── Maps ───────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} conn_events SEC(".maps");

// Keyed by sock pointer; tracks every open TCP connection.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct conn_open_info);
} active_conns SEC(".maps");

// Scratch: populated at fentry/tcp_connect, consumed at ESTABLISHED.
// Keyed by sock pointer (stable for the full connection lifetime).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pre_conn);
} connect_scratch SEC(".maps");

// ── Probe 1: process execution ────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e) return 0;

    e->type         = EVENT_PROCESS;
    e->pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid         = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid          = bpf_get_current_uid_gid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename),
                            (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Probe 2: TCP active open — client side ────────────────────
// Fires in process context: pid and comm identify the connecting process.
// The socket is not ESTABLISHED yet; stash in connect_scratch for probe 5.

SEC("fentry/tcp_connect")
int BPF_PROG(trace_tcp_connect, struct sock *sk)
{
    __u64 sock_id = (unsigned long)sk;
    struct pre_conn pc = {};
    pc.ts_ns = bpf_ktime_get_ns();
    pc.pid   = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(pc.comm, sizeof(pc.comm));
    bpf_map_update_elem(&connect_scratch, &sock_id, &pc, BPF_ANY);
    return 0;
}

// ── Probe 3: bytes sent ───────────────────────────────────────
// fexit fires after tcp_sendmsg returns; ret is bytes written (> 0) or error.

SEC("fexit/tcp_sendmsg")
int BPF_PROG(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg,
             size_t size, int ret)
{
    if (ret <= 0) return 0;
    __u64 sock_id = (unsigned long)sk;
    struct conn_open_info *info = bpf_map_lookup_elem(&active_conns, &sock_id);
    if (!info) return 0;
    __sync_fetch_and_add(&info->tx_bytes, (__u64)ret);
    return 0;
}

// ── Probe 4: bytes received ───────────────────────────────────
// fexit fires after tcp_recvmsg returns; ret is bytes read (> 0) or error.

SEC("fexit/tcp_recvmsg")
int BPF_PROG(trace_tcp_recvmsg, struct sock *sk, struct msghdr *msg,
             size_t len, int flags, int *addr_len, int ret)
{
    if (ret <= 0) return 0;
    __u64 sock_id = (unsigned long)sk;
    struct conn_open_info *info = bpf_map_lookup_elem(&active_conns, &sock_id);
    if (!info) return 0;
    __sync_fetch_and_add(&info->rx_bytes, (__u64)ret);
    return 0;
}

// ── Probe 5: TCP connection established — both sides ──────────
// inet_sock_set_state fires on every TCP state transition.
//
//   SYN_SENT  → ESTABLISHED : client active open (SYN-ACK received)
//   SYN_RECV  → ESTABLISHED : server passive open (ACK received)
//
// Both transitions land here identically, making open-event handling
// symmetric. The role field distinguishes client from server.
//
// Client: pid/comm recovered from connect_scratch (set at fentry/tcp_connect).
// Server: pid=0, comm="" — this transition fires in softirq, so there is no
//         user-space context. Userspace can enrich from /proc/net/tcp by port.
//
// RTT: read tcp_sock.srtt_us (kernel smoothed RTT, 8× actual).
//   At SYN_SENT→ESTABLISHED the kernel has just processed the first SYN-ACK,
//   so srtt_us reflects that first measured RTT sample.
//   At SYN_RECV→ESTABLISHED the server has not sent data yet, so srtt_us may
//   still be 0; the initial RTT is more meaningful on the client side.

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != IPPROTO_TCP) return 0;
    if (ctx->family   != AF_INET)     return 0;
    if (ctx->newstate != TCP_ESTABLISHED) return 0;
    if (ctx->oldstate != TCP_SYN_SENT && ctx->oldstate != TCP_SYN_RECV) return 0;

    __u64 sock_id = (unsigned long)ctx->skaddr;
    __u64 ts      = bpf_ktime_get_ns();
    __u8  role    = (ctx->oldstate == TCP_SYN_RECV) ? 1 : 0;

    __u32 pid = 0;
    char  comm[16] = {};

    if (role == 0) {
        struct pre_conn *pc = bpf_map_lookup_elem(&connect_scratch, &sock_id);
        if (pc) {
            pid = pc->pid;
            __builtin_memcpy(comm, pc->comm, sizeof(comm));
            bpf_map_delete_elem(&connect_scratch, &sock_id);
        }
    }

    // srtt_us is stored as 8× the actual RTT (fixed-point arithmetic in the kernel).
    struct tcp_sock *tp = (struct tcp_sock *)ctx->skaddr;
    __u32 srtt_us = BPF_CORE_READ(tp, srtt_us);
    __u32 rtt_us  = srtt_us >> 3;

    // saddr/daddr in the tracepoint args are __u8[4] in network byte order.
    __u32 saddr = *(__u32 *)ctx->saddr;
    __u32 daddr = *(__u32 *)ctx->daddr;
    __u16 sport = ctx->sport; // already host byte order in the tracepoint
    __u16 dport = ctx->dport;

    struct conn_open_info info = {};
    info.open_ts_ns = ts;
    info.pid        = pid;
    info.saddr      = saddr;
    info.daddr      = daddr;
    info.sport      = sport;
    info.dport      = dport;
    info.role       = role;
    info.rtt_us     = rtt_us;
    __builtin_memcpy(info.comm, comm, sizeof(info.comm));
    bpf_map_update_elem(&active_conns, &sock_id, &info, BPF_ANY);

    struct conn_event *ce = bpf_ringbuf_reserve(&conn_events, sizeof(*ce), 0);
    if (!ce) return 0;
    __builtin_memset(ce, 0, sizeof(*ce));
    ce->type    = EVENT_TCP_OPEN;
    ce->role    = role;
    ce->pid     = pid;
    ce->sock_id = sock_id;
    ce->ts_ns   = ts;
    ce->saddr   = saddr;
    ce->daddr   = daddr;
    ce->sport   = sport;
    ce->dport   = dport;
    ce->rtt_us  = rtt_us;
    __builtin_memcpy(ce->comm, comm, sizeof(ce->comm));
    bpf_ringbuf_submit(ce, 0);
    return 0;
}

// ── Probe 6: TCP connection close ────────────────────────────
// fentry/tcp_close fires when the kernel tears down the socket.
// Covers both sides and both FIN initiators.

SEC("fentry/tcp_close")
int BPF_PROG(trace_tcp_close, struct sock *sk, long timeout)
{
    __u64 sock_id = (unsigned long)sk;
    struct conn_open_info *info = bpf_map_lookup_elem(&active_conns, &sock_id);
    if (!info) return 0; // connection predates collector start

    __u64 ts = bpf_ktime_get_ns();

    struct conn_event *ce = bpf_ringbuf_reserve(&conn_events, sizeof(*ce), 0);
    if (!ce) {
        bpf_map_delete_elem(&active_conns, &sock_id);
        return 0;
    }
    __builtin_memset(ce, 0, sizeof(*ce));
    ce->type        = EVENT_TCP_CLOSE;
    ce->role        = info->role;
    ce->pid         = info->pid;
    ce->sock_id     = sock_id;
    ce->ts_ns       = ts;
    ce->saddr       = info->saddr;
    ce->daddr       = info->daddr;
    ce->sport       = info->sport;
    ce->dport       = info->dport;
    ce->rtt_us      = info->rtt_us;
    ce->duration_ns = ts - info->open_ts_ns;
    ce->tx_bytes    = info->tx_bytes;
    ce->rx_bytes    = info->rx_bytes;
    __builtin_memcpy(ce->comm, info->comm, sizeof(ce->comm));
    bpf_ringbuf_submit(ce, 0);

    bpf_map_delete_elem(&active_conns, &sock_id);
    return 0;
}

char _license[] SEC("license") = "GPL";
