// probes.bpf.c
// Build: clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
//        -I/usr/include/bpf \
//        -c probes.bpf.c -o probes.bpf.o
// CO-RE: requires vmlinux.h  (generate with: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ── Event types ────────────────────────────────────────────────
#define EVENT_PROCESS  1
#define EVENT_CONNECT  2
#define EVENT_LATENCY  3
#define EVENT_TCP_OPEN  4   // TCP connection established (client or server)
#define EVENT_TCP_CLOSE 5   // TCP connection closed

// TCP state constants (from enum tcp_state in vmlinux.h)
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3

// Socket address family and protocol constants.
// vmlinux.h provides BTF types only — UAPI #defines are not included.
// These values are stable Linux UAPI ABI (linux/socket.h, linux/in.h).
#define AF_INET      2
#define IPPROTO_TCP  6

// ── Main event struct (process + basic network events) ─────────

struct event {
    __u8  type;
    __u8  _pad[3];        // explicit padding to align pid to 4-byte boundary
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 _pad1;          // explicit: align timestamp_ns to 8-byte boundary
    __u64 timestamp_ns;
    char  comm[16];

    // process events
    char  filename[128];

    // network events
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 _pad2;          // explicit: align latency_ns to 8-byte boundary

    // latency events
    __u64 latency_ns;
    __u32 bytes;
    __u32 _pad3;          // align struct to 8-byte boundary
};

_Static_assert(sizeof(struct event) == 208, "struct event size mismatch — update Go Event struct");

// ── TCP connection lifecycle structs ───────────────────────────

// conn_open_info — map value stored in active_conns while connection is open.
// Keyed by sock pointer (u64) for the lifetime of the connection.
struct conn_open_info {
    __u64 open_ts_ns;  // bpf_ktime_get_ns() at ESTABLISHED
    __u32 pid;
    __u32 saddr;       // local IPv4 (host byte order, from skc_rcv_saddr)
    __u32 daddr;       // remote IPv4 (host byte order, from skc_daddr)
    __u16 sport;       // local port (host byte order)
    __u16 dport;       // remote port (host byte order)
    __u8  role;        // 0=client (active open), 1=server (passive open)
    __u8  _pad[3];
    char  comm[16];
    // compiler adds 4 bytes trailing padding → sizeof = 48
};

// conn_event — ring buffer element for connection lifecycle events.
// Offsets:  type(1)+role(1)+pad(2)+pid(4)=8 | sock_id(8) | ts_ns(8)
//           saddr(4)+daddr(4)+sport(2)+dport(2)+pad2(4)=16 | comm(16)
// Total: 56 bytes.
struct conn_event {
    __u8  type;      // EVENT_TCP_OPEN or EVENT_TCP_CLOSE
    __u8  role;      // 0=client, 1=server
    __u8  _pad[2];
    __u32 pid;
    __u64 sock_id;   // kernel sock pointer — unique connection ID for correlation
    __u64 ts_ns;     // bpf_ktime_get_ns() (monotonic; collector converts to wall-clock)
    __u32 saddr;     // local IPv4 (host byte order)
    __u32 daddr;     // remote IPv4 (host byte order)
    __u16 sport;     // local port (host byte order)
    __u16 dport;     // remote port (host byte order)
    __u8  _pad2[4];
    char  comm[16];
};

_Static_assert(sizeof(struct conn_event) == 56, "struct conn_event size mismatch — update Go ConnEvent struct");

// ── Maps ───────────────────────────────────────────────────────

// exec_events — process execution events (execve).  Low volume; 1 MB is ample.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024); // 1 MB
} exec_events SEC(".maps");

// data_events — network connect and TCP latency events.  Higher volume; 8 MB.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024); // 8 MB
} data_events SEC(".maps");

// conn_events — TCP connection lifecycle (open/close).  1 MB.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024); // 1 MB
} conn_events SEC(".maps");

// Scratch map — stash per-pid state across entry/exit probes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // pid
    __type(value, __u64);  // timestamp at entry
} inflight SEC(".maps");

// active_conns — tracks open TCP connections by sock pointer.
// Populated on ESTABLISHED, deleted on tcp_close().
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);                   // sock pointer (unique per connection)
    __type(value, struct conn_open_info);
} active_conns SEC(".maps");

// ── Probe 1: process execution ─────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e) return 0;  // ring buffer full — drop

    e->type         = EVENT_PROCESS;
    e->pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid         = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid          = bpf_get_current_uid_gid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // args->filename is a userspace pointer — must use bpf_probe_read_user_str
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Probe 2: TCP active open (client connect) ──────────────────
// fentry fires in the context of the process calling connect(), so pid is correct.
// We emit EVENT_CONNECT to data_events (existing behaviour) AND record the
// connection open in active_conns + conn_events for span tracking.
SEC("fentry/tcp_connect")
int BPF_PROG(trace_tcp_connect, struct sock *sk)
{
    // ── Existing: emit EVENT_CONNECT to data_events ──────────────
    struct event *ev = bpf_ringbuf_reserve(&data_events, sizeof(*ev), 0);
    if (ev) {
        ev->type         = EVENT_CONNECT;
        ev->pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        ev->tgid         = bpf_get_current_pid_tgid() >> 32;
        ev->timestamp_ns = bpf_ktime_get_ns();
        bpf_get_current_comm(ev->comm, sizeof(ev->comm));
        ev->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        ev->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        bpf_ringbuf_submit(ev, 0);
    }

    // ── New: track in active_conns and emit EVENT_TCP_OPEN ───────
    __u64 sock_id = (unsigned long)sk;
    __u64 ts      = bpf_ktime_get_ns();
    __u32 pid     = bpf_get_current_pid_tgid() >> 32;

    struct conn_open_info info = {};
    info.open_ts_ns = ts;
    info.pid        = pid;
    info.saddr      = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    info.daddr      = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    info.sport      = BPF_CORE_READ(sk, __sk_common.skc_num);
    info.dport      = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    info.role       = 0; // client (active open)
    bpf_get_current_comm(info.comm, sizeof(info.comm));
    bpf_map_update_elem(&active_conns, &sock_id, &info, BPF_ANY);

    struct conn_event *ce = bpf_ringbuf_reserve(&conn_events, sizeof(*ce), 0);
    if (!ce) return 0;
    ce->type    = EVENT_TCP_OPEN;
    ce->role    = 0;
    ce->pid     = pid;
    ce->sock_id = sock_id;
    ce->ts_ns   = ts;
    ce->saddr   = info.saddr;
    ce->daddr   = info.daddr;
    ce->sport   = info.sport;
    ce->dport   = info.dport;
    __builtin_memcpy(ce->comm, info.comm, sizeof(ce->comm));
    bpf_ringbuf_submit(ce, 0);
    return 0;
}

// ── Probe 3: TCP passive open (server accept) ──────────────────
// inet_sock_set_state fires on every TCP state transition.
// We look for SYN_RECV → ESTABLISHED which marks a passive-open connection
// becoming ready on the server side.
//
// Note: bpf_get_current_pid_tgid() here runs in softirq/ksoftirqd context,
// so pid will be 0 or a kernel thread.  We record pid=0 and fill comm from
// the current task (best-effort — comm may be "ksoftirqd").
// The 4-tuple uniquely identifies the connection for service-map stitching.
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // Only IPv4 TCP
    if (ctx->protocol != IPPROTO_TCP) return 0;
    if (ctx->family   != AF_INET)     return 0;

    // Only care about the SYN_RECV → ESTABLISHED transition (passive open).
    // Client-side (SYN_SENT → ESTABLISHED) is captured by fentry/tcp_connect.
    if (ctx->oldstate != TCP_SYN_RECV || ctx->newstate != TCP_ESTABLISHED)
        return 0;

    __u64 sock_id = (unsigned long)ctx->skaddr;
    __u64 ts      = bpf_ktime_get_ns();

    // saddr/daddr in the tracepoint are __u8[4] in network byte order.
    // Reading as __u32 gives the same representation as BPF_CORE_READ on
    // skc_rcv_saddr (__be32), which is what the Go decoder expects.
    __u32 saddr = *(__u32 *)ctx->saddr;
    __u32 daddr = *(__u32 *)ctx->daddr;
    // sport/dport are already in host byte order (kernel calls ntohs before storing)
    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;

    struct conn_open_info info = {};
    info.open_ts_ns = ts;
    info.pid        = 0; // softirq context — no user pid
    info.saddr      = saddr;
    info.daddr      = daddr;
    info.sport      = sport;
    info.dport      = dport;
    info.role       = 1; // server (passive open)
    bpf_map_update_elem(&active_conns, &sock_id, &info, BPF_ANY);

    struct conn_event *ce = bpf_ringbuf_reserve(&conn_events, sizeof(*ce), 0);
    if (!ce) return 0;
    ce->type    = EVENT_TCP_OPEN;
    ce->role    = 1;
    ce->pid     = 0;
    ce->sock_id = sock_id;
    ce->ts_ns   = ts;
    ce->saddr   = saddr;
    ce->daddr   = daddr;
    ce->sport   = sport;
    ce->dport   = dport;
    // comm is not meaningful in softirq context; leave zeroed
    bpf_ringbuf_submit(ce, 0);
    return 0;
}

// ── Probe 4: TCP connection close ─────────────────────────────
// fentry/tcp_close fires when the kernel tears down the socket.
// This covers both client and server sides regardless of who initiates FIN.
SEC("fentry/tcp_close")
int BPF_PROG(trace_tcp_close, struct sock *sk, long timeout)
{
    __u64 sock_id = (unsigned long)sk;
    struct conn_open_info *info = bpf_map_lookup_elem(&active_conns, &sock_id);
    if (!info) return 0; // not a tracked connection (pre-existed collector start)

    struct conn_event *ce = bpf_ringbuf_reserve(&conn_events, sizeof(*ce), 0);
    if (!ce) {
        bpf_map_delete_elem(&active_conns, &sock_id);
        return 0;
    }
    ce->type    = EVENT_TCP_CLOSE;
    ce->role    = info->role;
    ce->pid     = info->pid;
    ce->sock_id = sock_id;
    ce->ts_ns   = bpf_ktime_get_ns();
    ce->saddr   = info->saddr;
    ce->daddr   = info->daddr;
    ce->sport   = info->sport;
    ce->dport   = info->dport;
    __builtin_memcpy(ce->comm, info->comm, sizeof(ce->comm));
    bpf_ringbuf_submit(ce, 0);

    bpf_map_delete_elem(&active_conns, &sock_id);
    return 0;
}

char _license[] SEC("license") = "GPL";

// ── Probe 5: TCP send latency ──────────────────────────────────

// Stash the timestamp when sendmsg is called
SEC("fentry/tcp_sendmsg")
int BPF_PROG(trace_tcp_sendmsg_enter, struct sock *sk, struct msghdr *msg, size_t size)
{
    __u64 ts = bpf_ktime_get_ns();
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_map_update_elem(&inflight, &tid, &ts, BPF_ANY);
    return 0;
}

// On return, compute delta and emit a latency event
SEC("fexit/tcp_recvmsg")
int BPF_PROG(trace_tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg,
             size_t len, int flags, int *addr_len, int ret)
{
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u64 *start_ts = bpf_map_lookup_elem(&inflight, &tid);
    if (!start_ts) return 0;

    __u64 delta_ns = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&inflight, &tid);

    if (ret <= 0) return 0; // skip errors and zero-byte reads

    struct event *e = bpf_ringbuf_reserve(&data_events, sizeof(*e), 0);
    if (!e) return 0;

    e->type         = EVENT_LATENCY;
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->latency_ns   = delta_ns;
    e->bytes        = (__u32)ret;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // Capture the 4-tuple for service attribution
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
