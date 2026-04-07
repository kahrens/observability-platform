// probes.bpf.c
// Build: clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
//        -I/usr/include/bpf \
//        -c probes.bpf.c -o probes.bpf.o
// CO-RE: requires vmlinux.h  (generate with: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Event types ────────────────────────────────────────────────
#define EVENT_PROCESS  1
#define EVENT_CONNECT  2
#define EVENT_LATENCY  3

struct event {
    __u8  type;
    __u8  _pad[3];        // explicit padding to align pid to 4-byte boundary
    __u32 pid;
    __u32 tgid;
    __u64 timestamp_ns;
    char  comm[16];

    // process events
    char  filename[128];

    // network events
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;

    // latency events
    __u64 latency_ns;
    __u32 bytes;
    __u32 _pad2;          // align struct to 8-byte boundary
};

// ── Maps ───────────────────────────────────────────────────────

// Ring buffer — low-overhead, variable-length, ordered event stream
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4 MB
} events SEC(".maps");

// Scratch map — stash per-pid state across entry/exit probes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // pid
    __type(value, __u64);  // timestamp at entry
} inflight SEC(".maps");

// ── Probe 1: process execution ─────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;  // ring buffer full — drop

    e->type         = EVENT_PROCESS;
    e->pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid         = bpf_get_current_pid_tgid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // args->filename is a userspace pointer — must use bpf_probe_read_user_str
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Probe 2: TCP connect (fentry — faster than kprobe) ─────────
SEC("fentry/tcp_connect")
int BPF_PROG(trace_tcp_connect, struct sock *sk)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type         = EVENT_CONNECT;
    e->pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->tgid         = bpf_get_current_pid_tgid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // CO-RE field access — libbpf adjusts offsets at load time for this kernel
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
// In probes.bpf.c — add these two probes to your existing object

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

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
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
