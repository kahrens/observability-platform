# ebpf-platform — Claude Code context

## What this project is
A code-free Linux observability platform that uses eBPF to capture metrics,
traces, and logs from any app running on Linux without instrumentation.
Targets RHEL 9.x and RHEL 10.x production hosts. Development environment
is Fedora 42 (kernel 6.14+), validated against AlmaLinux 9 for RHEL parity.

## Current state
Early development. Architecture designed, starter code scaffolded.
Project as-is builds and runs. Implemented functionality:
- Process exec events → OTel logs (execve tracepoint)
- TCP session tracking → OTel trace spans: 4-tuple, role (client/server), RTT estimate,
  session duration, bytes sent/received in each direction
Code will build and run on x86_64 and arm64. Start here before writing any new code.

## Architecture (read docs/architecture.md for full detail and
docs/platform_architecture_overview.svg)
Three tiers:
1. Kernel tier — eBPF probes (C, compiled with clang, CO-RE via vmlinux.h)
2. Collector daemon — Go, using cilium/ebpf for loading and ring buffer reading
3. Backends — OTLP → OTel Collector → Prometheus / Tempo / Loki / Grafana

## Key technology decisions (do not revisit without good reason)
- eBPF loader: cilium/ebpf (not libbpf-go, not gobpf)
- Code generation: bpf2go (generates Go bindings from .bpf.c at build time)
- Probe types: fentry/fexit preferred over kprobes; tracepoints for syscalls
- Portability: CO-RE mandatory — all kernel struct access via BPF_CORE_READ()
- Event transport: BPF_MAP_TYPE_RINGBUF (not perf event array)
- Metrics SDK: go.opentelemetry.io/otel/sdk/metric with OTLP/gRPC exporter
- Trace SDK: go.opentelemetry.io/otel/sdk/trace with explicit start/end timestamps
- Log SDK: go.opentelemetry.io/otel/sdk/log with OTLP/gRPC exporter
- Histogram buckets for TCP latency: [0.1,0.5,1,5,10,25,50,100,250,500,1000,2500,5000] ms

## Correlation key design
Connections are keyed by sock pointer (u64) in BPF maps — globally unique for the
connection lifetime, stable from tcp_connect/inet_csk_accept through tcp_close.
Client pid/comm is captured at fentry/tcp_connect and recovered at ESTABLISHED via
connect_scratch. Server-side pid is zero at open time (inet_sock_set_state fires in
softirq); enrich from /proc/net/tcp by local port if needed.

## Topology and Service Map
Run eBPF probes on multiple servers.  Ship connection information to trace
data store.  Use 5-tuples to join the source->destination and destination->source
into distributed traces with spans.  This can be used to build a service map and show
application topology.

## HTTP trace reconstruction approach
Capture write()/read() syscall exit tracepoints.
Buffer up to 256 bytes per event (verifier limit for bounded copies).
Parse HTTP/1.1 in user space using Go's net/http reader on accumulated chunks.
span.startTime = write() exit timestamp (bpf_ktime_get_ns, nanoseconds).
span.endTime   = read() exit timestamp when response headers complete.
State machine: IDLE → REQ_HEADERS → AWAIT_RESPONSE → RESP_HEADERS → EMIT.
TLS: use uprobe on libssl:SSL_write / SSL_read instead of syscall layer.

## BPF map conventions
- active_conns:      HASH  sock_ptr(u64) → conn_open_info   max 65536
- connect_scratch:   HASH  sock_ptr(u64) → pre_conn         max 4096
- exec_events:       RINGBUF 1MB
- conn_events:       RINGBUF 4MB
(Future payload capture will add buf_args and data_events maps.)

## Go package layout
collector/
  main.go              — ring buf event loop + signal handling
  loader.go            — BPF object load + probe attach (stub, logic in main.go)
  enricher.go          — /proc + cgroup + k8s metadata
  processors/
    traces.go          — TCP session lifecycle → OTLP spans
    metrics.go         — TCP latency → OTLP histogram (instruments defined; wiring pending)
    logs.go            — execve events → OTLP logs

## Build requirements
- clang 14+ (for BPF compilation)
- bpftool (for vmlinux.h generation)
- Go 1.22+
- linux-headers or kernel-devel matching running kernel
- Run `make vmlinux.h` first on any new machine before anything else

## Do not do these things
- Do not use kprobes where fentry/fexit is available (kernel >= 5.5 + BTF)
- Do not use BPF_MAP_TYPE_PERF_EVENT_ARRAY for new code (use RINGBUF)
- Do not put raw IPs, PIDs, or full container IDs as OTLP metric attributes
- Do not access kernel structs directly — always use BPF_CORE_READ()
- Do not skip bounds-checking BPF_CORE_READ results (verifier will reject)

## References
- Brendan Gregg "BPF Performance Tools" — canonical reference
- cilium/ebpf docs: https://pkg.go.dev/github.com/cilium/ebpf
- OTel semconv for HTTP: semconv/v1.24.0
- RHEL 9 eBPF support: kernel 5.14 base, eBPF facility rebased to 6.12 features
