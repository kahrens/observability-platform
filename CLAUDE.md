# ebpf-platform — Claude Code context

## What this project is
A code-free Linux observability platform that uses eBPF to capture metrics,
traces, and logs from any app running on Linux without instrumentation.
Targets RHEL 9.x and RHEL 10.x production hosts. Development environment
is Fedora 42 (kernel 6.14+), validated against AlmaLinux 9 for RHEL parity.

## Current state
Early development. Architecture designed, starter code scaffolded.
Project as-is builds and runs. The current functionality is a single use case that records new process exec data and emits OTel logs with it.  Code will build and run on x86_64 and arm64. Start here before writing any new code.

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
- Histogram buckets for TCP latency: [0.1,0.5,1,5,10,25,50,100,250,500,1000,2500,5000] ms

## Correlation key design
Connections are keyed by {pid u32, fd u32} in BPF maps.
fd reuse is handled by using open_ts_ns as a generation counter in Go-side maps.
See docs/ebpf-patterns.md for the full pattern.

## HTTP trace reconstruction approach
Capture write()/read() syscall exit tracepoints.
Buffer up to 256 bytes per event (verifier limit for bounded copies).
Parse HTTP/1.1 in user space using Go's net/http reader on accumulated chunks.
span.startTime = write() exit timestamp (bpf_ktime_get_ns, nanoseconds).
span.endTime   = read() exit timestamp when response headers complete.
State machine: IDLE → REQ_HEADERS → AWAIT_RESPONSE → RESP_HEADERS → EMIT.
TLS: use uprobe on libssl:SSL_write / SSL_read instead of syscall layer.

## BPF map conventions
- active_conns:   HASH  {pid,fd} → conn_info       max 65536
- inflight_reqs:  HASH  tid → scratch              max 65536
- buf_args:       HASH  tid → userspace buf ptr    max 65536
- data_events:    RINGBUF 8MB
- conn_events:    RINGBUF 1MB

## Go package layout
collector/
  main.go              — ring buf event loop + signal handling
  loader.go            — BPF object load + probe attach
  enricher.go          — /proc + cgroup + k8s metadata
  processors/
    metrics.go         — TCP latency → OTLP histogram
    http_trace.go      — HTTP reconstruction → OTLP spans
    logs.go            — execve/open events → OTLP logs

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
