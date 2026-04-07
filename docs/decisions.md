# Architecture decision records

## ADR-001: cilium/ebpf over libbpf-go
Date: 2025-01
Status: accepted
Decision: Use cilium/ebpf as the Go eBPF library.
Reason: Better maintained, bpf2go code generation eliminates manual struct
mirroring, used by production projects (Cilium, Tetragon) we want to learn from.
Rejected: gobpf (unmaintained), raw syscalls (too much boilerplate).

## ADR-002: CO-RE mandatory
Date: 2025-01
Status: accepted
Decision: All kernel struct access must use BPF_CORE_READ(). No direct dereference.
Reason: Platform must deploy across RHEL 9 and RHEL 10 without recompiling on target.
CO-RE + BTF handles struct layout differences at load time.

## ADR-003: RINGBUF over PERF_EVENT_ARRAY
Date: 2025-01
Status: accepted
Decision: Use BPF_MAP_TYPE_RINGBUF for all event streaming.
Reason: Lower overhead, ordered, variable-length records, no per-CPU complexity.
PERF_EVENT_ARRAY only for CPU sampling (perf events proper).

## ADR-004: 256-byte buffer capture limit
Date: 2025-01
Status: accepted
Decision: Cap bpf_probe_read_user copies at 256 bytes per event.
Reason: Verifier requires compile-time-bounded copies. 256B captures HTTP/1.1
request line + key headers. Body content not needed for trace reconstruction.
Revisit: gRPC/HTTP2 binary framing needs a different approach (frame header decode).

## ADR-005: Fedora 42 for development, AlmaLinux 9 for RHEL parity testing
Date: 2025-01
Status: accepted
Decision: Develop on Fedora 42 (kernel 6.14+, full BTF), validate on AlmaLinux 9.
Reason: Fedora has cutting-edge eBPF support and matches upstream toolchain.
AlmaLinux 9 is a free 1:1 RHEL 9 rebuild for validating production parity.
