┌─────────────────────────────────────────────────────┐
│                  TARGET LINUX HOST                   │
│                                                      │
│  Apps (any language, no instrumentation required)    │
│    │                                                 │
│  eBPF Probes (auto-attached)                         │
│    ├── syscall layer  (tracepoints)                  │
│    ├── network layer  (tc/XDP + sk_buff)             │
│    ├── file I/O       (kprobes/fentry)               │
│    ├── scheduler      (sched tracepoints)            │
│    └── TLS/HTTP       (uprobes on libssl/libhttp)    │
│    │                                                 │
│  BPF Maps + Ring Buffers                             │
│    │                                                 │
│  User-space Collector (Go/Rust)                      │
│    ├── parse events                                  │
│    ├── enrich with /proc metadata                    │
│    └── emit OTLP (metrics + traces + logs)           │
└─────────────────────┬───────────────────────────────┘
                      │ OTLP
              ┌───────▼────────┐
              │  OpenTelemetry │
              │  Collector     │
              └───────┬────────┘
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       Metrics      Traces      Logs
    (Prometheus)  (Tempo/Jaeger) (Loki)
          └───────────┼───────────┘
                      ▼
                  Grafana / UI
