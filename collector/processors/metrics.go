package processors

import (
    "context"
    "fmt"
    "log"
    "time"

    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
    "go.opentelemetry.io/otel/sdk/metric"
    "go.opentelemetry.io/otel/sdk/resource"
    semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
    otelmetric "go.opentelemetry.io/otel/metric"
)

// LatencyEvent is what the ring buffer decoder hands us.
// Matches the C struct EVENT_LATENCY layout.
type LatencyEvent struct {
    Pid         uint32
    TimestampNs uint64
    LatencyNs   uint64
    Bytes       uint32
    Comm        [16]byte
    Saddr       uint32
    Daddr       uint32
    Sport       uint16
    Dport       uint16
    // Set by Enricher before reaching here
    ContainerID string
    PodName     string
    Namespace   string
}

// MetricProcessor holds the OTel instruments and records events.
type MetricProcessor struct {
    // Histogram: TCP request/response latency in milliseconds
    tcpLatency otelmetric.Float64Histogram

    // Counter: total bytes transferred
    tcpBytes otelmetric.Int64Counter

    // Counter: total TCP operations (gives you request rate)
    tcpOps otelmetric.Int64Counter

    // Counter: errors (ret <= 0 from recvmsg, tracked separately)
    tcpErrors otelmetric.Int64Counter
}

// NewMetricProcessor initialises the OTLP exporter, MeterProvider,
// and all instruments. Call once at startup.
func NewMetricProcessor(ctx context.Context, otlpEndpoint string) (*MetricProcessor, func(), error) {
    // ── Exporter ────────────────────────────────────────────────
    // Pushes to an OTel Collector (or directly to a backend) via gRPC.
    // otlpEndpoint is e.g. "localhost:4317"
    exporter, err := otlpmetricgrpc.New(ctx,
        otlpmetricgrpc.WithEndpoint(otlpEndpoint),
        otlpmetricgrpc.WithInsecure(), // use WithTLSClientConfig in prod
    )
    if err != nil {
        return nil, nil, fmt.Errorf("create OTLP exporter: %w", err)
    }

    // ── Resource ─────────────────────────────────────────────────
    // Identifies THIS collector instance in the backend.
    res, err := resource.New(ctx,
        resource.WithAttributes(
            semconv.ServiceName("ebpf-platform-collector"),
            semconv.ServiceVersion("0.1.0"),
            attribute.String("platform.type", "ebpf"),
        ),
        resource.WithHost(),      // adds host.name
        resource.WithProcess(),   // adds process.pid
    )
    if err != nil {
        return nil, nil, fmt.Errorf("create resource: %w", err)
    }

    // ── MeterProvider ────────────────────────────────────────────
    // PeriodicReader flushes accumulated metrics every 10 seconds.
    // This is a push model — adjust interval to match your backend's
    // scrape expectations, or switch to a pull-based reader for Prometheus.
    provider := metric.NewMeterProvider(
        metric.WithReader(
            metric.NewPeriodicReader(exporter,
                metric.WithInterval(10*time.Second),
            ),
        ),
        metric.WithResource(res),

        // Explicit histogram bucket boundaries tuned for microsecond
        // to second TCP latency. Default OTel buckets are too coarse.
        metric.WithView(
            metric.NewView(
                metric.Instrument{Name: "tcp.latency"},
                metric.Stream{
                    Aggregation: metric.AggregationExplicitBucketHistogram{
                        Boundaries: []float64{
                            0.1, 0.5, 1, 5, 10, 25, 50,
                            100, 250, 500, 1000, 2500, 5000,
                        }, // milliseconds
                    },
                },
            ),
        ),
    )

    // Register globally so other packages can grab meters if needed
    otel.SetMeterProvider(provider)

    // Cleanup: flush and shutdown on collector exit
    shutdown := func() {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := provider.Shutdown(ctx); err != nil {
            log.Printf("metrics provider shutdown: %v", err)
        }
    }

    // ── Instruments ──────────────────────────────────────────────
    meter := provider.Meter("ebpf.platform",
        otelmetric.WithInstrumentationVersion("0.1.0"),
    )

    tcpLatency, err := meter.Float64Histogram(
        "tcp.latency",
        otelmetric.WithDescription("TCP send→recv round-trip latency"),
        otelmetric.WithUnit("ms"),
    )
    if err != nil {
        return nil, shutdown, fmt.Errorf("create latency histogram: %w", err)
    }

    tcpBytes, err := meter.Int64Counter(
        "tcp.bytes",
        otelmetric.WithDescription("TCP bytes received"),
        otelmetric.WithUnit("By"),
    )
    if err != nil {
        return nil, shutdown, fmt.Errorf("create bytes counter: %w", err)
    }

    tcpOps, err := meter.Int64Counter(
        "tcp.operations",
        otelmetric.WithDescription("TCP recv operations — proxy for request rate"),
        otelmetric.WithUnit("{operation}"),
    )
    if err != nil {
        return nil, shutdown, fmt.Errorf("create ops counter: %w", err)
    }

    tcpErrors, err := meter.Int64Counter(
        "tcp.errors",
        otelmetric.WithDescription("TCP recv errors"),
        otelmetric.WithUnit("{error}"),
    )
    if err != nil {
        return nil, shutdown, fmt.Errorf("create errors counter: %w", err)
    }

    return &MetricProcessor{
        tcpLatency: tcpLatency,
        tcpBytes:   tcpBytes,
        tcpOps:     tcpOps,
        tcpErrors:  tcpErrors,
    }, shutdown, nil
}

// Record processes one LatencyEvent from the ring buffer.
// Called from the EventRouter for every EVENT_LATENCY record.
func (p *MetricProcessor) Record(ctx context.Context, e *LatencyEvent) {
    latencyMs := float64(e.LatencyNs) / 1e6 // nanoseconds → milliseconds

    // ── Attributes (dimensions) ──────────────────────────────────
    // These become the label set in Prometheus / dimensions in Tempo.
    // Keep cardinality bounded — never put raw IPs or PIDs here.
    attrs := []attribute.KeyValue{
        attribute.String("process.comm",          nullStr(e.Comm[:])),
        attribute.String("net.peer.port",         fmt.Sprintf("%d", e.Dport)),
        attribute.String("k8s.pod.name",          e.PodName),
        attribute.String("k8s.namespace.name",    e.Namespace),
        attribute.String("container.id",          truncate(e.ContainerID, 12)),
    }
    attrSet := attribute.NewSet(attrs...)
    attrOpt := otelmetric.WithAttributeSet(attrSet)

    // ── Record instruments ───────────────────────────────────────
    p.tcpLatency.Record(ctx, latencyMs, attrOpt)
    p.tcpBytes.Add(ctx, int64(e.Bytes), attrOpt)
    p.tcpOps.Add(ctx, 1, attrOpt)
}

// RecordError is called when recvmsg returns an error code.
func (p *MetricProcessor) RecordError(ctx context.Context, e *LatencyEvent, errCode int) {
    attrs := otelmetric.WithAttributes(
        attribute.String("process.comm",       nullStr(e.Comm[:])),
        attribute.String("error.code",         fmt.Sprintf("%d", errCode)),
        attribute.String("k8s.namespace.name", e.Namespace),
    )
    p.tcpErrors.Add(ctx, 1, attrs)
}

func nullStr(b []byte) string {
    for i, v := range b {
        if v == 0 { return string(b[:i]) }
    }
    return string(b)
}

func truncate(s string, n int) string {
    if len(s) <= n { return s }
    return s[:n]
}
