// collector/processors/traces.go
// OTel trace span emission for TCP session lifecycle events.
// Each tracked connection becomes a span: start = ESTABLISHED, end = tcp_close.
// Client spans (SpanKindClient) are emitted for active opens (connect).
// Server spans (SpanKindServer) are emitted for passive opens (accept).
package processors

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Event type constants — must mirror C defines in probes.bpf.c.
const (
	EventTcpOpen  uint8 = 2
	EventTcpClose uint8 = 3
)

// TcpConnEvent is the processed form of a BPF conn_event passed to TraceProcessor.
type TcpConnEvent struct {
	Type       uint8  // EventTcpOpen or EventTcpClose
	Role       uint8  // 0 = client (active open), 1 = server (passive open)
	Pid        uint32
	SockID     uint64 // kernel sock pointer — unique connection ID
	TsNs       uint64 // wall-clock nanoseconds (already converted from BPF monotonic)
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Comm       string // process name; empty for server-side opens
	RttUs      uint32 // smoothed RTT in microseconds at ESTABLISHED time
	DurationNs uint64 // session duration; only set on EventTcpClose
	TxBytes    uint64 // bytes sent; only set on EventTcpClose
	RxBytes    uint64 // bytes received; only set on EventTcpClose
}

// openConn holds the in-flight span for a tracked connection.
type openConn struct {
	span      trace.Span
	startTime time.Time
	event     TcpConnEvent
}

// TraceProcessor tracks open TCP connections and emits OTLP spans on close.
type TraceProcessor struct {
	mu       sync.Mutex
	conns    map[uint64]*openConn
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
	ticker   *time.Ticker
}

// NewTraceProcessor creates a TraceProcessor that exports via OTLP/gRPC.
// Endpoint: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT → OTEL_EXPORTER_OTLP_ENDPOINT → localhost:4317.
func NewTraceProcessor(ctx context.Context) (*TraceProcessor, func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "localhost:4317"
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("otlp trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("ebpf-collector"),
			semconv.ServiceVersion("0.1.0"),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)

	tp := &TraceProcessor{
		conns:    make(map[uint64]*openConn),
		tracer:   provider.Tracer("ebpf.tcp.trace", trace.WithInstrumentationVersion("0.1.0")),
		provider: provider,
		ticker:   time.NewTicker(30 * time.Second),
	}
	go tp.gcLoop()

	return tp, provider.Shutdown, nil
}

// Handle dispatches a TcpConnEvent to the open or close handler.
func (tp *TraceProcessor) Handle(ctx context.Context, e *TcpConnEvent) {
	switch e.Type {
	case EventTcpOpen:
		tp.handleOpen(ctx, e)
	case EventTcpClose:
		tp.handleClose(ctx, e)
	}
}

func (tp *TraceProcessor) handleOpen(ctx context.Context, e *TcpConnEvent) {
	kind := trace.SpanKindClient
	if e.Role == 1 {
		kind = trace.SpanKindServer
	}

	startTime := time.Unix(0, int64(e.TsNs))
	_, span := tp.tracer.Start(ctx, tcpSpanName(e),
		trace.WithSpanKind(kind),
		trace.WithTimestamp(startTime),
		trace.WithAttributes(openAttributes(e)...),
	)

	tp.mu.Lock()
	tp.conns[e.SockID] = &openConn{
		span:      span,
		startTime: startTime,
		event:     *e,
	}
	tp.mu.Unlock()
}

func (tp *TraceProcessor) handleClose(_ context.Context, e *TcpConnEvent) {
	tp.mu.Lock()
	oc, ok := tp.conns[e.SockID]
	if ok {
		delete(tp.conns, e.SockID)
	}
	tp.mu.Unlock()

	if !ok {
		return // predates collector start
	}

	endTime := time.Unix(0, int64(e.TsNs))
	oc.span.SetAttributes(closeAttributes(e)...)
	oc.span.End(trace.WithTimestamp(endTime))
}

func tcpSpanName(e *TcpConnEvent) string {
	if e.Role == 0 {
		if e.Comm != "" {
			return fmt.Sprintf("tcp.connect %s → %s:%d", e.Comm, e.DstIP, e.DstPort)
		}
		return fmt.Sprintf("tcp.connect %s:%d → %s:%d", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
	}
	return fmt.Sprintf("tcp.accept %s:%d ← %s:%d", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
}

// openAttributes are set when the span is created (at ESTABLISHED time).
func openAttributes(e *TcpConnEvent) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.NetworkTransportTCP,
		attribute.String("net.sock.host.addr", e.SrcIP),
		attribute.Int("net.sock.host.port", int(e.SrcPort)),
		attribute.String("net.sock.peer.addr", e.DstIP),
		attribute.Int("net.sock.peer.port", int(e.DstPort)),
		attribute.Int("tcp.role", int(e.Role)), // 0=client, 1=server
	}
	if e.RttUs > 0 {
		attrs = append(attrs, attribute.Float64("tcp.rtt.ms", float64(e.RttUs)/1000.0))
	}
	if e.Comm != "" {
		attrs = append(attrs, attribute.String("process.executable.name", e.Comm))
	}
	if e.Pid != 0 {
		attrs = append(attrs, attribute.Int("process.pid", int(e.Pid)))
	}
	if e.Role == 0 {
		attrs = append(attrs,
			semconv.ServerAddress(e.DstIP),
			semconv.ServerPort(int(e.DstPort)),
		)
	}
	return attrs
}

// closeAttributes are added to the span when the connection closes.
func closeAttributes(e *TcpConnEvent) []attribute.KeyValue {
	durationMs := float64(e.DurationNs) / 1_000_000.0
	return []attribute.KeyValue{
		attribute.Float64("tcp.duration.ms", durationMs),
		attribute.Int64("tcp.bytes.sent", int64(e.TxBytes)),
		attribute.Int64("tcp.bytes.received", int64(e.RxBytes)),
	}
}

// gcLoop evicts connections open more than 5 minutes without a close event.
func (tp *TraceProcessor) gcLoop() {
	for range tp.ticker.C {
		tp.mu.Lock()
		now := time.Now()
		for id, oc := range tp.conns {
			if age := now.Sub(oc.startTime); age > 5*time.Minute {
				log.Printf("tcp trace GC: evicting stale connection sock_id=%x %s:%d → %s:%d (age=%s)",
					id, oc.event.SrcIP, oc.event.SrcPort,
					oc.event.DstIP, oc.event.DstPort, age)
				oc.span.End(trace.WithTimestamp(now))
				delete(tp.conns, id)
			}
		}
		tp.mu.Unlock()
	}
}
