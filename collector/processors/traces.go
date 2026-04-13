// collector/processors/traces.go
// OTel trace span emission for TCP connection lifecycle events.
// Each tracked connection becomes a span: start = ESTABLISHED, end = tcp_close().
// Client spans (SpanKindClient) are emitted for active opens (connect()).
// Server spans (SpanKindServer) are emitted for passive opens (accept()).
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
	EventTcpOpen  uint8 = 4
	EventTcpClose uint8 = 5
)

// TcpConnEvent is the processed form of a BPF conn_event passed to TraceProcessor.
// main.go converts the raw ring-buffer bytes into this struct before calling Handle.
type TcpConnEvent struct {
	Type    uint8  // EventTcpOpen or EventTcpClose
	Role    uint8  // 0 = client (active open), 1 = server (passive open)
	Pid     uint32
	SockID  uint64 // kernel sock pointer — unique connection ID for correlation
	TsNs    uint64 // wall-clock nanoseconds (already converted from BPF monotonic)
	SrcIP   string // local IPv4
	DstIP   string // remote IPv4
	SrcPort uint16
	DstPort uint16
	Comm    string // process name (may be empty for server-side passive opens)
}

// openConn holds the span and start time for an in-flight connection.
type openConn struct {
	span      trace.Span
	startTime time.Time
	event     TcpConnEvent
}

// TraceProcessor tracks open TCP connections and emits OTLP spans on close.
type TraceProcessor struct {
	mu       sync.Mutex
	conns    map[uint64]*openConn // keyed by SockID (sock pointer)
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
	ticker   *time.Ticker
}

// NewTraceProcessor creates a TraceProcessor that exports via OTLP/gRPC.
// The endpoint is read from OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, then
// OTEL_EXPORTER_OTLP_ENDPOINT, defaulting to localhost:4317.
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

	spanName := tcpSpanName(e)
	startTime := time.Unix(0, int64(e.TsNs))

	attrs := connAttributes(e)

	spanCtx, span := tp.tracer.Start(ctx, spanName,
		trace.WithSpanKind(kind),
		trace.WithTimestamp(startTime),
		trace.WithAttributes(attrs...),
	)
	_ = spanCtx // context kept alive through span; we end it in handleClose

	tp.mu.Lock()
	tp.conns[e.SockID] = &openConn{
		span:      span,
		startTime: startTime,
		event:     *e,
	}
	tp.mu.Unlock()
}

func (tp *TraceProcessor) handleClose(ctx context.Context, e *TcpConnEvent) {
	tp.mu.Lock()
	oc, ok := tp.conns[e.SockID]
	if ok {
		delete(tp.conns, e.SockID)
	}
	tp.mu.Unlock()

	if !ok {
		// Connection was not tracked (existed before collector started).
		return
	}

	endTime := time.Unix(0, int64(e.TsNs))
	oc.span.End(trace.WithTimestamp(endTime))
}

// tcpSpanName returns a concise span name for the connection.
// Format: "tcp.connect {comm} → {dst}:{port}" for clients,
//
//	"tcp.accept {dst}:{port} → {src}" for servers.
func tcpSpanName(e *TcpConnEvent) string {
	if e.Role == 0 {
		// Client: we know the comm and are connecting to dst
		if e.Comm != "" {
			return fmt.Sprintf("tcp.connect %s → %s:%d", e.Comm, e.DstIP, e.DstPort)
		}
		return fmt.Sprintf("tcp.connect %s:%d → %s:%d", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
	}
	// Server: we accepted a connection from dst (remote client)
	return fmt.Sprintf("tcp.accept %s:%d ← %s:%d", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
}

// connAttributes returns OTel semantic-convention attributes for a TCP connection.
// IPs and ports are fine in trace attributes (unlike metric labels where cardinality matters).
func connAttributes(e *TcpConnEvent) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.NetworkTransportTCP,
		attribute.String("net.sock.host.addr", e.SrcIP),
		attribute.Int("net.sock.host.port", int(e.SrcPort)),
		attribute.String("net.sock.peer.addr", e.DstIP),
		attribute.Int("net.sock.peer.port", int(e.DstPort)),
		attribute.Int("tcp.conn.role", int(e.Role)), // 0=client, 1=server
	}
	if e.Comm != "" {
		attrs = append(attrs, attribute.String("process.executable.name", e.Comm))
	}
	if e.Pid != 0 {
		attrs = append(attrs, attribute.Int("process.pid", int(e.Pid)))
	}
	// For client spans, set the canonical server.address / server.port so
	// backends can group spans by destination service.
	if e.Role == 0 {
		attrs = append(attrs,
			semconv.ServerAddress(e.DstIP),
			semconv.ServerPort(int(e.DstPort)),
		)
	}
	return attrs
}

// gcLoop evicts connections that have been open for more than 5 minutes without
// a close event (e.g., long-lived idle connections, or collector restart mid-connection).
// These spans are ended with a synthetic end time so they don't leak memory.
func (tp *TraceProcessor) gcLoop() {
	for range tp.ticker.C {
		tp.mu.Lock()
		now := time.Now()
		for id, oc := range tp.conns {
			age := now.Sub(oc.startTime)
			if age > 5*time.Minute {
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
