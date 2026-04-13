// collector/processors/logs.go
// OTLP log record emission for process execution events.
package processors

import (
	"context"
	"fmt"
	"os"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// ExecEvent carries the fields from an execve BPF event needed to emit a log record.
type ExecEvent struct {
	Pid         uint32
	Uid         uint32
	Gid         uint32
	TimestampNs uint64
	Comm        string
	Filename    string
	ContainerID string
}

// LogProcessor emits structured log records for process execution events.
type LogProcessor struct {
	logger   log.Logger
	provider *sdklog.LoggerProvider
}

// NewLogProcessor creates a LogProcessor that exports via OTLP/gRPC.
// The endpoint is read from the OTEL_EXPORTER_OTLP_ENDPOINT env var,
// defaulting to localhost:4317 (OTel Collector default gRPC port).
func NewLogProcessor(ctx context.Context) (*LogProcessor, func(context.Context) error, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("ebpf-collector"),
			semconv.ServiceVersion("0.1.0"),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create resource: %w", err)
	}

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if endpoint == "" {
		endpoint = "localhost:4317"
	}
	exp, err := otlploggrpc.New(ctx, otlploggrpc.WithEndpoint(endpoint), otlploggrpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("otlp log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	)

	return &LogProcessor{
			logger:   provider.Logger("ebpf-collector"),
			provider: provider,
		},
		provider.Shutdown,
		nil
}

// safeStr replaces invalid UTF-8 sequences with the replacement character
// so OTLP gRPC marshalling never fails on kernel-sourced byte strings.
func safeStr(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return string([]rune(s))
}

// ProcessExec emits a log record for a process execution event.
func (lp *LogProcessor) ProcessExec(ctx context.Context, e ExecEvent) {
	e.Comm = safeStr(e.Comm)
	e.Filename = safeStr(e.Filename)
	var r log.Record
	r.SetTimestamp(time.Unix(0, int64(e.TimestampNs)))
	r.SetObservedTimestamp(time.Now())
	r.SetSeverity(log.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(log.StringValue(fmt.Sprintf("exec pid=%d uid=%d gid=%d comm=%s file=%s", e.Pid, e.Uid, e.Gid, e.Comm, e.Filename)))

	attrs := []log.KeyValue{
		log.Int64("process.pid", int64(e.Pid)),
		log.Int64("process.user.id", int64(e.Uid)),
		log.Int64("process.group.id", int64(e.Gid)),
		log.String("process.executable.name", e.Comm),
		log.String("process.executable.path", e.Filename),
	}
	if e.ContainerID != "" {
		cid := e.ContainerID
		if len(cid) > 12 {
			cid = cid[:12]
		}
		attrs = append(attrs, log.String("container.id", cid))
	}
	r.AddAttributes(attrs...)
	lp.logger.Emit(ctx, r)
}
