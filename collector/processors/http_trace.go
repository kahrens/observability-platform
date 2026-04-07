// collector/processors/http_trace.go
package processors

import (
    "bufio"
    "bytes"
    "context"
    "fmt"
    "log"
    "net/http"
    "strings"
    "sync"
    "time"

    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/codes"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
    "go.opentelemetry.io/otel/trace"
)

// ── Event types (must mirror C constants) ─────────────────────────

const (
    EventConnOpen  = 1
    EventConnClose = 2
    EventDataWrite = 3
    EventDataRead  = 4
)

type ConnEvent struct {
    Type      uint8
    Pid       uint32
    Fd        uint32
    TsNs      uint64
    Saddr     uint32
    Daddr     uint32
    Sport     uint16
    Dport     uint16
    Role      uint8
}

type DataEvent struct {
    Type   uint8
    Pid    uint32
    Fd     uint32
    TsNs   uint64
    Ret    int64
    Buf    [256]byte
    BufLen uint32
    Comm   [16]byte
}

// ── Correlation key ───────────────────────────────────────────────

type PidFd struct {
    Pid uint32
    Fd  uint32
}

// ── Per-connection state machine ──────────────────────────────────

type parseState int

const (
    stateIdle         parseState = iota
    stateReqHeaders
    stateReqBody
    stateAwaitResponse
    stateRespHeaders
    stateComplete
    stateAborted
)

type connState struct {
    pid       uint32
    fd        uint32
    saddr     string
    daddr     string
    sport     uint16
    dport     uint16
    role      uint8
    openTime  time.Time

    // parser state
    state     parseState
    reqBuf    []byte  // accumulates write() chunks
    respBuf   []byte  // accumulates read() chunks
    reqStartTs  uint64  // ns — write() timestamp (span start)
    respEndTs   uint64  // ns — read() timestamp  (span end)

    // parsed HTTP fields
    method      string
    path        string
    statusCode  int
    contentType string
}

// ── HTTPTraceProcessor ────────────────────────────────────────────

type HTTPTraceProcessor struct {
    mu     sync.Mutex
    conns  map[PidFd]*connState
    tracer trace.Tracer
    ticker *time.Ticker   // for timeout GC
}

func NewHTTPTraceProcessor(tp *sdktrace.TracerProvider) *HTTPTraceProcessor {
    p := &HTTPTraceProcessor{
        conns:  make(map[PidFd]*connState),
        tracer: tp.Tracer("ebpf.http.trace", trace.WithInstrumentationVersion("0.1.0")),
        ticker: time.NewTicker(15 * time.Second),
    }
    go p.gcLoop()
    return p
}

// HandleConn processes CONN_OPEN / CONN_CLOSE events.
func (p *HTTPTraceProcessor) HandleConn(ctx context.Context, e *ConnEvent) {
    p.mu.Lock()
    defer p.mu.Unlock()

    key := PidFd{Pid: e.Pid, Fd: e.Fd}

    switch e.Type {
    case EventConnOpen:
        p.conns[key] = &connState{
            pid:      e.Pid,
            fd:       e.Fd,
            saddr:    int32ToIP(e.Saddr),
            daddr:    int32ToIP(e.Daddr),
            sport:    e.Sport,
            dport:    e.Dport,
            role:     e.Role,
            openTime: nsToTime(e.TsNs),
            state:    stateIdle,
        }

    case EventConnClose:
        if cs, ok := p.conns[key]; ok {
            // Connection closed before response completed — emit error span
            if cs.state == stateAwaitResponse || cs.state == stateRespHeaders {
                cs.state = stateAborted
                p.emitSpan(ctx, cs, e.TsNs)
            }
            delete(p.conns, key)
        }
    }
}

// HandleData processes DATA_WRITE / DATA_READ events.
func (p *HTTPTraceProcessor) HandleData(ctx context.Context, e *DataEvent) {
    p.mu.Lock()
    defer p.mu.Unlock()

    key := PidFd{Pid: e.Pid, Fd: e.Fd}
    cs, ok := p.conns[key]
    if !ok {
        // Conn not tracked yet (accept4 may have raced) — create placeholder
        cs = &connState{pid: e.Pid, fd: e.Fd, state: stateIdle}
        p.conns[key] = cs
    }

    chunk := e.Buf[:e.BufLen]

    switch e.Type {
    case EventDataWrite:
        p.handleWrite(ctx, cs, chunk, e.TsNs)
    case EventDataRead:
        p.handleRead(ctx, cs, chunk, e.TsNs)
    }
}

func (p *HTTPTraceProcessor) handleWrite(ctx context.Context, cs *connState, chunk []byte, tsNs uint64) {
    switch cs.state {
    case stateIdle:
        // Check if this looks like an HTTP request or response
        if isHTTPRequest(chunk) || isHTTPResponse(chunk) {
            cs.reqBuf = append(cs.reqBuf[:0], chunk...)
            cs.reqStartTs = tsNs
            cs.state = stateReqHeaders
            p.tryParseRequest(cs)
        }
        // Non-HTTP traffic on this fd — ignore

    case stateReqHeaders:
        // Multi-chunk request headers
        cs.reqBuf = append(cs.reqBuf, chunk...)
        p.tryParseRequest(cs)
    }
}

func (p *HTTPTraceProcessor) handleRead(ctx context.Context, cs *connState, chunk []byte, tsNs uint64) {
    switch cs.state {
    case stateAwaitResponse, stateRespHeaders:
        cs.respBuf = append(cs.respBuf, chunk...)
        cs.respEndTs = tsNs
        cs.state = stateRespHeaders
        if p.tryParseResponse(cs) {
            cs.state = stateComplete
            p.emitSpan(ctx, cs, tsNs)
            // Reset for next request on same persistent connection (HTTP keep-alive)
            p.resetConn(cs)
        }
    }
}

// tryParseRequest looks for \r\n\r\n boundary and extracts method + path.
func (p *HTTPTraceProcessor) tryParseRequest(cs *connState) {
    if !bytes.Contains(cs.reqBuf, []byte("\r\n\r\n")) {
        return // headers not complete yet
    }

    req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(cs.reqBuf)))
    if err != nil {
        // Not valid HTTP — mark idle so we stop trying
        cs.state = stateIdle
        return
    }
    req.Body.Close()

    cs.method = req.Method
    cs.path   = req.URL.Path

    // Determine if there's a body to wait for
    if req.ContentLength > 0 {
        cs.state = stateReqBody
        // For our purposes (headers only), skip straight to awaiting response.
        // A production impl would track body bytes remaining.
    }
    cs.state = stateAwaitResponse
}

// tryParseResponse returns true when we have a complete response status.
func (p *HTTPTraceProcessor) tryParseResponse(cs *connState) bool {
    if !bytes.Contains(cs.respBuf, []byte("\r\n\r\n")) {
        return false // response headers not complete yet
    }

    resp, err := http.ReadResponse(
        bufio.NewReader(bytes.NewReader(cs.respBuf)),
        nil, // no corresponding request needed for status parsing
    )
    if err != nil {
        return false
    }
    resp.Body.Close()

    cs.statusCode  = resp.StatusCode
    cs.contentType = resp.Header.Get("Content-Type")
    return true
}

// emitSpan builds and records an OTLP trace span.
func (p *HTTPTraceProcessor) emitSpan(ctx context.Context, cs *connState, endTsNs uint64) {
    startTime := nsToTime(cs.reqStartTs)
    endTime   := nsToTime(endTsNs)

    // SpanKind: CLIENT if we initiated the connection, SERVER if we accepted it
    kind := trace.SpanKindClient
    if cs.role == 1 {
        kind = trace.SpanKindServer
    }

    spanName := fmt.Sprintf("%s %s", cs.method, cs.path)
    if cs.state == stateAborted {
        spanName = fmt.Sprintf("%s %s (aborted)", cs.method, cs.path)
    }

    // Use the OTel SDK's WithTimestamp option to back-date span to kernel time.
    // This is the critical piece — spans reflect actual kernel event times,
    // not the time the Go collector processed the event.
    _, span := p.tracer.Start(ctx, spanName,
        trace.WithSpanKind(kind),
        trace.WithTimestamp(startTime),
        trace.WithAttributes(
            // Semantic conventions for HTTP spans
            semconv.HTTPRequestMethodKey.String(cs.method),
            semconv.URLPath(cs.path),
            semconv.ServerAddress(cs.daddr),
            semconv.ServerPort(int(cs.dport)),
            semconv.NetworkPeerAddress(cs.saddr),
            attribute.Int("http.response.status_code", cs.statusCode),
            attribute.String("http.response.content_type", cs.contentType),
            // Platform-specific
            attribute.Int("process.pid", int(cs.pid)),
            attribute.Int("net.fd", int(cs.fd)),
        ),
    )

    if cs.state == stateAborted {
        span.SetStatus(codes.Error, "connection closed before response")
    } else if cs.statusCode >= 500 {
        span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", cs.statusCode))
    } else {
        span.SetStatus(codes.Ok, "")
    }

    span.End(trace.WithTimestamp(endTime))
}

func (p *HTTPTraceProcessor) resetConn(cs *connState) {
    cs.state       = stateIdle
    cs.reqBuf      = cs.reqBuf[:0]
    cs.respBuf     = cs.respBuf[:0]
    cs.reqStartTs  = 0
    cs.respEndTs   = 0
    cs.method      = ""
    cs.path        = ""
    cs.statusCode  = 0
    cs.contentType = ""
}

// gcLoop evicts connections that have been waiting too long for a response.
// Without this, a kept-alive connection that goes quiet leaks memory forever.
func (p *HTTPTraceProcessor) gcLoop() {
    for range p.ticker.C {
        p.mu.Lock()
        now := uint64(time.Now().UnixNano())
        for key, cs := range p.conns {
            if cs.state == stateAwaitResponse {
                age := now - cs.reqStartTs
                if age > uint64(30*time.Second) {
                    cs.state = stateAborted
                    log.Printf("GC: evicting timed-out request pid=%d fd=%d %s %s",
                        cs.pid, cs.fd, cs.method, cs.path)
                    delete(p.conns, key)
                }
            }
        }
        p.mu.Unlock()
    }
}

// ── Helpers ───────────────────────────────────────────────────────

// isHTTPRequest checks if bytes start with a known HTTP method.
func isHTTPRequest(b []byte) bool {
    methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ",
                         "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "}
    s := string(b[:min(16, len(b))])
    for _, m := range methods {
        if strings.HasPrefix(s, m) { return true }
    }
    return false
}

// isHTTPResponse checks if bytes start with an HTTP status line.
func isHTTPResponse(b []byte) bool {
    return bytes.HasPrefix(b, []byte("HTTP/1.")) ||
           bytes.HasPrefix(b, []byte("HTTP/2"))
}

func nsToTime(ns uint64) time.Time {
    return time.Unix(0, int64(ns))
}

func int32ToIP(n uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d", n&0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff)
}

func min(a, b int) int {
    if a < b { return a }
    return b
}
