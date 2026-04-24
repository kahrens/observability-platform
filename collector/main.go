// collector/main.go
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/observability-platform/ebpf-collector/collector/processors"
	"golang.org/x/sys/unix"
)

// ExecEvent mirrors C struct exec_event (probes.bpf.c, 176 bytes).
type ExecEvent struct {
	Type        uint8
	Pad0        [3]byte
	Pid         uint32
	Tgid        uint32
	Uid         uint32
	Gid         uint32
	Pad1        uint32 // aligns TimestampNs to 8 bytes
	TimestampNs uint64
	Comm        [16]byte
	Filename    [128]byte
}

// ConnEvent mirrors C struct conn_event (probes.bpf.c, 88 bytes).
type ConnEvent struct {
	Type       uint8
	Role       uint8
	Pad0       [2]byte
	Pid        uint32
	SockID     uint64
	TsNs       uint64
	Saddr      uint32
	Daddr      uint32
	Sport      uint16
	Dport      uint16
	Pad1       [4]byte
	Comm       [16]byte
	RttUs      uint32
	Pad2       uint32
	DurationNs uint64
	TxBytes    uint64
	RxBytes    uint64
}

const (
	EventProcess  = 1
	EventTcpOpen  = 2
	EventTcpClose = 3
)

var (
	logProc   *processors.LogProcessor
	traceProc *processors.TraceProcessor
)

// bootTimeNs converts BPF monotonic timestamps (bpf_ktime_get_ns) to wall clock.
var bootTimeNs uint64

func init() {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		monotonicNs := uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
		bootTimeNs = uint64(time.Now().UnixNano()) - monotonicNs
	}
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-g -O2 -Wno-missing-declarations" -target amd64,arm64 probes ../probes/probes.bpf.c -- -I../probes

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	ctx := context.Background()

	var logShutdown func(context.Context) error
	var err error
	logProc, logShutdown, err = processors.NewLogProcessor(ctx)
	if err != nil {
		log.Fatalf("init log processor: %v", err)
	}
	defer logShutdown(ctx)

	var traceShutdown func(context.Context) error
	traceProc, traceShutdown, err = processors.NewTraceProcessor(ctx)
	if err != nil {
		log.Fatalf("init trace processor: %v", err)
	}
	defer traceShutdown(ctx)

	objs := probesObjects{}
	if err := loadProbesObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	// execve tracepoint
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("attach execve tracepoint: %v", err)
	}
	defer tpExecve.Close()

	// fentry/tcp_connect — stashes pid/comm in connect_scratch
	feTcpConnect, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpConnect})
	if err != nil {
		log.Fatalf("attach tcp_connect fentry: %v", err)
	}
	defer feTcpConnect.Close()

	// fexit/tcp_sendmsg — accumulates tx_bytes
	feTcpSend, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpSendmsg})
	if err != nil {
		log.Fatalf("attach tcp_sendmsg fexit: %v", err)
	}
	defer feTcpSend.Close()

	// fexit/tcp_recvmsg — accumulates rx_bytes
	feTcpRecv, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpRecvmsg})
	if err != nil {
		log.Fatalf("attach tcp_recvmsg fexit: %v", err)
	}
	defer feTcpRecv.Close()

	// inet_sock_set_state — handles ESTABLISHED for both client and server
	tpSockState, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Fatalf("attach inet_sock_set_state tracepoint: %v", err)
	}
	defer tpSockState.Close()

	// fentry/tcp_close — emits close event with duration and byte counts
	feTcpClose, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpClose})
	if err != nil {
		log.Fatalf("attach tcp_close fentry: %v", err)
	}
	defer feTcpClose.Close()

	execRd, err := ringbuf.NewReader(objs.ExecEvents)
	if err != nil {
		log.Fatalf("open exec ring buffer: %v", err)
	}
	connRd, err := ringbuf.NewReader(objs.ConnEvents)
	if err != nil {
		log.Fatalf("open conn ring buffer: %v", err)
	}

	log.Println("collector running — ctrl+c to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		execRd.Close()
		connRd.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		var e ExecEvent
		for {
			record, err := execRd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("exec ring buffer read error: %v", err)
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("exec decode error: %v", err)
				continue
			}
			handleProcess(&e)
		}
	}()

	go func() {
		defer wg.Done()
		var e ConnEvent
		for {
			record, err := connRd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("conn ring buffer read error: %v", err)
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("conn decode error: %v", err)
				continue
			}
			handleConn(&e)
		}
	}()

	wg.Wait()
}

func handleProcess(e *ExecEvent) {
	meta := enrich(e.Pid)
	wallClockNs := bootTimeNs + e.TimestampNs
	logProc.ProcessExec(context.Background(), processors.ExecEvent{
		Pid:         e.Pid,
		Uid:         e.Uid,
		Gid:         e.Gid,
		TimestampNs: wallClockNs,
		Comm:        nullStr(e.Comm[:]),
		Filename:    nullStr(e.Filename[:]),
		ContainerID: meta.ContainerID,
	})
}

func handleConn(e *ConnEvent) {
	wallClockNs := bootTimeNs + e.TsNs
	te := &processors.TcpConnEvent{
		Type:       e.Type,
		Role:       e.Role,
		Pid:        e.Pid,
		SockID:     e.SockID,
		TsNs:       wallClockNs,
		SrcIP:      ipStr(e.Saddr),
		DstIP:      ipStr(e.Daddr),
		SrcPort:    e.Sport,
		DstPort:    e.Dport,
		Comm:       nullStr(e.Comm[:]),
		RttUs:      e.RttUs,
		DurationNs: e.DurationNs,
		TxBytes:    e.TxBytes,
		RxBytes:    e.RxBytes,
	}
	traceProc.Handle(context.Background(), te)
}

// ProcMeta holds /proc-derived enrichment data.
type ProcMeta struct {
	ContainerID string
	CgroupPath  string
}

func enrich(pid uint32) ProcMeta {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ProcMeta{}
	}
	return ProcMeta{CgroupPath: string(data)}
}

func nullStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return string(b)
	}
	return string(b[:n])
}

func ipStr(n uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
