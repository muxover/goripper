package trace

import (
	"time"

	"github.com/muxover/goripper/internal/functions"
)

type EventType string

const (
	EventCall    EventType = "call"
	EventReturn  EventType = "return"
	EventSyscall EventType = "syscall"
	EventFile    EventType = "file"
	EventNet     EventType = "net"
)

type Event struct {
	Type       EventType `json:"type"`
	Func       string    `json:"func,omitempty"`
	Addr       string    `json:"addr,omitempty"`
	TsNs       int64     `json:"ts_ns"`
	DurationNs int64     `json:"duration_ns,omitempty"`
	Name       string    `json:"name,omitempty"`
	Args       []string  `json:"args,omitempty"`
	Op         string    `json:"op,omitempty"`
	Path       string    `json:"path,omitempty"`
	NetAddr    string    `json:"net_addr,omitempty"`
	Proto      string    `json:"proto,omitempty"`
}

type Options struct {
	Timeout   time.Duration
	MaxEvents int
}

type Tracer interface {
	Trace(binaryPath string, args []string, funcs []functions.Function, opts Options, out chan<- Event) error
}
