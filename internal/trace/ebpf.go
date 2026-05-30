//go:build linux

package trace

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/muxover/goripper/internal/functions"
)

type linuxTracer struct{}

func New() Tracer { return &linuxTracer{} }

const (
	uprobeEvents = "/sys/kernel/debug/tracing/uprobe_events"
	tracePipe    = "/sys/kernel/debug/tracing/trace_pipe"
	traceEnable  = "/sys/kernel/debug/tracing/events/uprobes/enable"
)

func (t *linuxTracer) Trace(binaryPath string, args []string, funcs []functions.Function, opts Options, out chan<- Event) error {
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}

	// Format: p:<group>/<event> <binary>:<offset>
	var probeNames []string
	eventsFile, err := os.OpenFile(uprobeEvents, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open uprobe_events (need root or CAP_BPF): %w", err)
	}
	defer func() {
		eventsFile.Close()
		removeProbes(probeNames)
	}()

	for _, fn := range funcs {
		if fn.PackageKind != functions.PackageUser {
			continue
		}
		// sanitise the name for tracefs: replace non-alphanum with _
		evtName := sanitiseName(fn.Name)
		line := fmt.Sprintf("p:uprobes/%s %s:0x%x\n", evtName, absPath, fn.Addr)
		if _, err := fmt.Fprint(eventsFile, line); err != nil {
			// Non-fatal: kernel may reject individual probes; continue with others.
			continue
		}
		probeNames = append(probeNames, evtName)
	}
	eventsFile.Close()

	if err := os.WriteFile(traceEnable, []byte("1\n"), 0); err != nil {
		return fmt.Errorf("enable uprobes: %w", err)
	}

	cmd := exec.Command(absPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start target: %w", err)
	}

	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()

	pipe, err := os.Open(tracePipe)
	if err != nil {
		return fmt.Errorf("open trace_pipe: %w", err)
	}
	defer pipe.Close()

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	count := 0

	scanner := bufio.NewScanner(pipe)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		for scanner.Scan() {
			line := scanner.Text()
			if ev, ok := parseTraceLine(line, funcs); ok {
				out <- ev
				count++
				if opts.MaxEvents > 0 && count >= opts.MaxEvents {
					return
				}
			}
			if time.Now().After(deadline) {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-scanDone:
	case <-time.After(timeout):
		cmd.Process.Kill()
	}

	os.WriteFile(traceEnable, []byte("0\n"), 0)
	return nil
}

func parseTraceLine(line string, funcs []functions.Function) (Event, bool) {
	// trace_pipe format: <task>-<pid>  [cpu] .... <ts>: <probe>: (addr)
	// We only care about the probe name and timestamp.
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Event{}, false
	}

	// Find timestamp field: "1234567.890123:"
	tsIdx := strings.Index(line, ":")
	if tsIdx < 0 {
		return Event{}, false
	}
	// Fields are space-separated; find the one that looks like a float followed by ':'
	fields := strings.Fields(line)
	var tsNs int64
	var probeName string
	for i, f := range fields {
		if strings.HasSuffix(f, ":") {
			// Might be the timestamp or the probe name.
			val := strings.TrimSuffix(f, ":")
			if dot := strings.Index(val, "."); dot >= 0 {
				secs, _ := strconv.ParseInt(val[:dot], 10, 64)
				frac := val[dot+1:]
				// Pad/trim frac to 9 digits for nanoseconds.
				for len(frac) < 9 {
					frac += "0"
				}
				if len(frac) > 9 {
					frac = frac[:9]
				}
				ns, _ := strconv.ParseInt(frac, 10, 64)
				tsNs = secs*1e9 + ns
				// Next colon-terminated field is the probe group/name.
				if i+1 < len(fields) {
					probeName = strings.TrimSuffix(fields[i+1], ":")
				}
				break
			}
		}
	}

	if probeName == "" {
		return Event{}, false
	}
	// probeName is "uprobes/<sanitised_name>"; strip prefix.
	if strings.HasPrefix(probeName, "uprobes/") {
		probeName = probeName[len("uprobes/"):]
	}

	// Map sanitised name back to original function name.
	for _, fn := range funcs {
		if sanitiseName(fn.Name) == probeName {
			return Event{
				Type: EventCall,
				Func: fn.Name,
				Addr: fmt.Sprintf("0x%x", fn.Addr),
				TsNs: tsNs,
			}, true
		}
	}
	return Event{}, false
}

func sanitiseName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	// tracefs limits event names to 64 chars.
	if len(s) > 64 {
		s = s[len(s)-64:]
	}
	return s
}

func removeProbes(names []string) {
	f, err := os.OpenFile(uprobeEvents, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return
	}
	defer f.Close()
	for _, name := range names {
		fmt.Fprintf(f, "-:uprobes/%s\n", name)
	}
}
