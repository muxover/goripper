//go:build darwin

package trace

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/muxover/goripper/internal/functions"
)

type darwinTracer struct{}

func New() Tracer { return &darwinTracer{} }

func (t *darwinTracer) Trace(binaryPath string, args []string, funcs []functions.Function, opts Options, out chan<- Event) error {
	script := buildDtraceScript(binaryPath, funcs)

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// -q suppresses dtrace's own headers; -s /dev/stdin reads script from stdin.
	cmd := exec.Command("dtrace", "-q", "-s", "/dev/stdin",
		"-c", shellJoin(append([]string{binaryPath}, args...)))

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("dtrace stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("dtrace stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dtrace (need SIP disabled or root): %w", err)
	}

	// close stdin so dtrace begins execution.
	if _, err := fmt.Fprint(stdin, script); err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("write dtrace script: %w", err)
	}
	stdin.Close()

	count := 0
	deadline := time.Now().Add(timeout)

	scanner := bufio.NewScanner(stdout)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		for scanner.Scan() {
			line := scanner.Text()
			if ev, ok := parseDtraceLine(line); ok {
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
	case <-scanDone:
	case <-time.After(timeout):
		cmd.Process.Kill()
	}

	cmd.Wait()
	return nil
}

// Each probe emits: "call <funcname> <ts_ns>"
func buildDtraceScript(binaryPath string, funcs []functions.Function) string {
	var b strings.Builder

	b.WriteString("pid$target::entry\n")
	b.WriteString("/execname != \"dtrace\"/\n")
	b.WriteString("{\n")
	b.WriteString("    printf(\"call %s %d\\n\", probefunc, walltimestamp);\n")
	b.WriteString("}\n")

	for _, fn := range funcs {
		if fn.PackageKind != functions.PackageUser {
			continue
		}
		// dtrace probe: pid$target:binary:mangled_name:entry
		// We use the address-based probe to avoid name mangling issues.
		fmt.Fprintf(&b, "pid$target::0x%x:entry\n", fn.Addr)
		fmt.Fprintf(&b, "{\n")
		fmt.Fprintf(&b, "    printf(\"call %s %%d\\n\", walltimestamp);\n", fn.Name)
		fmt.Fprintf(&b, "}\n")
	}

	return b.String()
}

// Format: "call <funcname> <ts_ns>"
func parseDtraceLine(line string) (Event, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "call ") {
		return Event{}, false
	}
	// "call <name> <ts_ns>"
	rest := line[len("call "):]
	lastSpace := strings.LastIndex(rest, " ")
	if lastSpace < 0 {
		return Event{}, false
	}
	name := rest[:lastSpace]
	tsStr := rest[lastSpace+1:]
	tsNs, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
	if err != nil {
		return Event{}, false
	}
	return Event{
		Type: EventCall,
		Func: name,
		TsNs: tsNs,
	}, true
}

func shellJoin(parts []string) string {
	return strings.Join(parts, " ")
}
