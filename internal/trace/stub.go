//go:build !linux && !darwin && !windows

package trace

import (
	"errors"

	"github.com/muxover/goripper/internal/functions"
)

type stubTracer struct{}

func New() Tracer { return &stubTracer{} }

func (t *stubTracer) Trace(binaryPath string, args []string, funcs []functions.Function, opts Options, out chan<- Event) error {
	return errors.New("tracing is not supported on this platform")
}
