package gopclntab_test

import (
	"os"
	"strings"
	"testing"

	gobinary "github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/gopclntab"
)

func TestParse_OnTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	bin, err := gobinary.Open(exe)
	if err != nil {
		t.Fatalf("gobinary.Open(%q): %v", exe, err)
	}
	defer bin.Close()

	data, textVA, err := bin.FindGopclntab()
	if err != nil {
		t.Fatalf("FindGopclntab: %v", err)
	}

	parsed, err := gopclntab.Parse(data, textVA)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if parsed.GoVersion == "" {
		t.Error("GoVersion is empty")
	}

	if len(parsed.Funcs) < 100 {
		t.Errorf("expected >100 functions, got %d", len(parsed.Funcs))
	}

	// The test binary must contain at least one testing.* function
	found := false
	for _, f := range parsed.Funcs {
		if strings.HasPrefix(f.Name, "testing.") {
			found = true
			break
		}
	}
	if !found {
		t.Error("no testing.* functions found in parsed pclntab")
	}
}
