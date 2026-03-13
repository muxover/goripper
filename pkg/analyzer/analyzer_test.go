package analyzer_test

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/muxover/goripper/pkg/analyzer"
)

func TestRun_OnTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	a := analyzer.New(analyzer.Options{BinaryPath: exe})
	result, err := a.Run()
	if err != nil {
		t.Fatalf("analyzer.Run: %v", err)
	}
	if result == nil {
		t.Fatal("Run returned nil result")
	}

	if result.Summary.TotalFunctions == 0 {
		t.Error("expected TotalFunctions > 0")
	}
	if result.Summary.TotalStrings == 0 {
		t.Error("expected TotalStrings > 0")
	}
}

func TestRun_TruncatedBinary_NoPanic(t *testing.T) {
	f, err := os.CreateTemp("", "goripper-truncated-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	buf := make([]byte, 1024)
	rand.Read(buf)
	f.Write(buf)
	f.Close()

	a := analyzer.New(analyzer.Options{BinaryPath: f.Name()})
	// Must not panic. Either returns an error or a result with warnings.
	result, err := a.Run()
	if err == nil && result == nil {
		t.Error("expected non-nil error or result for random-data binary")
	}
}

func TestRun_ZeroByteFile_NoPanic(t *testing.T) {
	f, err := os.CreateTemp("", "goripper-empty-*.bin")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	a := analyzer.New(analyzer.Options{BinaryPath: f.Name()})
	_, err = a.Run()
	if err == nil {
		t.Error("expected non-nil error for empty file")
	}
}
