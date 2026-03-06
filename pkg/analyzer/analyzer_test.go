package analyzer_test

import (
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
