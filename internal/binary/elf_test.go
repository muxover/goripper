//go:build linux

package binary_test

import (
	"os"
	"testing"

	"github.com/muxover/goripper/internal/binary"
)

func TestELF_ParseOnLinux(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	bin, err := binary.Open(exe)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	if bin.Format() != "ELF" {
		t.Errorf("Format = %q, want ELF", bin.Format())
	}
	if bin.Arch() != "x86_64" {
		t.Errorf("Arch = %q, want x86_64", bin.Arch())
	}

	_, _, err = bin.FindGopclntab()
	if err != nil {
		t.Errorf("FindGopclntab: %v (gopclntab should be present in test binary)", err)
	}
}
