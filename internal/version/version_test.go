package version_test

import (
	"strings"
	"testing"

	"github.com/muxover/goripper/internal/version"
)

func TestString_NonEmpty(t *testing.T) {
	s := version.String()
	if s == "" {
		t.Fatal("version.String() returned empty string")
	}
}

func TestString_ContainsVersion(t *testing.T) {
	s := version.String()
	if !strings.Contains(s, version.Version) {
		t.Fatalf("version.String() = %q, want it to contain %q", s, version.Version)
	}
}

func TestString_ContainsGo(t *testing.T) {
	s := version.String()
	if !strings.Contains(s, "go") {
		t.Fatalf("version.String() = %q, want it to contain Go runtime version", s)
	}
}
