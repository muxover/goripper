package functions_test

import (
	"os"
	"testing"

	"github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/gopclntab"
)

func TestClassifyPackageKind_Table(t *testing.T) {
	cases := []struct {
		funcName string
		want     functions.PackageKind
	}{
		{"runtime.mallocgc", functions.PackageRuntime},
		{"runtime.newobject", functions.PackageRuntime},
		{"fmt.Println", functions.PackageStdlib},
		{"github.com/muxover/goripper/cmd/goripper.main", functions.PackageUser},
		{"_cgo_init", functions.PackageCGo},
		{"runtime/cgo.crosscall2", functions.PackageCGo},
		{"github.com/foo/bar.Do", functions.PackageUser},
		{"github.com/muxover/goripper/pkg/analyzer.New", functions.PackageUser},
	}

	for _, tc := range cases {
		pkg := functions.ExtractPackageName(tc.funcName)
		fn := functions.Function{Name: tc.funcName, Package: pkg}
		classified := functions.Classify([]functions.Function{fn})
		got := classified[0].PackageKind
		if got != tc.want {
			t.Errorf("Classify(%q): PackageKind = %v, want %v (pkg=%q)", tc.funcName, got, tc.want, pkg)
		}
	}
}

func TestClassifyPackageKind_EmptyIsRuntime(t *testing.T) {
	fn := functions.Function{Name: "", Package: ""}
	classified := functions.Classify([]functions.Function{fn})
	if classified[0].PackageKind != functions.PackageRuntime {
		t.Errorf("empty package: got %v, want PackageRuntime", classified[0].PackageKind)
	}
}

func TestExtract_OnTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	bin, err := binary.Open(exe)
	if err != nil {
		t.Fatalf("binary.Open: %v", err)
	}
	defer bin.Close()

	pclntabData, _, err := bin.FindGopclntab()
	if err != nil {
		t.Skipf("gopclntab not found in test binary: %v", err)
	}
	textStart, _, _ := bin.TextSectionRange()

	parsed, err := gopclntab.Parse(pclntabData, textStart)
	if err != nil {
		t.Fatalf("gopclntab.Parse: %v", err)
	}

	funcs := functions.Extract(parsed.Funcs)
	funcs = functions.Classify(funcs)

	if len(funcs) < 100 {
		t.Errorf("expected >= 100 functions, got %d", len(funcs))
	}

	hasUser := false
	for _, f := range funcs {
		if f.Addr == 0 {
			t.Errorf("function %q has zero Addr", f.Name)
		}
		if f.PackageKind == functions.PackageUser {
			hasUser = true
		}
	}
	if !hasUser {
		t.Error("expected at least one user-package function")
	}
}
