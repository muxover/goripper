package behaviors

import (
	"testing"

	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/functions"
)

func TestCGoBoundaries_FindsCallSites(t *testing.T) {
	funcs := []functions.Function{
		{Name: "main.doWork", PackageKind: functions.PackageUser},
		{Name: "_cgo_init", PackageKind: functions.PackageCGo},
	}
	graph := &callgraph.CallGraph{
		Calls: map[string][]string{
			"main.doWork": {"_cgo_init"},
		},
		CalledBy: map[string][]string{
			"_cgo_init": {"main.doWork"},
		},
	}

	callSites, cgoFuncs := CGoBoundaries(funcs, graph)

	if len(callSites) != 1 || callSites[0] != "main.doWork" {
		t.Errorf("callSites = %v, want [main.doWork]", callSites)
	}
	if len(cgoFuncs) != 1 || cgoFuncs[0] != "_cgo_init" {
		t.Errorf("cgoFuncs = %v, want [_cgo_init]", cgoFuncs)
	}
}

func TestCGoBoundaries_NoCGo_ReturnsNil(t *testing.T) {
	funcs := []functions.Function{
		{Name: "main.main", PackageKind: functions.PackageUser},
		{Name: "fmt.Println", PackageKind: functions.PackageStdlib},
	}
	graph := &callgraph.CallGraph{
		Calls:    map[string][]string{"main.main": {"fmt.Println"}},
		CalledBy: map[string][]string{"fmt.Println": {"main.main"}},
	}

	callSites, cgoFuncs := CGoBoundaries(funcs, graph)
	if len(callSites) != 0 || len(cgoFuncs) != 0 {
		t.Errorf("expected no CGo boundaries, got callSites=%v cgoFuncs=%v", callSites, cgoFuncs)
	}
}

func TestCGoBoundaries_NilGraph_ReturnsNil(t *testing.T) {
	funcs := []functions.Function{
		{Name: "_cgo_init", PackageKind: functions.PackageCGo},
	}
	callSites, cgoFuncs := CGoBoundaries(funcs, nil)
	if callSites != nil || cgoFuncs != nil {
		t.Errorf("nil graph should return nil, got callSites=%v cgoFuncs=%v", callSites, cgoFuncs)
	}
}

func TestIsCGOCall_Table(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"_cgo_runtime_cgocall", true},
		{"runtime/cgo.NewHandle", true},
		{"runtime.cgocall", true},
		{"runtime.asmcgocall", true},
		{"main.main", false},
		{"net.Dial", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isCGOCall(tt.name)
		if got != tt.want {
			t.Errorf("isCGOCall(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
