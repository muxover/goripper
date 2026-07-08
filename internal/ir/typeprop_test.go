package ir_test

import (
	"testing"

	"github.com/muxover/goripper/internal/ir"
)

// TestPropTypes_CallThroughAssignAndPhi checks that a recovered aggregate type flows
// from a constructor call through an assignment and a phi to the fixpoint.
func TestPropTypes_CallThroughAssignAndPhi(t *testing.T) {
	f := &ir.IRFunc{
		Vars: map[string]string{},
		Blocks: []*ir.IRBlock{{ID: 0, Instrs: []ir.IRInstr{
			{Op: ir.OpCall, Target: "runtime.makeslice", Dst: "v0", Src: []string{"typ", "0x3", "0x3"}},
			{Op: ir.OpAssign, Dst: "v1", Src: []string{"v0"}},
			{Op: ir.OpPhi, Dst: "v2", Src: []string{"v1", "v9"}},
		}}},
	}

	ir.PropTypes(f, nil)

	for _, v := range []string{"v0", "v1", "v2"} {
		if f.Vars[v] != "GoSlice" {
			t.Errorf("%s type = %q, want GoSlice", v, f.Vars[v])
		}
	}
	if f.Vars["0x3"] != "" {
		t.Errorf("literal should not be typed, got %q", f.Vars["0x3"])
	}
}
