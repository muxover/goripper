package ir_test

import (
	"testing"

	"github.com/muxover/goripper/internal/ir"
)

func TestReconstructFrame(t *testing.T) {
	f := &ir.IRFunc{
		Vars: map[string]string{},
		Blocks: []*ir.IRBlock{{ID: 0, Instrs: []ir.IRInstr{
			// load from a stack slot -> plain read
			{Op: ir.OpLoad, Dst: "_rax", Src: []string{"(*(_rsp + 0x28))"}},
			// store to a frame slot -> plain write
			{Op: ir.OpStore, Dst: "(*(_rbp - 0x10))", Src: []string{"_rbx"}},
			// indexed access is an array, not a slot -> untouched
			{Op: ir.OpLoad, Dst: "_rcx", Src: []string{"(*(_rsp + _rax*8 + 0x10))"}},
			// inline slot read inside a condition
			{Op: ir.OpIf, Meta: "(*(_rsp + 0x8)) != 0x0", Label: "L1", Label2: "L2"},
		}}},
	}

	ir.ReconstructFrame(f)
	got := f.Blocks[0].Instrs

	if got[0].Op != ir.OpAssign || got[0].Src[0] != "s_28" {
		t.Errorf("stack load = %+v, want assign from s_28", got[0])
	}
	if got[1].Op != ir.OpAssign || got[1].Dst != "b_n10" {
		t.Errorf("frame store = %+v, want assign to b_n10", got[1])
	}
	if got[2].Op != ir.OpLoad || got[2].Src[0] != "(*(_rsp + _rax*8 + 0x10))" {
		t.Errorf("indexed access should be untouched, got %+v", got[2])
	}
	if got[3].Meta != "s_8 != 0x0" {
		t.Errorf("inline slot read = %q, want s_8 != 0x0", got[3].Meta)
	}
}
