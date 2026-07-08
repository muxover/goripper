package ir_test

import (
	"strings"
	"testing"

	"github.com/muxover/goripper/internal/ir"
)

// TestRenameVars_PhiAtMerge builds a diamond where _rax is defined on both branches
// and read after the merge. SSA must place a 2-operand phi at the merge and rewrite
// the read to reference it.
func TestRenameVars_PhiAtMerge(t *testing.T) {
	f := &ir.IRFunc{
		Vars: map[string]string{},
		Blocks: []*ir.IRBlock{
			{ID: 0, Succs: []int{1, 2}, Instrs: []ir.IRInstr{
				{Op: ir.OpAssign, Dst: "_rax", Src: []string{"0x1"}},
				{Op: ir.OpIf, Meta: "_rcx != 0x0", Label: "L1", Label2: "L2"},
			}},
			{ID: 1, Succs: []int{3}, Preds: []int{0}, Instrs: []ir.IRInstr{
				{Op: ir.OpAssign, Dst: "_rax", Src: []string{"0x2"}},
			}},
			{ID: 2, Succs: []int{3}, Preds: []int{0}, Instrs: []ir.IRInstr{
				{Op: ir.OpAssign, Dst: "_rax", Src: []string{"0x3"}},
			}},
			{ID: 3, Preds: []int{1, 2}, Instrs: []ir.IRInstr{
				{Op: ir.OpArith, Dst: "_rbx", Src: []string{"_rax", "0x0"}, Meta: "add"},
			}},
		},
	}

	ir.RenameVars(f)

	merge := f.Blocks[3]
	if len(merge.Instrs) < 2 || merge.Instrs[0].Op != ir.OpPhi {
		t.Fatalf("expected a phi at the top of the merge block, got %+v", merge.Instrs)
	}
	phi := merge.Instrs[0]
	if !strings.HasPrefix(phi.Dst, "_rax_v") {
		t.Errorf("phi dst = %q, want a version of _rax", phi.Dst)
	}
	if len(phi.Src) != 2 {
		t.Errorf("phi should join both branches, got %d operands: %v", len(phi.Src), phi.Src)
	}
	if use := merge.Instrs[1]; use.Src[0] != phi.Dst {
		t.Errorf("read after merge = %q, want the phi result %q", use.Src[0], phi.Dst)
	}
}

// TestRenameVars_ParamFirstVersion checks that a parameter register keeps its _v0
// version so downstream param recovery can map it.
func TestRenameVars_ParamFirstVersion(t *testing.T) {
	f := &ir.IRFunc{
		Params: []string{"_rax"},
		Vars:   map[string]string{},
		Blocks: []*ir.IRBlock{
			{ID: 0, Instrs: []ir.IRInstr{
				{Op: ir.OpArith, Dst: "_rbx", Src: []string{"_rax", "0x8"}, Meta: "add"},
			}},
		},
	}

	ir.RenameVars(f)

	if _, ok := f.Vars["_rax_v0"]; !ok {
		t.Fatalf("param _rax should have version _v0 registered; vars: %v", f.Vars)
	}
	if got := f.Blocks[0].Instrs[0].Src[0]; got != "_rax_v0" {
		t.Errorf("param read = %q, want _rax_v0", got)
	}
}
