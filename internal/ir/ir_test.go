package ir_test

import (
	"strings"
	"testing"

	"github.com/muxover/goripper/internal/cfg"
	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/ir"
)

func makeFn(name, pkg string, addr, size uint64) functions.Function {
	return functions.Function{
		Name:        name,
		Package:     pkg,
		Addr:        addr,
		Size:        size,
		PackageKind: functions.PackageUser,
	}
}

func makeBlock(id int, startPC uint64, instrs []disasm.Instr, succs, preds []int) *cfg.BasicBlock {
	return &cfg.BasicBlock{
		ID:      id,
		StartPC: startPC,
		Instrs:  instrs,
		Succs:   succs,
		Preds:   preds,
	}
}

func TestLiftArch_EmptyBlocks(t *testing.T) {
	fn := makeFn("main.Empty", "main", 0x1000, 0)
	c := &cfg.CFG{FuncName: "main.Empty", FuncAddr: 0x1000}
	f := ir.LiftArch(fn, c, nil, 0, nil, "x86_64")
	if len(f.Blocks) != 0 {
		t.Errorf("expected 0 blocks for empty CFG, got %d", len(f.Blocks))
	}
	if f.Name != "main.Empty" {
		t.Errorf("name mismatch: got %q", f.Name)
	}
}

func TestLiftArch_NilCFG(t *testing.T) {
	fn := makeFn("main.Nil", "main", 0x1000, 0)
	f := ir.LiftArch(fn, nil, nil, 0, nil, "x86_64")
	if f == nil {
		t.Fatal("expected non-nil IRFunc for nil CFG")
	}
	if len(f.Blocks) != 0 {
		t.Errorf("expected 0 blocks, got %d", len(f.Blocks))
	}
}

// TestLiftX86_RetInstruction encodes a single RET (0xC3) and verifies it lifts
// to an OpReturn instruction.
func TestLiftX86_RetInstruction(t *testing.T) {
	// Encode: RET (0xC3)
	textData := []byte{0xC3}
	textVA := uint64(0x1000)

	d := disasm.New("x86_64")
	instr, err := d.Decode(textData, textVA)
	if err != nil {
		t.Fatalf("decode RET: %v", err)
	}

	fn := makeFn("main.Ret", "main", textVA, uint64(len(textData)))
	blk := makeBlock(0, textVA, []disasm.Instr{instr}, nil, nil)
	c := &cfg.CFG{FuncName: fn.Name, FuncAddr: fn.Addr, Blocks: []*cfg.BasicBlock{blk}}

	f := ir.LiftArch(fn, c, textData, textVA, nil, "x86_64")
	if len(f.Blocks) == 0 {
		t.Fatal("expected at least one block")
	}

	var foundRet bool
	for _, block := range f.Blocks {
		for _, instr := range block.Instrs {
			if instr.Op == ir.OpReturn {
				foundRet = true
			}
		}
	}
	if !foundRet {
		t.Error("expected OpReturn in lifted IR, not found")
	}
}

// TestLiftX86_MovAssign encodes MOV RAX, RBX (48 89 D8) and verifies OpAssign.
func TestLiftX86_MovAssign(t *testing.T) {
	// MOV RAX, RBX = 48 89 D8
	textData := []byte{0x48, 0x89, 0xD8}
	textVA := uint64(0x1000)

	d := disasm.New("x86_64")
	instr, err := d.Decode(textData, textVA)
	if err != nil {
		t.Fatalf("decode MOV RAX,RBX: %v", err)
	}

	fn := makeFn("main.Mov", "main", textVA, uint64(len(textData)))
	blk := makeBlock(0, textVA, []disasm.Instr{instr}, nil, nil)
	c := &cfg.CFG{FuncName: fn.Name, FuncAddr: fn.Addr, Blocks: []*cfg.BasicBlock{blk}}

	f := ir.LiftArch(fn, c, textData, textVA, nil, "x86_64")
	if len(f.Blocks) == 0 || len(f.Blocks[0].Instrs) == 0 {
		t.Fatal("expected instructions in lifted block")
	}

	found := false
	for _, instr := range f.Blocks[0].Instrs {
		if instr.Op == ir.OpAssign {
			found = true
			if instr.Dst != "_rax" {
				t.Errorf("expected dst=_rax, got %q", instr.Dst)
			}
			if len(instr.Src) == 0 || instr.Src[0] != "_rbx" {
				t.Errorf("expected src[0]=_rbx, got %v", instr.Src)
			}
		}
	}
	if !found {
		t.Error("expected OpAssign instruction for MOV RAX,RBX")
	}
}

// TestLiftX86_AddArith encodes ADD RAX, RBX (48 01 D8) and verifies OpArith with "add".
func TestLiftX86_AddArith(t *testing.T) {
	// ADD RAX, RBX = 48 01 D8
	textData := []byte{0x48, 0x01, 0xD8}
	textVA := uint64(0x1000)

	d := disasm.New("x86_64")
	instr, err := d.Decode(textData, textVA)
	if err != nil {
		t.Fatalf("decode ADD: %v", err)
	}

	fn := makeFn("main.Add", "main", textVA, uint64(len(textData)))
	blk := makeBlock(0, textVA, []disasm.Instr{instr}, nil, nil)
	c := &cfg.CFG{FuncName: fn.Name, FuncAddr: fn.Addr, Blocks: []*cfg.BasicBlock{blk}}

	f := ir.LiftArch(fn, c, textData, textVA, nil, "x86_64")
	if len(f.Blocks) == 0 {
		t.Fatal("no blocks")
	}

	found := false
	for _, ir_ := range f.Blocks[0].Instrs {
		if ir_.Op == ir.OpArith && ir_.Meta == "add" {
			found = true
		}
	}
	if !found {
		t.Error("expected OpArith(add) for ADD RAX,RBX")
	}
}

// TestRenameVars_BasicRenaming verifies that SSA renaming creates versioned names.
func TestRenameVars_BasicRenaming(t *testing.T) {
	f := &ir.IRFunc{
		Name:    "main.test",
		Package: "main",
		Vars:    map[string]string{},
		Blocks: []*ir.IRBlock{
			{
				ID:    0,
				Label: "L0",
				Instrs: []ir.IRInstr{
					{Op: ir.OpAssign, Dst: "_rax", Src: []string{"_rbx"}},
					{Op: ir.OpArith, Dst: "_rax", Src: []string{"_rax", "0x1"}, Meta: "add"},
				},
			},
		},
	}

	ir.RenameVars(f)

	// After renaming, _rax should have at least two distinct versioned names.
	names := map[string]bool{}
	for _, instr := range f.Blocks[0].Instrs {
		if instr.Dst != "" {
			names[instr.Dst] = true
		}
	}
	if len(names) < 2 {
		t.Errorf("expected at least 2 distinct dst names after SSA rename, got %v", names)
	}
}

// TestRecoverVars_ParamNaming verifies that discovered params become "param0", "param1", etc.
func TestRecoverVars_ParamNaming(t *testing.T) {
	f := &ir.IRFunc{
		Name:    "main.Fn",
		Package: "main",
		Params:  []string{"_rax_v0", "_rbx_v0"},
		Vars:    map[string]string{"_rax_v0": "", "_rbx_v0": ""},
		Blocks:  []*ir.IRBlock{{ID: 0, Label: "L0", Instrs: []ir.IRInstr{
			{Op: ir.OpAssign, Dst: "_rax_v0", Src: []string{"0x1"}},
			{Op: ir.OpReturn, Src: []string{"_rbx_v0"}},
		}}},
	}

	ir.RecoverVars(f)

	if len(f.Params) != 2 || f.Params[0] != "param0" || f.Params[1] != "param1" {
		t.Errorf("expected params [param0, param1], got %v", f.Params)
	}
}

// TestPropTypes_ArithIsInt verifies that OpArith destinations get typed as int64_t.
func TestPropTypes_ArithIsInt(t *testing.T) {
	f := &ir.IRFunc{
		Name:    "main.Fn",
		Package: "main",
		Vars:    map[string]string{"v0": ""},
		Blocks: []*ir.IRBlock{{
			ID:    0,
			Label: "L0",
			Instrs: []ir.IRInstr{
				{Op: ir.OpArith, Dst: "v0", Src: []string{"param0", "param1"}, Meta: "add"},
			},
		}},
	}

	ir.PropTypes(f, nil)

	if f.Vars["v0"] != "int64_t" {
		t.Errorf("expected v0 to be int64_t, got %q", f.Vars["v0"])
	}
}

// TestPropTypes_LoadIsPointer verifies that OpLoad destinations get typed as void*.
func TestPropTypes_LoadIsPointer(t *testing.T) {
	f := &ir.IRFunc{
		Name:    "main.Fn",
		Package: "main",
		Vars:    map[string]string{"ptr": ""},
		Blocks: []*ir.IRBlock{{
			ID:    0,
			Label: "L0",
			Instrs: []ir.IRInstr{
				{Op: ir.OpLoad, Dst: "ptr", Src: []string{"_rsp + 0x8"}},
			},
		}},
	}

	ir.PropTypes(f, nil)

	if f.Vars["ptr"] != "void*" {
		t.Errorf("expected ptr to be void*, got %q", f.Vars["ptr"])
	}
}

// TestBlockLabel verifies that block labels follow "L<id>" format.
func TestBlockLabel(t *testing.T) {
	fn := makeFn("main.F", "main", 0x1000, 1)
	// Single NOP (0x90) to make a non-empty block.
	textData := []byte{0x90}
	textVA := uint64(0x1000)

	d := disasm.New("x86_64")
	instr, _ := d.Decode(textData, textVA)

	blk := makeBlock(5, textVA, []disasm.Instr{instr}, nil, nil)
	c := &cfg.CFG{FuncName: fn.Name, FuncAddr: fn.Addr, Blocks: []*cfg.BasicBlock{blk}}

	f := ir.LiftArch(fn, c, textData, textVA, nil, "x86_64")
	if len(f.Blocks) == 0 {
		t.Fatal("expected at least one block")
	}
	if f.Blocks[0].Label != "L5" {
		t.Errorf("expected label L5, got %q", f.Blocks[0].Label)
	}
}

// TestLiftX86_CallResolution verifies that call targets are resolved to function names.
func TestLiftX86_CallResolution(t *testing.T) {
	// CALL rel32 targeting 0x2000: E8 FB 0F 00 00
	// Relative offset = 0x2000 - (0x1000 + 5) = 0x0FFB
	textData := []byte{0xE8, 0xFB, 0x0F, 0x00, 0x00}
	textVA := uint64(0x1000)

	addrToName := map[uint64]string{0x2000: "fmt.Println"}

	d := disasm.New("x86_64")
	instr, err := d.Decode(textData, textVA)
	if err != nil {
		t.Fatalf("decode CALL: %v", err)
	}

	fn := makeFn("main.Main", "main", textVA, uint64(len(textData)))
	blk := makeBlock(0, textVA, []disasm.Instr{instr}, nil, nil)
	c := &cfg.CFG{FuncName: fn.Name, FuncAddr: fn.Addr, Blocks: []*cfg.BasicBlock{blk}}

	f := ir.LiftArch(fn, c, textData, textVA, addrToName, "x86_64")
	if len(f.Blocks) == 0 {
		t.Fatal("no blocks")
	}

	found := false
	for _, ir_ := range f.Blocks[0].Instrs {
		if ir_.Op == ir.OpCall && ir_.Target == "fmt.Println" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected OpCall to fmt.Println; got instrs: %v", f.Blocks[0].Instrs)
	}
}

// TestLiftX86_CondBranch verifies CMP+JE produces an OpIf with "==" condition.
func TestLiftX86_CondBranch(t *testing.T) {
	// CMP RAX, RBX: 48 39 D8  (3 bytes)
	// JE +5:        74 05      (2 bytes) → target = 0x1000 + 5 + 5 = 0x100A
	textData := []byte{0x48, 0x39, 0xD8, 0x74, 0x05}
	textVA := uint64(0x1000)

	d := disasm.New("x86_64")
	var instrs []disasm.Instr
	pos := 0
	for pos < len(textData) {
		instr, err := d.Decode(textData[pos:], textVA+uint64(pos))
		if err != nil {
			t.Fatalf("decode at offset %d: %v", pos, err)
		}
		instrs = append(instrs, instr)
		pos += instr.Len
	}

	fn := makeFn("main.Cond", "main", textVA, uint64(len(textData)))
	blk := makeBlock(0, textVA, instrs, nil, nil)
	c := &cfg.CFG{FuncName: fn.Name, FuncAddr: fn.Addr, Blocks: []*cfg.BasicBlock{blk}}

	f := ir.LiftArch(fn, c, textData, textVA, nil, "x86_64")
	if len(f.Blocks) == 0 {
		t.Fatal("no blocks")
	}

	found := false
	for _, ir_ := range f.Blocks[0].Instrs {
		if ir_.Op == ir.OpIf {
			found = true
			if !strings.Contains(ir_.Meta, "==") {
				t.Errorf("expected '==' in condition, got %q", ir_.Meta)
			}
		}
	}
	if !found {
		t.Error("expected OpIf for CMP+JE sequence")
	}
}
