package ir

import (
	"fmt"
	"strings"
)

func RecoverVars(f *IRFunc) {
	if len(f.Blocks) == 0 {
		return
	}

	rename := make(map[string]string)

	loopCtr := []string{"i", "j", "k", "n", "m"}
	loopIdx := 0
	localIdx := 0

	paramMap := make(map[string]int) // base reg → param index
	for i, p := range f.Params {
		paramMap[p] = i
	}

	// Explicitly rename the seeded v0 versions of param registers.
	// SSA seeding pre-creates _raxX_v0 in f.Vars but they never appear
	// as Dst of any instruction, so the instruction-scan loop below would miss them.
	for reg, pi := range paramMap {
		v0 := reg + "_v0"
		if _, exists := f.Vars[v0]; exists {
			rename[v0] = fmt.Sprintf("param%d", pi)
		}
	}

	for _, blk := range f.Blocks {
		for _, instr := range blk.Instrs {
			if instr.Dst == "" || !isSSAVar(instr.Dst) {
				continue
			}
			if _, already := rename[instr.Dst]; already {
				continue
			}

			base := ssaBase(instr.Dst)

			if pi, ok := paramMap[base]; ok && isFirstVersion(instr.Dst) {
				rename[instr.Dst] = fmt.Sprintf("param%d", pi)
				continue
			}

			// Loop counter heuristic: variable incremented by a small constant
			// (detected as OpArith "add" where one src is itself and other is small imm).
			if isLoopIncrement(instr) && loopIdx < len(loopCtr) {
				rename[instr.Dst] = loopCtr[loopIdx]
				loopIdx++
				continue
			}

			rename[instr.Dst] = fmt.Sprintf("v%d", localIdx)
			localIdx++
		}
	}

	for _, blk := range f.Blocks {
		for i, instr := range blk.Instrs {
			blk.Instrs[i].Dst = applyRename(instr.Dst, rename)
			blk.Instrs[i].Src = renameSlice(instr.Src, rename)
			blk.Instrs[i].Meta = applyRenameExpr(instr.Meta, rename)
		}
	}

	newParams := make([]string, len(f.Params))
	for i := range f.Params {
		newParams[i] = fmt.Sprintf("param%d", i)
	}
	f.Params = newParams

	newVars := make(map[string]string, len(f.Vars))
	for old, typ := range f.Vars {
		friendly := applyRename(old, rename)
		newVars[friendly] = typ
	}
	f.Vars = newVars
}

func isSSAVar(s string) bool {
	if !isRegVar(s) {
		return false
	}
	return strings.Contains(s, "_v")
}

func ssaBase(s string) string {
	if i := strings.LastIndex(s, "_v"); i > 0 {
		return s[:i]
	}
	return s
}

func isFirstVersion(s string) bool {
	return strings.HasSuffix(s, "_v0")
}

// isLoopIncrement detects the pattern: dst = dst_prev + small_imm
// which is the canonical loop-counter increment.
func isLoopIncrement(instr IRInstr) bool {
	if instr.Op != OpArith || instr.Meta != "add" || len(instr.Src) < 2 {
		return false
	}
	s := instr.Src[1]
	switch s {
	case "0x1", "0x2", "0x4", "0x8", "1", "2", "4", "8":
		return true
	}
	return false
}

func applyRename(s string, rename map[string]string) string {
	if v, ok := rename[s]; ok {
		return v
	}
	return s
}

func applyRenameExpr(expr string, rename map[string]string) string {
	result := expr
	for old, newV := range rename {
		result = replaceWord(result, old, newV)
	}
	return result
}

func renameSlice(srcs []string, rename map[string]string) []string {
	if len(srcs) == 0 {
		return srcs
	}
	out := make([]string, len(srcs))
	for i, s := range srcs {
		out[i] = applyRenameExpr(s, rename)
	}
	return out
}
