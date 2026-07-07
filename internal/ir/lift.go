package ir

import (
	"fmt"
	"strings"

	"github.com/muxover/goripper/internal/cfg"
	"github.com/muxover/goripper/internal/functions"
)

// textData/textVA must span the entire binary text section so each instruction
// can be re-decoded with full operand detail by the architecture-specific lifter.
func Lift(fn functions.Function, c *cfg.CFG, textData []byte, textVA uint64, addrToName map[uint64]string) *IRFunc {
	f := &IRFunc{
		Name:    fn.Name,
		Package: fn.Package,
		Addr:    fn.Addr,
		Vars:    make(map[string]string),
	}

	if c == nil || len(c.Blocks) == 0 {
		return f
	}

	arch := archFromPackage(fn)

	for _, bb := range c.Blocks {
		irb := &IRBlock{
			ID:    bb.ID,
			Label: blockLabel(bb.StartPC),
			Succs: append([]int(nil), bb.Succs...),
			Preds: append([]int(nil), bb.Preds...),
		}
		irb.Instrs = liftBlock(bb, textData, textVA, addrToName, arch)
		f.Blocks = append(f.Blocks, irb)
	}

	f.Params, f.RetVars = discoverParams(f, arch)
	return f
}

func archFromPackage(_ functions.Function) string {
	return "x86_64"
}

func LiftArch(fn functions.Function, c *cfg.CFG, textData []byte, textVA uint64, addrToName map[uint64]string, arch string) *IRFunc {
	f := &IRFunc{
		Name:    fn.Name,
		Package: fn.Package,
		Addr:    fn.Addr,
		Vars:    make(map[string]string),
	}
	if c == nil || len(c.Blocks) == 0 {
		return f
	}
	for _, bb := range c.Blocks {
		irb := &IRBlock{
			ID:    bb.ID,
			Label: blockLabel(bb.StartPC),
			Succs: append([]int(nil), bb.Succs...),
			Preds: append([]int(nil), bb.Preds...),
		}
		irb.Instrs = liftBlock(bb, textData, textVA, addrToName, arch)
		f.Blocks = append(f.Blocks, irb)
	}
	f.Params, f.RetVars = discoverParams(f, arch)
	return f
}

func liftBlock(bb *cfg.BasicBlock, textData []byte, textVA uint64, addrToName map[uint64]string, arch string) []IRInstr {
	var out []IRInstr
	// pendingCmp holds the two operands of the most recent CMP/TEST so the
	// following conditional branch can build a proper condition expression.
	var pendingCmp [2]string

	for _, dinstr := range bb.Instrs {
		if dinstr.VA < textVA {
			out = append(out, mkComment(fmt.Sprintf("instr VA 0x%x below text base", dinstr.VA)))
			continue
		}
		off := dinstr.VA - textVA
		if int(off)+dinstr.Len > len(textData) {
			out = append(out, mkComment(fmt.Sprintf("instr at 0x%x out of text range", dinstr.VA)))
			continue
		}
		raw := textData[off : int(off)+dinstr.Len]

		var lifted []IRInstr
		var newCmp [2]string

		switch arch {
		case "x86_64", "386":
			lifted, newCmp = liftX86Instr(raw, dinstr, addrToName, pendingCmp)
		case "arm64":
			lifted, newCmp = liftArm64Instr(raw, dinstr, addrToName, pendingCmp)
		default:
			lifted = []IRInstr{mkComment(fmt.Sprintf("unsupported arch %q at 0x%x", arch, dinstr.VA))}
		}

		if newCmp != ([2]string{}) {
			pendingCmp = newCmp
		} else if len(lifted) > 0 {
			last := lifted[len(lifted)-1]
			// Reset pendingCmp unless the instruction is a branch/goto/return that
			// consumes it, or a comment that doesn't affect state.
			switch last.Op {
			case OpIf, OpGoto, OpReturn, OpComment, OpLabel:
				// keep pendingCmp for potential second branch off same comparison
			default:
				pendingCmp = [2]string{}
			}
		}

		out = append(out, lifted...)
	}
	return out
}

func discoverParams(f *IRFunc, arch string) (params []string, rets []string) {
	// Go register calling convention (Go 1.17+) argument registers, in order.
	var argOrder []string
	switch arch {
	case "x86_64", "386":
		argOrder = []string{"_rax", "_rbx", "_rcx", "_rdi", "_rsi", "_r8", "_r9", "_r10", "_r11"}
	case "arm64":
		argOrder = []string{
			"_r0", "_r1", "_r2", "_r3", "_r4", "_r5", "_r6", "_r7",
			"_r8", "_r9", "_r10", "_r11", "_r12", "_r13", "_r14", "_r15",
		}
	default:
		return nil, nil
	}

	written := make(map[string]bool)
	paramSet := make(map[string]bool)

	for _, blk := range f.Blocks {
		for _, instr := range blk.Instrs {
			for _, src := range instr.Src {
				if isRegVar(src) && !written[src] {
					paramSet[src] = true
				}
			}
			if instr.Dst != "" && isRegVar(instr.Dst) {
				written[instr.Dst] = true
			}
		}
	}

	for _, r := range argOrder {
		if paramSet[r] {
			params = append(params, r)
		}
	}
	return params, nil
}

func isRegVar(s string) bool {
	return len(s) > 1 && s[0] == '_'
}

func blockLabel(startPC uint64) string {
	return fmt.Sprintf("L_0x%x", startPC)
}

func mkComment(text string) IRInstr {
	return IRInstr{Op: OpComment, Meta: text}
}

// FilterBoilerplate removes Go runtime boilerplate from lifted IR blocks.
// Currently suppresses the stack growth check prologue that appears at the
// entry of every Go function: LEA + CMP against [g+0x10] + JBE morestack.
// The pattern is identified by an OpIf whose true-branch label is a hex
// address (outside the function) and whose condition references the goroutine
// pointer register (_r14 on x86_64, _r28 on ARM64).
func FilterBoilerplate(f *IRFunc) {
	for _, blk := range f.Blocks {
		var out []IRInstr
		instrs := blk.Instrs
		i := 0
		for i < len(instrs) {
			instr := instrs[i]
			if instr.Op == OpIf && isStackGrowthCheck(instr) {
				// Back up to absorb the preceding LEA that computed the stack limit.
				if len(out) > 0 {
					prev := out[len(out)-1]
					if isStackLimitLEA(prev) {
						out = out[:len(out)-1]
					}
				}
				out = append(out, mkComment("stack growth check"))
				i++
				continue
			}
			out = append(out, instr)
			i++
		}
		blk.Instrs = out
	}
}

// isStackGrowthCheck detects the JBE morestack conditional branch.
// The true-branch label is a hex address (L_0x...) because morestack lives
// outside the current function, and the condition references _r14 (the
// goroutine pointer register in the Go x86_64 ABI) or _r28 (ARM64).
func isStackGrowthCheck(instr IRInstr) bool {
	if instr.Op != OpIf {
		return false
	}
	// True-branch must be a hex address label (not a simple L<N> block label).
	if !strings.HasPrefix(instr.Label, "L_0x") {
		return false
	}
	// Condition must reference the goroutine pointer register.
	return strings.Contains(instr.Meta, "_r14") || strings.Contains(instr.Meta, "_r28")
}

// isStackLimitLEA detects the preceding LEA that computes RSP - frameSize.
func isStackLimitLEA(instr IRInstr) bool {
	if instr.Op != OpAssign {
		return false
	}
	return len(instr.Src) > 0 && strings.Contains(instr.Src[0], "_rsp")
}
