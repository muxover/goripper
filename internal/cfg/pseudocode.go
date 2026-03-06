package cfg

import (
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// Emit converts a CFG to simplified pseudocode text.
// The output is an approximation, not compilable code.
func Emit(cfg *CFG, addrToName map[uint64]string) string {
	if cfg == nil || len(cfg.Blocks) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("func %s():\n", cfg.FuncName))

	for _, block := range cfg.Blocks {
		if len(block.Instrs) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("  block_%d: // 0x%x\n", block.ID, block.StartPC))

		for _, di := range block.Instrs {
			line := liftInstr(di, addrToName)
			if line != "" {
				sb.WriteString("    ")
				sb.WriteString(line)
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

// liftInstr converts a single instruction to a pseudocode line.
// Returns empty string for instructions that generate too much noise.
func liftInstr(di DecodedInstr, addrToName map[uint64]string) string {
	inst := di.Inst

	switch inst.Op {
	case x86asm.CALL:
		callee := resolveCallTarget(di, addrToName)
		return fmt.Sprintf("call %s", callee)

	case x86asm.RET, x86asm.LRET:
		return "return"

	case x86asm.JMP:
		if target, ok := branchTarget(di); ok {
			if name, ok := addrToName[target]; ok {
				return fmt.Sprintf("goto %s", name)
			}
			return fmt.Sprintf("goto 0x%x", target)
		}
		return "goto <indirect>"

	case x86asm.JE:
		return fmt.Sprintf("if equal: goto %s", branchDesc(di, addrToName))
	case x86asm.JNE:
		return fmt.Sprintf("if not-equal: goto %s", branchDesc(di, addrToName))
	case x86asm.JL, x86asm.JB:
		return fmt.Sprintf("if less: goto %s", branchDesc(di, addrToName))
	case x86asm.JG, x86asm.JA:
		return fmt.Sprintf("if greater: goto %s", branchDesc(di, addrToName))
	case x86asm.JLE, x86asm.JBE:
		return fmt.Sprintf("if less-or-equal: goto %s", branchDesc(di, addrToName))
	case x86asm.JGE, x86asm.JAE:
		return fmt.Sprintf("if greater-or-equal: goto %s", branchDesc(di, addrToName))
	case x86asm.JS:
		return fmt.Sprintf("if negative: goto %s", branchDesc(di, addrToName))
	case x86asm.JNS:
		return fmt.Sprintf("if non-negative: goto %s", branchDesc(di, addrToName))

	case x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		return fmt.Sprintf("loop: goto %s", branchDesc(di, addrToName))

	case x86asm.MOV:
		return fmt.Sprintf("%s = %s", argStr(inst.Args[0]), argStr(inst.Args[1]))

	case x86asm.PUSH:
		return fmt.Sprintf("push %s", argStr(inst.Args[0]))

	case x86asm.POP:
		return fmt.Sprintf("pop %s", argStr(inst.Args[0]))

	case x86asm.ADD:
		return fmt.Sprintf("%s += %s", argStr(inst.Args[0]), argStr(inst.Args[1]))

	case x86asm.SUB:
		return fmt.Sprintf("%s -= %s", argStr(inst.Args[0]), argStr(inst.Args[1]))

	case x86asm.CMP:
		return fmt.Sprintf("cmp %s, %s", argStr(inst.Args[0]), argStr(inst.Args[1]))

	case x86asm.TEST:
		return fmt.Sprintf("test %s, %s", argStr(inst.Args[0]), argStr(inst.Args[1]))

	case x86asm.XOR:
		// Skip XOR reg, reg (zero idiom) as it's noise
		if inst.Args[0] == inst.Args[1] {
			return ""
		}
		return fmt.Sprintf("%s ^= %s", argStr(inst.Args[0]), argStr(inst.Args[1]))

	case x86asm.LEA:
		return fmt.Sprintf("%s = &(%s)", argStr(inst.Args[0]), argStr(inst.Args[1]))

	case x86asm.NOP:
		return "" // noise

	default:
		// Include the raw instruction for everything else
		return strings.ToLower(inst.Op.String()) + " " + argsStr(inst)
	}
}

func resolveCallTarget(di DecodedInstr, addrToName map[uint64]string) string {
	inst := di.Inst
	if len(inst.Args) == 0 || inst.Args[0] == nil {
		return "<indirect>"
	}
	switch arg := inst.Args[0].(type) {
	case x86asm.Rel:
		target := di.PC + uint64(inst.Len) + uint64(arg)
		if name, ok := addrToName[target]; ok {
			return name
		}
		return fmt.Sprintf("0x%x", target)
	case x86asm.Reg:
		return fmt.Sprintf("<indirect:%s>", arg)
	default:
		return "<indirect>"
	}
}

func branchDesc(di DecodedInstr, addrToName map[uint64]string) string {
	if target, ok := branchTarget(di); ok {
		if name, ok := addrToName[target]; ok {
			return name
		}
		return fmt.Sprintf("block_0x%x", target)
	}
	return "<indirect>"
}

func argStr(arg x86asm.Arg) string {
	if arg == nil {
		return ""
	}
	switch a := arg.(type) {
	case x86asm.Reg:
		return strings.ToLower(a.String())
	case x86asm.Imm:
		return fmt.Sprintf("0x%x", uint64(a))
	case x86asm.Mem:
		if a.Base == x86asm.RIP {
			return fmt.Sprintf("[rip+0x%x]", a.Disp)
		}
		if a.Index == 0 && a.Scale == 0 {
			if a.Disp != 0 {
				return fmt.Sprintf("[%s+0x%x]", strings.ToLower(a.Base.String()), a.Disp)
			}
			return fmt.Sprintf("[%s]", strings.ToLower(a.Base.String()))
		}
		return arg.String()
	default:
		return arg.String()
	}
}

func argsStr(inst x86asm.Inst) string {
	var parts []string
	for _, a := range inst.Args {
		if a == nil {
			break
		}
		parts = append(parts, argStr(a))
	}
	return strings.Join(parts, ", ")
}
