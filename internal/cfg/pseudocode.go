package cfg

import (
	"fmt"
	"strings"

	"github.com/muxover/goripper/internal/disasm"
)

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
		for _, instr := range block.Instrs {
			if line := liftInstr(instr, addrToName); line != "" {
				sb.WriteString("    ")
				sb.WriteString(line)
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

func liftInstr(instr disasm.Instr, addrToName map[uint64]string) string {
	switch instr.Op {
	case disasm.OpCall:
		if instr.Indirect {
			return "call <indirect>"
		}
		if name, ok := addrToName[instr.Target]; ok {
			return fmt.Sprintf("call %s", name)
		}
		return fmt.Sprintf("call 0x%x", instr.Target)
	case disasm.OpRet:
		return "return"
	case disasm.OpUncondBranch:
		if instr.Indirect {
			return "goto <indirect>"
		}
		if name, ok := addrToName[instr.Target]; ok {
			return fmt.Sprintf("goto %s", name)
		}
		return fmt.Sprintf("goto 0x%x", instr.Target)
	case disasm.OpCondBranch:
		if name, ok := addrToName[instr.Target]; ok {
			return fmt.Sprintf("if cond: goto %s", name)
		}
		if instr.Target != 0 {
			return fmt.Sprintf("if cond: goto 0x%x", instr.Target)
		}
		return "if cond: goto <indirect>"
	}
	return ""
}
