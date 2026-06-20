package ir

import (
	"fmt"

	"github.com/muxover/goripper/internal/disasm"
	"golang.org/x/arch/arm64/arm64asm"
)

func liftArm64Instr(raw []byte, dinstr disasm.Instr, addrToName map[uint64]string, pendingCmp [2]string) ([]IRInstr, [2]string) {
	if len(raw) < 4 {
		return []IRInstr{mkComment(fmt.Sprintf("short arm64 instr at 0x%x", dinstr.VA))}, [2]string{}
	}
	inst, err := arm64asm.Decode(raw[:4])
	if err != nil {
		return []IRInstr{mkComment(fmt.Sprintf("decode err at 0x%x: %v", dinstr.VA, err))}, [2]string{}
	}

	switch dinstr.Op {
	case disasm.OpCall:
		target := arm64ResolveCall(inst, dinstr, addrToName)
		return []IRInstr{{Op: OpCall, Dst: "_ret", Target: target, Addr: dinstr.VA}}, [2]string{}

	case disasm.OpRet:
		return []IRInstr{{Op: OpReturn, Addr: dinstr.VA}}, [2]string{}

	case disasm.OpUncondBranch:
		label := arm64BranchLabel(dinstr.Target, addrToName)
		return []IRInstr{{Op: OpGoto, Label: label, Addr: dinstr.VA}}, [2]string{}

	case disasm.OpCondBranch:
		cmpOp := arm64CondOp(inst)
		cond := buildCond(pendingCmp, cmpOp)
		trueLabel := arm64BranchLabel(dinstr.Target, addrToName)
		falseLabel := arm64BranchLabel(dinstr.VA+4, addrToName)
		return []IRInstr{{Op: OpIf, Meta: cond, Label: trueLabel, Label2: falseLabel, Addr: dinstr.VA}}, [2]string{}
	}

	switch inst.Op {
	case arm64asm.MOV, arm64asm.MOVZ, arm64asm.MOVN, arm64asm.MOVK:
		return liftArm64Mov(inst, dinstr.VA), [2]string{}

	case arm64asm.LDR, arm64asm.LDRB, arm64asm.LDRH, arm64asm.LDRSB, arm64asm.LDRSH, arm64asm.LDRSW:
		return liftArm64Load(inst, dinstr.VA), [2]string{}

	case arm64asm.LDP:
		return liftArm64Ldp(inst, dinstr.VA), [2]string{}

	case arm64asm.STR, arm64asm.STRB, arm64asm.STRH:
		return liftArm64Store(inst, dinstr.VA), [2]string{}

	case arm64asm.STP:
		return liftArm64Stp(inst, dinstr.VA), [2]string{}

	case arm64asm.ADD:
		return liftArm64Arith(inst, "add", dinstr.VA), [2]string{}
	case arm64asm.SUB, arm64asm.SUBS:
		return liftArm64Arith(inst, "sub", dinstr.VA), [2]string{}
	case arm64asm.MUL, arm64asm.SMULL, arm64asm.UMULL:
		return liftArm64Arith(inst, "mul", dinstr.VA), [2]string{}
	case arm64asm.SDIV, arm64asm.UDIV:
		return liftArm64Arith(inst, "div", dinstr.VA), [2]string{}
	case arm64asm.AND, arm64asm.ANDS:
		return liftArm64Arith(inst, "and", dinstr.VA), [2]string{}
	case arm64asm.ORR:
		return liftArm64Arith(inst, "or", dinstr.VA), [2]string{}
	case arm64asm.EOR:
		return liftArm64Arith(inst, "xor", dinstr.VA), [2]string{}
	case arm64asm.LSL:
		return liftArm64Arith(inst, "shl", dinstr.VA), [2]string{}
	case arm64asm.LSR:
		return liftArm64Arith(inst, "shr", dinstr.VA), [2]string{}
	case arm64asm.ASR:
		return liftArm64Arith(inst, "sar", dinstr.VA), [2]string{}

	case arm64asm.NEG, arm64asm.NEGS:
		if len(inst.Args) >= 2 && inst.Args[0] != nil && inst.Args[1] != nil {
			dst := arm64ArgStr(inst.Args[0])
			src := arm64ArgStr(inst.Args[1])
			return []IRInstr{{Op: OpUnary, Dst: dst, Src: []string{src}, Meta: "neg", Addr: dinstr.VA}}, [2]string{}
		}

	case arm64asm.CMP, arm64asm.CMN, arm64asm.TST:
		return liftArm64Cmp(inst, dinstr.VA)

	case arm64asm.CBZ, arm64asm.CBNZ:
		return liftArm64CbzCbnz(inst, dinstr, addrToName)

	case arm64asm.NOP:
		return nil, [2]string{}
	}

	return []IRInstr{mkComment(inst.String())}, [2]string{}
}

func liftArm64Mov(inst arm64asm.Inst, va uint64) []IRInstr {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return []IRInstr{mkComment(inst.String())}
	}
	dst := arm64ArgStr(inst.Args[0])
	src := arm64ArgStr(inst.Args[1])
	return []IRInstr{{Op: OpAssign, Dst: dst, Src: []string{src}, Addr: va}}
}

func liftArm64Load(inst arm64asm.Inst, va uint64) []IRInstr {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return []IRInstr{mkComment(inst.String())}
	}
	dst := arm64ArgStr(inst.Args[0])
	addr := arm64MemStr(inst.Args[1])
	return []IRInstr{{Op: OpLoad, Dst: dst, Src: []string{addr}, Addr: va}}
}

func liftArm64Ldp(inst arm64asm.Inst, va uint64) []IRInstr {
	if len(inst.Args) < 3 || inst.Args[0] == nil || inst.Args[1] == nil || inst.Args[2] == nil {
		return []IRInstr{mkComment(inst.String())}
	}
	dst1 := arm64ArgStr(inst.Args[0])
	dst2 := arm64ArgStr(inst.Args[1])
	addr := arm64MemStr(inst.Args[2])
	return []IRInstr{
		{Op: OpLoad, Dst: dst1, Src: []string{addr}, Addr: va},
		{Op: OpLoad, Dst: dst2, Src: []string{addr + "+8"}, Addr: va},
	}
}

func liftArm64Store(inst arm64asm.Inst, va uint64) []IRInstr {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return []IRInstr{mkComment(inst.String())}
	}
	src := arm64ArgStr(inst.Args[0])
	addr := arm64MemStr(inst.Args[1])
	return []IRInstr{{Op: OpStore, Dst: addr, Src: []string{src}, Addr: va}}
}

func liftArm64Stp(inst arm64asm.Inst, va uint64) []IRInstr {
	if len(inst.Args) < 3 || inst.Args[0] == nil || inst.Args[1] == nil || inst.Args[2] == nil {
		return []IRInstr{mkComment(inst.String())}
	}
	src1 := arm64ArgStr(inst.Args[0])
	src2 := arm64ArgStr(inst.Args[1])
	addr := arm64MemStr(inst.Args[2])
	return []IRInstr{
		{Op: OpStore, Dst: addr, Src: []string{src1}, Addr: va},
		{Op: OpStore, Dst: addr + "+8", Src: []string{src2}, Addr: va},
	}
}

func liftArm64Arith(inst arm64asm.Inst, op string, va uint64) []IRInstr {
	if len(inst.Args) < 3 || inst.Args[0] == nil || inst.Args[1] == nil || inst.Args[2] == nil {
		if len(inst.Args) >= 2 && inst.Args[0] != nil && inst.Args[1] != nil {
			dst := arm64ArgStr(inst.Args[0])
			src := arm64ArgStr(inst.Args[1])
			return []IRInstr{{Op: OpArith, Dst: dst, Src: []string{dst, src}, Meta: op, Addr: va}}
		}
		return []IRInstr{mkComment(inst.String())}
	}
	dst := arm64ArgStr(inst.Args[0])
	a := arm64ArgStr(inst.Args[1])
	b := arm64ArgStr(inst.Args[2])
	return []IRInstr{{Op: OpArith, Dst: dst, Src: []string{a, b}, Meta: op, Addr: va}}
}

func liftArm64Cmp(inst arm64asm.Inst, va uint64) ([]IRInstr, [2]string) {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return nil, [2]string{}
	}
	a := arm64ArgStr(inst.Args[0])
	b := arm64ArgStr(inst.Args[1])
	return nil, [2]string{a, b}
}

// liftArm64CbzCbnz handles CBZ/CBNZ which embed the comparison in the branch.
func liftArm64CbzCbnz(inst arm64asm.Inst, dinstr disasm.Instr, addrToName map[uint64]string) ([]IRInstr, [2]string) {
	if len(inst.Args) < 1 || inst.Args[0] == nil {
		return []IRInstr{mkComment(inst.String())}, [2]string{}
	}
	reg := arm64ArgStr(inst.Args[0])
	op := "=="
	if inst.Op == arm64asm.CBNZ {
		op = "!="
	}
	cond := fmt.Sprintf("%s %s 0x0", reg, op)
	trueLabel := arm64BranchLabel(dinstr.Target, addrToName)
	falseLabel := arm64BranchLabel(dinstr.VA+4, addrToName)
	return []IRInstr{{Op: OpIf, Meta: cond, Label: trueLabel, Label2: falseLabel, Addr: dinstr.VA}}, [2]string{}
}

func arm64ArgStr(arg arm64asm.Arg) string {
	if arg == nil {
		return ""
	}
	switch a := arg.(type) {
	case arm64asm.Reg:
		return arm64RegName(a)
	case arm64asm.RegSP:
		// RegSP represents a register where X31/W31 means SP/WSP.
		if a.String() == "SP" || a.String() == "WSP" {
			return "_sp"
		}
		return arm64RegName(arm64asm.Reg(a))
	case arm64asm.ImmShift:
		return a.String()
	case arm64asm.RegExtshiftAmount:
		// All fields are unexported; use String() and convert to IR naming.
		return parseArm64RegStr(a.String())
	case arm64asm.Imm:
		// arm64asm.Imm is a struct with Imm uint32.
		if a.Imm == 0 {
			return "0x0"
		}
		return fmt.Sprintf("0x%x", a.Imm)
	case arm64asm.PCRel:
		return fmt.Sprintf("0x%x", int64(a))
	}
	s := arg.String()
	if s == "" {
		return "?"
	}
	return s
}

// Since MemImmediate.imm is unexported, we use String() to get a readable form
// and strip the ARM64 bracket syntax.
func arm64MemStr(arg arm64asm.Arg) string {
	if arg == nil {
		return "?"
	}
	switch m := arg.(type) {
	case arm64asm.MemImmediate:
		// m.imm is unexported; use String() and strip ARM64 bracket notation.
		baseStr := m.Base.String()
		if baseStr == "SP" || baseStr == "WSP" {
			baseStr = "_sp"
		} else {
			// Parse "X<n>" → "_r<n>"
			baseStr = parseArm64RegStr(baseStr)
		}
		s := m.String()
		return stripBrackets(baseStr, s)
	case arm64asm.MemExtend:
		base := parseArm64RegStr(arm64asm.Reg(m.Base).String())
		idx := arm64RegName(m.Index)
		if m.Amount != 0 {
			return fmt.Sprintf("%s + %s*%d", base, idx, 1<<m.Amount)
		}
		return fmt.Sprintf("%s + %s", base, idx)
	}
	s := arg.String()
	if len(s) >= 2 && s[0] == '[' {
		s = s[1 : len(s)-1]
		// Remove trailing ! for pre-index.
		if len(s) > 0 && s[len(s)-1] == '!' {
			s = s[:len(s)-1]
		}
	}
	return s
}

func stripBrackets(base, s string) string {
	if len(s) >= 2 && s[0] == '[' {
		s = s[1:]
		if s[len(s)-1] == ']' {
			s = s[:len(s)-1]
		} else if s[len(s)-1] == '!' {
			s = s[:len(s)-1]
			if len(s) > 0 && s[len(s)-1] == ']' {
				s = s[:len(s)-1]
			}
		}
	}
	if s == base {
		return base
	}
	return base + s[len(base):]
}

// parseArm64RegStr converts arm64asm register strings ("X0"→"_r0", "W0"→"_r0", "SP"→"_sp").
func parseArm64RegStr(s string) string {
	if s == "SP" || s == "WSP" {
		return "_sp"
	}
	if s == "XZR" || s == "WZR" {
		return "0x0"
	}
	if len(s) > 1 && (s[0] == 'X' || s[0] == 'W') {
		return "_r" + s[1:]
	}
	return "_" + s
}

// arm64RegName maps arm64asm.Reg to a canonical register variable name.
func arm64RegName(r arm64asm.Reg) string {
	switch {
	case r == arm64asm.XZR:
		return "0x0"
	case r == arm64asm.WZR:
		return "0x0"
	case r >= arm64asm.X0 && r <= arm64asm.X30:
		return fmt.Sprintf("_r%d", int(r-arm64asm.X0))
	case r >= arm64asm.W0 && r <= arm64asm.W30:
		return fmt.Sprintf("_r%d", int(r-arm64asm.W0))
	default:
		return fmt.Sprintf("_r%d", int(r))
	}
}

// arm64BranchLabel resolves a branch target to a label or function name.
func arm64BranchLabel(target uint64, addrToName map[uint64]string) string {
	if addrToName != nil {
		if name, ok := addrToName[target]; ok {
			return name
		}
	}
	return fmt.Sprintf("L_0x%x", target)
}

// arm64CondOp extracts the comparison operator from a conditional branch instruction.
// arm64asm.Cond is a struct; we use its String() representation.
func arm64CondOp(inst arm64asm.Inst) string {
	for _, arg := range inst.Args {
		if arg == nil {
			break
		}
		if c, ok := arg.(arm64asm.Cond); ok {
			switch c.String() {
			case "EQ":
				return "=="
			case "NE":
				return "!="
			case "LT", "CC", "LO":
				return "<"
			case "LE", "LS":
				return "<="
			case "GT", "HI":
				return ">"
			case "GE", "CS", "HS":
				return ">="
			case "MI":
				return "< 0 /* neg */"
			case "PL":
				return ">= 0 /* pos */"
			default:
				return "/* cond */"
			}
		}
	}
	return "/* cond */"
}

func arm64ResolveCall(inst arm64asm.Inst, dinstr disasm.Instr, addrToName map[uint64]string) string {
	if dinstr.Indirect {
		for _, arg := range inst.Args {
			if arg == nil {
				break
			}
			if reg, ok := arg.(arm64asm.Reg); ok {
				return fmt.Sprintf("(*%s)", arm64RegName(reg))
			}
		}
		return "<indirect>"
	}
	if name, ok := addrToName[dinstr.Target]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", dinstr.Target)
}
