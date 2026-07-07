package ir

import (
	"fmt"
	"strings"

	"github.com/muxover/goripper/internal/disasm"
	"golang.org/x/arch/x86/x86asm"
)

// newCmp is non-zero when this instruction sets a comparison state (CMP/TEST).
func liftX86Instr(raw []byte, dinstr disasm.Instr, addrToName map[uint64]string, pendingCmp [2]string) ([]IRInstr, [2]string) {
	inst, err := x86asm.Decode(raw, 64)
	if err != nil {
		return []IRInstr{mkComment(fmt.Sprintf("decode err at 0x%x: %v", dinstr.VA, err))}, [2]string{}
	}

	switch dinstr.Op {
	case disasm.OpCall:
		return liftX86Call(inst, dinstr, addrToName), [2]string{}

	case disasm.OpRet:
		return []IRInstr{{Op: OpReturn, Addr: dinstr.VA}}, [2]string{}

	case disasm.OpUncondBranch:
		label := x86BranchLabel(dinstr.Target, addrToName)
		return []IRInstr{{Op: OpGoto, Label: label, Addr: dinstr.VA}}, [2]string{}

	case disasm.OpCondBranch:
		cmpOp := x86CondOp(inst.Op)
		cond := buildCond(pendingCmp, cmpOp)
		trueLabel := x86BranchLabel(dinstr.Target, addrToName)
		nextVA := dinstr.VA + uint64(dinstr.Len)
		falseLabel := x86BranchLabel(nextVA, addrToName)
		return []IRInstr{{Op: OpIf, Src: nil, Meta: cond, Label: trueLabel, Label2: falseLabel, Addr: dinstr.VA}}, [2]string{}
	}

	switch inst.Op {
	case x86asm.MOV, x86asm.MOVSX, x86asm.MOVZX, x86asm.MOVSXD, x86asm.MOVQ:
		return liftX86Mov(inst, dinstr.VA, addrToName), [2]string{}

	case x86asm.MOVUPS, x86asm.MOVAPS, x86asm.MOVDQU, x86asm.MOVDQA, x86asm.MOVSD, x86asm.MOVSS:
		return liftX86Mov(inst, dinstr.VA, addrToName), [2]string{}

	case x86asm.LEA:
		return liftX86Lea(inst, dinstr.VA), [2]string{}

	case x86asm.ADD:
		return liftX86Arith(inst, "add", dinstr.VA), [2]string{}
	case x86asm.SUB:
		return liftX86Arith(inst, "sub", dinstr.VA), [2]string{}
	case x86asm.IMUL, x86asm.MUL:
		return liftX86Arith(inst, "mul", dinstr.VA), [2]string{}
	case x86asm.IDIV, x86asm.DIV:
		return liftX86Arith(inst, "div", dinstr.VA), [2]string{}
	case x86asm.AND:
		return liftX86Arith(inst, "and", dinstr.VA), [2]string{}
	case x86asm.OR:
		return liftX86Arith(inst, "or", dinstr.VA), [2]string{}
	case x86asm.XOR:
		return liftX86Arith(inst, "xor", dinstr.VA), [2]string{}
	case x86asm.SHL:
		return liftX86Arith(inst, "shl", dinstr.VA), [2]string{}
	case x86asm.SHR:
		return liftX86Arith(inst, "shr", dinstr.VA), [2]string{}
	case x86asm.SAR:
		return liftX86Arith(inst, "sar", dinstr.VA), [2]string{}

	case x86asm.NEG:
		if len(inst.Args) > 0 && inst.Args[0] != nil {
			dst := x86ArgStr(inst.Args[0], dinstr.VA, addrToName)
			return []IRInstr{{Op: OpUnary, Dst: dst, Src: []string{dst}, Meta: "neg", Addr: dinstr.VA}}, [2]string{}
		}

	case x86asm.NOT:
		if len(inst.Args) > 0 && inst.Args[0] != nil {
			dst := x86ArgStr(inst.Args[0], dinstr.VA, addrToName)
			return []IRInstr{{Op: OpUnary, Dst: dst, Src: []string{dst}, Meta: "not", Addr: dinstr.VA}}, [2]string{}
		}

	case x86asm.CMP:
		return liftX86Cmp(inst, dinstr.VA, addrToName)

	case x86asm.TEST:
		return liftX86Test(inst, dinstr.VA, addrToName)

	case x86asm.PUSH:
		if len(inst.Args) > 0 && inst.Args[0] != nil {
			src := x86ArgStr(inst.Args[0], dinstr.VA, addrToName)
			return []IRInstr{{Op: OpStore, Dst: "_rsp", Src: []string{src}, Addr: dinstr.VA}}, [2]string{}
		}

	case x86asm.POP:
		if len(inst.Args) > 0 && inst.Args[0] != nil {
			dst := x86ArgStr(inst.Args[0], dinstr.VA, addrToName)
			return []IRInstr{{Op: OpLoad, Dst: dst, Src: []string{"_rsp"}, Addr: dinstr.VA}}, [2]string{}
		}

	case x86asm.XCHG:
		if len(inst.Args) >= 2 && inst.Args[0] != nil && inst.Args[1] != nil {
			a := x86ArgStr(inst.Args[0], dinstr.VA, addrToName)
			b := x86ArgStr(inst.Args[1], dinstr.VA, addrToName)
			tmp := "_xchg_tmp"
			return []IRInstr{
				{Op: OpAssign, Dst: tmp, Src: []string{a}, Addr: dinstr.VA},
				{Op: OpAssign, Dst: a, Src: []string{b}, Addr: dinstr.VA},
				{Op: OpAssign, Dst: b, Src: []string{tmp}, Addr: dinstr.VA},
			}, [2]string{}
		}

	case x86asm.NOP:
		return nil, [2]string{}

	case x86asm.SYSCALL, x86asm.INT:
		return []IRInstr{mkComment(fmt.Sprintf("syscall at 0x%x", dinstr.VA))}, [2]string{}
	}

	return []IRInstr{mkComment(x86asm.IntelSyntax(inst, dinstr.VA, nil))}, [2]string{}
}

func liftX86Call(inst x86asm.Inst, dinstr disasm.Instr, addrToName map[uint64]string) []IRInstr {
	var target string
	if dinstr.Indirect {
		if len(inst.Args) > 0 && inst.Args[0] != nil {
			target = fmt.Sprintf("(*%s)", x86ArgStr(inst.Args[0], dinstr.VA, addrToName))
		} else {
			target = "<indirect>"
		}
	} else if name, ok := addrToName[dinstr.Target]; ok {
		target = name
	} else {
		target = fmt.Sprintf("0x%x", dinstr.Target)
	}
	return []IRInstr{{Op: OpCall, Dst: "_ret", Target: target, Addr: dinstr.VA}}
}

func liftX86Mov(inst x86asm.Inst, va uint64, addrToName map[uint64]string) []IRInstr {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return []IRInstr{mkComment(x86asm.IntelSyntax(inst, va, nil))}
	}
	dst := inst.Args[0]
	src := inst.Args[1]

	dstStr := x86ArgStr(dst, va, addrToName)
	srcStr := x86ArgStr(src, va, addrToName)

	_, dstIsMem := dst.(x86asm.Mem)
	_, srcIsMem := src.(x86asm.Mem)

	switch {
	case dstIsMem && !srcIsMem:
		return []IRInstr{{Op: OpStore, Dst: dstStr, Src: []string{srcStr}, Addr: va}}
	case !dstIsMem && srcIsMem:
		return []IRInstr{{Op: OpLoad, Dst: dstStr, Src: []string{srcStr}, Addr: va}}
	default:
		return []IRInstr{{Op: OpAssign, Dst: dstStr, Src: []string{srcStr}, Addr: va}}
	}
}

func liftX86Lea(inst x86asm.Inst, va uint64) []IRInstr {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return []IRInstr{mkComment(x86asm.IntelSyntax(inst, va, nil))}
	}
	dst := x86ArgStr(inst.Args[0], va, nil)
	mem, ok := inst.Args[1].(x86asm.Mem)
	if !ok {
		return []IRInstr{mkComment(x86asm.IntelSyntax(inst, va, nil))}
	}
	// LEA computes an address expression — emit as arithmetic, not &(mem).
	addr := x86MemAddrExpr(mem)
	return []IRInstr{{Op: OpAssign, Dst: dst, Src: []string{addr}, Addr: va}}
}

func liftX86Arith(inst x86asm.Inst, op string, va uint64) []IRInstr {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		// Single-operand forms (MUL/DIV use implicit RAX).
		if len(inst.Args) >= 1 && inst.Args[0] != nil {
			src := x86ArgStr(inst.Args[0], va, nil)
			return []IRInstr{{Op: OpArith, Dst: "_rax", Src: []string{"_rax", src}, Meta: op, Addr: va}}
		}
		return []IRInstr{mkComment(x86asm.IntelSyntax(inst, va, nil))}
	}
	dst := x86ArgStr(inst.Args[0], va, nil)
	src := x86ArgStr(inst.Args[1], va, nil)
	// x86 two-operand: dst op= src → dst = dst op src
	return []IRInstr{{Op: OpArith, Dst: dst, Src: []string{dst, src}, Meta: op, Addr: va}}
}

func liftX86Cmp(inst x86asm.Inst, va uint64, addrToName map[uint64]string) ([]IRInstr, [2]string) {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return nil, [2]string{}
	}
	a := x86ArgStr(inst.Args[0], va, addrToName)
	b := x86ArgStr(inst.Args[1], va, addrToName)
	return nil, [2]string{a, b}
}

func liftX86Test(inst x86asm.Inst, va uint64, addrToName map[uint64]string) ([]IRInstr, [2]string) {
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return nil, [2]string{}
	}
	a := x86ArgStr(inst.Args[0], va, addrToName)
	b := x86ArgStr(inst.Args[1], va, addrToName)
	// TEST a, a → effectively CMP a, 0.
	if a == b {
		return nil, [2]string{a, "0x0"}
	}
	return nil, [2]string{a + "&" + b, "0x0"}
}

func x86ArgStr(arg x86asm.Arg, va uint64, addrToName map[uint64]string) string {
	if arg == nil {
		return ""
	}
	switch a := arg.(type) {
	case x86asm.Reg:
		return x86RegName(a)
	case x86asm.Imm:
		if a == 0 {
			return "0x0"
		}
		v := int64(a)
		if v < 0 {
			return fmt.Sprintf("-0x%x", -v)
		}
		return fmt.Sprintf("0x%x", v)
	case x86asm.Mem:
		return x86MemExpr(a, va, addrToName)
	case x86asm.Rel:
		// Relative addresses appear in jump/call targets; resolved via dinstr.Target.
		target := uint64(int64(va) + int64(a))
		if addrToName != nil {
			if name, ok := addrToName[target]; ok {
				return name
			}
		}
		return fmt.Sprintf("0x%x", target)
	}
	return "?"
}

func x86MemExpr(m x86asm.Mem, va uint64, addrToName map[uint64]string) string {
	if m.Base == x86asm.RIP {
		abs := uint64(int64(va) + int64(m.Disp))
		if addrToName != nil {
			if name, ok := addrToName[abs]; ok {
				return fmt.Sprintf("(*%s)", name)
			}
		}
		return fmt.Sprintf("(*0x%x)", abs)
	}
	return fmt.Sprintf("(*(%s))", x86MemAddrExpr(m))
}

func x86MemAddrExpr(m x86asm.Mem) string {
	var sb strings.Builder
	if m.Base != 0 {
		sb.WriteString(x86RegName(m.Base))
	}
	if m.Index != 0 {
		if sb.Len() > 0 {
			sb.WriteString(" + ")
		}
		sb.WriteString(x86RegName(m.Index))
		if m.Scale > 1 {
			sb.WriteString(fmt.Sprintf("*%d", m.Scale))
		}
	}
	if m.Disp != 0 {
		if sb.Len() > 0 {
			if m.Disp > 0 {
				sb.WriteString(fmt.Sprintf(" + 0x%x", m.Disp))
			} else {
				sb.WriteString(fmt.Sprintf(" - 0x%x", -m.Disp))
			}
		} else {
			sb.WriteString(fmt.Sprintf("0x%x", m.Disp))
		}
	}
	return sb.String()
}

func x86RegName(r x86asm.Reg) string {
	switch r {
	case x86asm.AL, x86asm.AX, x86asm.EAX, x86asm.RAX:
		return "_rax"
	case x86asm.BL, x86asm.BX, x86asm.EBX, x86asm.RBX:
		return "_rbx"
	case x86asm.CL, x86asm.CX, x86asm.ECX, x86asm.RCX:
		return "_rcx"
	case x86asm.DL, x86asm.DX, x86asm.EDX, x86asm.RDX:
		return "_rdx"
	case x86asm.SIB, x86asm.SI, x86asm.ESI, x86asm.RSI:
		return "_rsi"
	case x86asm.DIB, x86asm.DI, x86asm.EDI, x86asm.RDI:
		return "_rdi"
	case x86asm.SPB, x86asm.SP, x86asm.ESP, x86asm.RSP:
		return "_rsp"
	case x86asm.BPB, x86asm.BP, x86asm.EBP, x86asm.RBP:
		return "_rbp"
	case x86asm.R8B, x86asm.R8W, x86asm.R8L, x86asm.R8:
		return "_r8"
	case x86asm.R9B, x86asm.R9W, x86asm.R9L, x86asm.R9:
		return "_r9"
	case x86asm.R10B, x86asm.R10W, x86asm.R10L, x86asm.R10:
		return "_r10"
	case x86asm.R11B, x86asm.R11W, x86asm.R11L, x86asm.R11:
		return "_r11"
	case x86asm.R12B, x86asm.R12W, x86asm.R12L, x86asm.R12:
		return "_r12"
	case x86asm.R13B, x86asm.R13W, x86asm.R13L, x86asm.R13:
		return "_r13"
	case x86asm.R14B, x86asm.R14W, x86asm.R14L, x86asm.R14:
		return "_r14"
	case x86asm.R15B, x86asm.R15W, x86asm.R15L, x86asm.R15:
		return "_r15"
	case x86asm.X0, x86asm.X1, x86asm.X2, x86asm.X3:
		return fmt.Sprintf("_xmm%d", int(r-x86asm.X0))
	default:
		return fmt.Sprintf("_r%d", int(r))
	}
}

// x86BranchLabel resolves a branch target to a block label or a function name.
func x86BranchLabel(target uint64, addrToName map[uint64]string) string {
	if addrToName != nil {
		if name, ok := addrToName[target]; ok {
			return name
		}
	}
	return fmt.Sprintf("L_0x%x", target)
}

// x86CondOp maps a conditional jump opcode to a C comparison operator string.
func x86CondOp(op x86asm.Op) string {
	switch op {
	case x86asm.JE:
		return "=="
	case x86asm.JNE:
		return "!="
	case x86asm.JL, x86asm.JB:
		return "<"
	case x86asm.JLE, x86asm.JBE:
		return "<="
	case x86asm.JG, x86asm.JA:
		return ">"
	case x86asm.JGE, x86asm.JAE:
		return ">="
	case x86asm.JS:
		return "< 0 /* sign */"
	case x86asm.JNS:
		return ">= 0 /* sign */"
	case x86asm.JO:
		return "/* overflow */"
	case x86asm.JNO:
		return "/* no-overflow */"
	case x86asm.JP:
		return "/* parity */"
	case x86asm.JNP:
		return "/* no-parity */"
	case x86asm.JRCXZ, x86asm.JECXZ, x86asm.JCXZ:
		return "== 0 /* rcx */"
	case x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		return "!= 0 /* loop */"
	default:
		return "/* cond */"
	}
}

// buildCond combines pendingCmp operands with a comparison operator into a C condition string.
func buildCond(cmp [2]string, op string) string {
	if cmp[0] == "" || cmp[1] == "" {
		return "cond"
	}
	return fmt.Sprintf("%s %s %s", cmp[0], op, cmp[1])
}
