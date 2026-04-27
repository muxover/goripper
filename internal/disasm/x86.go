package disasm

import "golang.org/x/arch/x86/x86asm"

type x86Disasm struct{}

func (d *x86Disasm) Arch() string { return "x86_64" }

func (d *x86Disasm) Decode(data []byte, va uint64) (Instr, error) {
	inst, err := x86asm.Decode(data, 64)
	if err != nil {
		return Instr{}, err
	}
	i := Instr{VA: va, Len: inst.Len}

	switch inst.Op {
	case x86asm.CALL:
		i.Op = OpCall
		if len(inst.Args) > 0 && inst.Args[0] != nil {
			if rel, ok := inst.Args[0].(x86asm.Rel); ok {
				i.Target = va + uint64(inst.Len) + uint64(rel)
			} else {
				i.Indirect = true
			}
		}
	case x86asm.RET, x86asm.LRET:
		i.Op = OpRet
	case x86asm.JMP:
		i.Op = OpUncondBranch
		if len(inst.Args) > 0 && inst.Args[0] != nil {
			if rel, ok := inst.Args[0].(x86asm.Rel); ok {
				i.Target = va + uint64(inst.Len) + uint64(rel)
			}
		}
	default:
		if isX86CondBranch(inst.Op) {
			i.Op = OpCondBranch
			if len(inst.Args) > 0 && inst.Args[0] != nil {
				if rel, ok := inst.Args[0].(x86asm.Rel); ok {
					i.Target = va + uint64(inst.Len) + uint64(rel)
				}
			}
		} else if inst.Op == x86asm.LEA || inst.Op == x86asm.MOV {
			for _, arg := range inst.Args {
				if arg == nil {
					continue
				}
				if mem, ok := arg.(x86asm.Mem); ok && mem.Base == x86asm.RIP {
					i.Op = OpAddrLoad
					i.AddrRef = uint64(int64(va) + int64(inst.Len) + mem.Disp)
					break
				}
			}
		}
	}
	return i, nil
}

func isX86CondBranch(op x86asm.Op) bool {
	switch op {
	case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE,
		x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO,
		x86asm.JP, x86asm.JS, x86asm.JCXZ, x86asm.JECXZ, x86asm.JRCXZ,
		x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		return true
	}
	return false
}
