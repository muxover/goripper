package disasm

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
)

type arm64Disasm struct{}

func (d *arm64Disasm) Arch() string { return "arm64" }

func (d *arm64Disasm) Decode(data []byte, va uint64) (Instr, error) {
	if len(data) < 4 {
		return Instr{}, fmt.Errorf("arm64: need at least 4 bytes")
	}
	inst, err := arm64asm.Decode(data[:4])
	if err != nil {
		return Instr{}, err
	}
	i := Instr{VA: va, Len: 4}

	switch inst.Op {
	case arm64asm.BL:
		i.Op = OpCall
		for _, arg := range inst.Args {
			if arg == nil {
				break
			}
			if pcrel, ok := arg.(arm64asm.PCRel); ok {
				i.Target = uint64(int64(va) + int64(pcrel))
			}
		}
	case arm64asm.BLR:
		i.Op = OpCall
		i.Indirect = true
	case arm64asm.RET:
		i.Op = OpRet
	case arm64asm.B:
		// B with a Cond arg → B.cond (conditional); without → unconditional.
		hasCond := false
		for _, arg := range inst.Args {
			if arg == nil {
				break
			}
			if _, ok := arg.(arm64asm.Cond); ok {
				hasCond = true
			}
			if pcrel, ok := arg.(arm64asm.PCRel); ok {
				i.Target = uint64(int64(va) + int64(pcrel))
			}
		}
		if hasCond {
			i.Op = OpCondBranch
		} else {
			i.Op = OpUncondBranch
		}
	case arm64asm.BR:
		i.Op = OpUncondBranch
		i.Indirect = true
	case arm64asm.CBZ, arm64asm.CBNZ, arm64asm.TBZ, arm64asm.TBNZ:
		i.Op = OpCondBranch
		for _, arg := range inst.Args {
			if arg == nil {
				break
			}
			if pcrel, ok := arg.(arm64asm.PCRel); ok {
				i.Target = uint64(int64(va) + int64(pcrel))
			}
		}
	case arm64asm.ADRP:
		// ADRP: args[0]=Reg (dst), args[1]=PCRel (page-aligned offset from current page).
		// If the next instruction is ADD targeting the same register, compute the full address.
		var dstReg arm64asm.Reg
		var pageAddr uint64
		if reg, ok := inst.Args[0].(arm64asm.Reg); ok {
			dstReg = reg
		}
		if pcrel, ok := inst.Args[1].(arm64asm.PCRel); ok {
			// Target page = (va & ~0xFFF) + pcrel (pcrel is already page-aligned offset).
			pageAddr = (va &^ 0xFFF) + uint64(int64(pcrel))
		}
		if pageAddr != 0 {
			i.Op = OpAddrLoad
			if len(data) >= 8 {
				if addOff, ok := adrpAddImm(data[4:], dstReg); ok {
					i.AddrRef = pageAddr + addOff
				} else {
					i.AddrRef = pageAddr
				}
			} else {
				i.AddrRef = pageAddr
			}
		}
	case arm64asm.ADR:
		i.Op = OpAddrLoad
		for _, arg := range inst.Args {
			if arg == nil {
				break
			}
			if pcrel, ok := arg.(arm64asm.PCRel); ok {
				i.AddrRef = uint64(int64(va) + int64(pcrel))
				break
			}
		}
	}
	return i, nil
}

// adrpAddImm decodes the next instruction as ADD <same_reg>, <same_reg>, #imm
// and returns the immediate. Returns (0, false) if the pattern doesn't match.
func adrpAddImm(nextData []byte, adrpDst arm64asm.Reg) (uint64, bool) {
	if len(nextData) < 4 {
		return 0, false
	}
	next, err := arm64asm.Decode(nextData[:4])
	if err != nil || next.Op != arm64asm.ADD {
		return 0, false
	}
	// ADD args: [0]=Rd (RegSP), [1]=Rn (RegSP), [2]=ImmShift
	rd, ok := next.Args[0].(arm64asm.RegSP)
	if !ok || arm64asm.Reg(rd) != adrpDst {
		return 0, false
	}
	rn, ok := next.Args[1].(arm64asm.RegSP)
	if !ok || arm64asm.Reg(rn) != adrpDst {
		return 0, false
	}
	is, ok := next.Args[2].(arm64asm.ImmShift)
	if !ok {
		return 0, false
	}
	return parseImmShiftStr(is.String()), true
}

// parseImmShiftStr parses arm64asm.ImmShift.String() e.g. "#0x8" or "#0x8, LSL#12".
func parseImmShiftStr(s string) uint64 {
	s = strings.TrimPrefix(s, "#")
	parts := strings.SplitN(s, ",", 2)
	imm := parseHexDec(strings.TrimSpace(parts[0]))
	if len(parts) == 2 {
		sh := strings.TrimSpace(parts[1])
		sh = strings.TrimPrefix(sh, "LSL#")
		shift, _ := strconv.ParseUint(sh, 10, 8)
		imm <<= shift
	}
	return imm
}

func parseHexDec(s string) uint64 {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, _ := strconv.ParseUint(s[2:], 16, 64)
		return v
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}
