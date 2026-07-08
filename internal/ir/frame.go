package ir

import "regexp"

// A stack slot is a dereference of the stack or frame pointer with a constant
// displacement and no index register: (*(_rsp + 0x28)), (*(_rbp - 0x10)), (*(_rsp)).
// An index register means an array access, which is deliberately not matched.
var stackSlotRe = regexp.MustCompile(`\(\*\((_rsp|_rbp)(?: ([+-]) (0x[0-9a-fA-F]+))?\)\)`)

// ReconstructFrame promotes stack-slot memory references to named locals. A direct
// load or store of a slot becomes a plain assignment (`_rax = s_28`, `s_28 = _rbx`);
// slot reads embedded in larger expressions are substituted in place. Address-taken
// slots (LEA, which have no deref wrapper) are left alone. It runs before SSA so the
// slot names stay stable across the function.
func ReconstructFrame(f *IRFunc) {
	for _, blk := range f.Blocks {
		for i := range blk.Instrs {
			ins := &blk.Instrs[i]
			switch {
			case ins.Op == OpLoad && len(ins.Src) == 1:
				if name, ok := fullStackSlot(ins.Src[0]); ok {
					ins.Op = OpAssign
					ins.Src[0] = name
				}
			case ins.Op == OpStore:
				if name, ok := fullStackSlot(ins.Dst); ok {
					ins.Op = OpAssign
					ins.Dst = name
				}
			}
			ins.Dst = replaceStackSlots(ins.Dst)
			for j := range ins.Src {
				ins.Src[j] = replaceStackSlots(ins.Src[j])
			}
			ins.Meta = replaceStackSlots(ins.Meta)
		}
	}
}

// fullStackSlot returns the slot name if expr is exactly one stack-slot dereference.
func fullStackSlot(expr string) (string, bool) {
	loc := stackSlotRe.FindStringSubmatchIndex(expr)
	if loc == nil || loc[0] != 0 || loc[1] != len(expr) {
		return "", false
	}
	m := stackSlotRe.FindStringSubmatch(expr)
	return slotName(m[1], m[2], m[3]), true
}

func replaceStackSlots(expr string) string {
	if expr == "" {
		return expr
	}
	return stackSlotRe.ReplaceAllStringFunc(expr, func(match string) string {
		m := stackSlotRe.FindStringSubmatch(match)
		return slotName(m[1], m[2], m[3])
	})
}

// slotName maps a (base, sign, offset) slot to a stable local: s_ for rsp, b_ for
// rbp, with an n prefix on the offset for negative displacements.
func slotName(base, sign, off string) string {
	prefix := "s"
	if base == "_rbp" {
		prefix = "b"
	}
	if off == "" {
		return prefix + "_0"
	}
	hex := off[2:]
	if sign == "-" {
		return prefix + "_n" + hex
	}
	return prefix + "_" + hex
}
