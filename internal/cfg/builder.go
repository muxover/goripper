package cfg

import (
	"github.com/muxover/goripper/internal/functions"
	"golang.org/x/arch/x86/x86asm"
)

// Build constructs a CFG for a function by splitting its instruction stream
// at branch targets and terminator instructions.
func Build(fn functions.Function, textData []byte, textVA uint64) (*CFG, error) {
	if fn.Addr < textVA || fn.Size == 0 {
		return &CFG{FuncName: fn.Name, FuncAddr: fn.Addr}, nil
	}

	offset := fn.Addr - textVA
	if offset >= uint64(len(textData)) {
		return &CFG{FuncName: fn.Name, FuncAddr: fn.Addr}, nil
	}

	size := fn.Size
	if offset+size > uint64(len(textData)) {
		size = uint64(len(textData)) - offset
	}

	funcData := textData[offset : offset+size]

	// Step 1: Decode all instructions
	instrs := decodeAll(funcData, fn.Addr)
	if len(instrs) == 0 {
		return &CFG{FuncName: fn.Name, FuncAddr: fn.Addr}, nil
	}

	// Step 2: Find basic block leaders
	leaders := findLeaders(instrs, fn.Addr)

	// Step 3: Build basic blocks
	blocks := buildBlocks(instrs, leaders)

	return &CFG{
		FuncName: fn.Name,
		FuncAddr: fn.Addr,
		Blocks:   blocks,
	}, nil
}

func decodeAll(data []byte, baseVA uint64) []DecodedInstr {
	var instrs []DecodedInstr
	pos := 0
	for pos < len(data) {
		inst, err := x86asm.Decode(data[pos:], 64)
		if err != nil {
			pos++
			continue
		}
		instrs = append(instrs, DecodedInstr{
			PC:   baseVA + uint64(pos),
			Inst: inst,
		})
		pos += inst.Len
	}
	return instrs
}

func findLeaders(instrs []DecodedInstr, funcStart uint64) map[uint64]bool {
	leaders := map[uint64]bool{funcStart: true}

	for _, di := range instrs {
		inst := di.inst()
		nextPC := di.PC + uint64(inst.Len)

		if isTerminator(inst) || isConditionalBranch(inst) || isUnconditionalBranch(inst) {
			// The instruction after a branch is a leader
			leaders[nextPC] = true
			// The branch target is a leader
			if target, ok := branchTarget(di); ok {
				leaders[target] = true
			}
		}
	}

	return leaders
}

func buildBlocks(instrs []DecodedInstr, leaders map[uint64]bool) []*BasicBlock {
	if len(instrs) == 0 {
		return nil
	}

	var blocks []*BasicBlock
	var current *BasicBlock
	blockID := 0

	for _, di := range instrs {
		if leaders[di.PC] || current == nil {
			if current != nil {
				current.EndPC = di.PC
			}
			current = &BasicBlock{
				ID:      blockID,
				StartPC: di.PC,
			}
			blocks = append(blocks, current)
			blockID++
		}
		current.Instrs = append(current.Instrs, di)
	}

	if current != nil && len(current.Instrs) > 0 {
		last := current.Instrs[len(current.Instrs)-1]
		current.EndPC = last.PC + uint64(last.Inst.Len)
	}

	// Build successor/predecessor relationships
	pcToBlock := make(map[uint64]int, len(blocks))
	for i, b := range blocks {
		pcToBlock[b.StartPC] = i
	}

	for i, b := range blocks {
		if len(b.Instrs) == 0 {
			continue
		}
		last := b.Instrs[len(b.Instrs)-1]
		inst := last.Inst

		if isTerminator(inst) {
			continue // RET/RETF: no successors
		}

		nextPC := last.PC + uint64(inst.Len)

		if isUnconditionalBranch(inst) {
			if target, ok := branchTarget(DecodedInstr{PC: last.PC, Inst: inst}); ok {
				if j, found := pcToBlock[target]; found {
					b.Succs = append(b.Succs, j)
					blocks[j].Preds = append(blocks[j].Preds, i)
				}
			}
		} else if isConditionalBranch(inst) {
			// Fall-through
			if j, found := pcToBlock[nextPC]; found {
				b.Succs = append(b.Succs, j)
				blocks[j].Preds = append(blocks[j].Preds, i)
			}
			// Branch target
			if target, ok := branchTarget(DecodedInstr{PC: last.PC, Inst: inst}); ok {
				if j, found := pcToBlock[target]; found {
					b.Succs = appendUniq(b.Succs, j)
					blocks[j].Preds = appendUniq(blocks[j].Preds, i)
				}
			}
		} else {
			// Sequential flow
			if j, found := pcToBlock[nextPC]; found {
				b.Succs = append(b.Succs, j)
				blocks[j].Preds = append(blocks[j].Preds, i)
			}
		}
	}

	return blocks
}

func (di DecodedInstr) inst() x86asm.Inst { return di.Inst }

func isTerminator(inst x86asm.Inst) bool {
	switch inst.Op {
	case x86asm.RET, x86asm.LRET, x86asm.UD2, x86asm.HLT,
		x86asm.INT, x86asm.INTO:
		return true
	}
	return false
}

func isConditionalBranch(inst x86asm.Inst) bool {
	switch inst.Op {
	case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE,
		x86asm.JE, x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE,
		x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO,
		x86asm.JP, x86asm.JS, x86asm.JCXZ, x86asm.JECXZ, x86asm.JRCXZ,
		x86asm.LOOP, x86asm.LOOPE, x86asm.LOOPNE:
		return true
	}
	return false
}

func isUnconditionalBranch(inst x86asm.Inst) bool {
	return inst.Op == x86asm.JMP
}

func branchTarget(di DecodedInstr) (uint64, bool) {
	if len(di.Inst.Args) == 0 || di.Inst.Args[0] == nil {
		return 0, false
	}
	if rel, ok := di.Inst.Args[0].(x86asm.Rel); ok {
		target := di.PC + uint64(di.Inst.Len) + uint64(rel)
		return target, true
	}
	return 0, false
}

func appendUniq(slice []int, v int) []int {
	for _, x := range slice {
		if x == v {
			return slice
		}
	}
	return append(slice, v)
}
