package cfg

import (
	"strings"

	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
)

func Build(fn functions.Function, textData []byte, textVA uint64, d disasm.Disassembler) (*CFG, error) {
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
	instrs := decodeAll(funcData, fn.Addr, d)
	if len(instrs) == 0 {
		return &CFG{FuncName: fn.Name, FuncAddr: fn.Addr}, nil
	}

	if isStubName(fn.Name) || !hasValidPrologue(instrs) {
		return &CFG{FuncName: fn.Name, FuncAddr: fn.Addr}, nil
	}

	leaders := findLeaders(instrs, fn.Addr)
	blocks := buildBlocks(instrs, leaders)

	return &CFG{
		FuncName: fn.Name,
		FuncAddr: fn.Addr,
		Blocks:   blocks,
	}, nil
}

func decodeAll(data []byte, baseVA uint64, d disasm.Disassembler) []disasm.Instr {
	var instrs []disasm.Instr
	pos := 0
	for pos < len(data) {
		instr, err := d.Decode(data[pos:], baseVA+uint64(pos))
		if err != nil {
			pos++
			continue
		}
		instrs = append(instrs, instr)
		pos += instr.Len
	}
	return instrs
}

func findLeaders(instrs []disasm.Instr, funcStart uint64) map[uint64]bool {
	leaders := map[uint64]bool{funcStart: true}

	for _, instr := range instrs {
		if instr.Op == disasm.OpRet {
			continue
		}
		if instr.Op == disasm.OpCondBranch || instr.Op == disasm.OpUncondBranch {
			nextPC := instr.VA + uint64(instr.Len)
			leaders[nextPC] = true
			if instr.Target != 0 {
				leaders[instr.Target] = true
			}
		}
	}
	return leaders
}

func buildBlocks(instrs []disasm.Instr, leaders map[uint64]bool) []*BasicBlock {
	if len(instrs) == 0 {
		return nil
	}

	var blocks []*BasicBlock
	var current *BasicBlock
	blockID := 0

	for _, instr := range instrs {
		if leaders[instr.VA] || current == nil {
			if current != nil {
				current.EndPC = instr.VA
			}
			current = &BasicBlock{
				ID:      blockID,
				StartPC: instr.VA,
			}
			blocks = append(blocks, current)
			blockID++
		}
		current.Instrs = append(current.Instrs, instr)
	}

	if current != nil && len(current.Instrs) > 0 {
		last := current.Instrs[len(current.Instrs)-1]
		current.EndPC = last.VA + uint64(last.Len)
	}

	pcToBlock := make(map[uint64]int, len(blocks))
	for i, b := range blocks {
		pcToBlock[b.StartPC] = i
	}

	for i, b := range blocks {
		if len(b.Instrs) == 0 {
			continue
		}
		last := b.Instrs[len(b.Instrs)-1]

		if last.Op == disasm.OpRet {
			continue
		}

		nextPC := last.VA + uint64(last.Len)

		if last.Op == disasm.OpUncondBranch {
			if last.Target != 0 {
				if j, found := pcToBlock[last.Target]; found {
					b.Succs = append(b.Succs, j)
					blocks[j].Preds = append(blocks[j].Preds, i)
				}
			}
		} else if last.Op == disasm.OpCondBranch {
			if j, found := pcToBlock[nextPC]; found {
				b.Succs = append(b.Succs, j)
				blocks[j].Preds = append(blocks[j].Preds, i)
			}
			if last.Target != 0 {
				if j, found := pcToBlock[last.Target]; found {
					b.Succs = appendUniq(b.Succs, j)
					blocks[j].Preds = appendUniq(blocks[j].Preds, i)
				}
			}
		} else {
			if j, found := pcToBlock[nextPC]; found {
				b.Succs = append(b.Succs, j)
				blocks[j].Preds = append(blocks[j].Preds, i)
			}
		}
	}

	return blocks
}

func appendUniq(slice []int, v int) []int {
	for _, x := range slice {
		if x == v {
			return slice
		}
	}
	return append(slice, v)
}

func isStubName(name string) bool {
	for _, prefix := range []string{"go:buildid", "go:cgo_", "_cgo_", "type:.", "go:."} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func hasValidPrologue(instrs []disasm.Instr) bool {
	if len(instrs) == 0 {
		return false
	}
	// Any real function starts with a non-branch, non-ret instruction.
	first := instrs[0]
	return first.Op == disasm.OpOther || first.Op == disasm.OpAddrLoad
}
