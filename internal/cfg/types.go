package cfg

import "golang.org/x/arch/x86/x86asm"

// BasicBlock represents a maximal sequence of instructions with no branches
// except possibly at the end.
type BasicBlock struct {
	ID      int
	StartPC uint64
	EndPC   uint64
	Instrs  []DecodedInstr
	Succs   []int // block IDs of successors
	Preds   []int // block IDs of predecessors
}

// DecodedInstr pairs a decoded instruction with its virtual address.
type DecodedInstr struct {
	PC   uint64
	Inst x86asm.Inst
}

// CFG is the control flow graph for a single function.
type CFG struct {
	FuncName string
	FuncAddr uint64
	Blocks   []*BasicBlock
}
