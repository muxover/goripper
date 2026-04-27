package cfg

import "github.com/muxover/goripper/internal/disasm"

type BasicBlock struct {
	ID      int
	StartPC uint64
	EndPC   uint64
	Instrs  []disasm.Instr
	Succs   []int
	Preds   []int
}

type CFG struct {
	FuncName string
	FuncAddr uint64
	Blocks   []*BasicBlock
}
