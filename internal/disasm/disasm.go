package disasm

// Op classifies an instruction for high-level analysis.
type Op uint8

const (
	OpOther       Op = iota
	OpCall           // direct or indirect function call
	OpRet            // function return
	OpCondBranch     // conditional branch
	OpUncondBranch   // unconditional branch (not a call)
	OpAddrLoad       // PC-relative address materialization (LEA/ADRP+ADD)
)

// Instr is an architecture-neutral decoded instruction.
type Instr struct {
	VA       uint64
	Len      int
	Op       Op
	Target   uint64 // call/branch target VA; 0 if indirect or unresolved
	AddrRef  uint64 // data VA for OpAddrLoad; 0 if none
	Indirect bool   // OpCall with register target
}

// Disassembler decodes machine code into arch-neutral Instrs.
type Disassembler interface {
	Arch() string
	// Decode decodes one instruction from data (starting at virtual address va).
	// data may be longer than the instruction — Decode reads exactly Instr.Len bytes.
	Decode(data []byte, va uint64) (Instr, error)
}

// New returns a Disassembler for the given architecture string ("x86_64", "arm64").
// Unrecognized architectures default to x86_64.
func New(arch string) Disassembler {
	switch arch {
	case "arm64", "aarch64":
		return &arm64Disasm{}
	default:
		return &x86Disasm{}
	}
}
