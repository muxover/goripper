package ir

type OpKind uint8

const (
	OpAssign  OpKind = iota // dst = src[0]
	OpLoad                  // dst = *src[0]           (memory read; src[0] is address expression)
	OpStore                 // *dst = src[0]           (memory write; dst is address expression)
	OpArith                 // dst = src[0] Meta src[1] (Meta: "add","sub","mul","div","and","or","xor","shl","shr")
	OpUnary                 // dst = Meta src[0]        (Meta: "neg","not")
	OpCall                  // dst = Target(src...)     (dst empty for void; Target is resolved name or hex)
	OpPhi                   // dst = phi(src...)
	OpIf                    // if src[0] Meta src[1] goto Label else Label2
	OpGoto                  // goto Label
	OpReturn                // return src...
	OpLabel                 // Label: (synthetic; blocks always start with one)
	OpComment               // // Meta
)

type IRInstr struct {
	Op     OpKind
	Dst    string   // destination variable name (or address expression for OpStore)
	Src    []string // source operand names / expressions
	Target string   // resolved callee name (OpCall)
	Label  string   // label for OpLabel / OpGoto / true-branch target for OpIf
	Label2 string   // false-branch label for OpIf
	Meta   string   // binary operator (OpArith), unary op (OpUnary), cmp op (OpIf), or comment text
	Addr   uint64   // originating instruction VA (debug only)
}

type IRBlock struct {
	ID     int
	Label  string // "L<id>"
	Instrs []IRInstr
	Succs  []int // successor block IDs
	Preds  []int // predecessor block IDs
}

type IRFunc struct {
	Name    string
	Package string
	Addr    uint64
	Blocks  []*IRBlock
	Params  []string          // parameter variable names in calling-convention order
	RetVars []string          // return variable names
	Vars    map[string]string // var name → C type ("" = unknown/int64_t)
}
