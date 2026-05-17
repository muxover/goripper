package functions

type PackageKind uint8

const (
	PackageRuntime PackageKind = iota // runtime, reflect, sync, syscall internals
	PackageStdlib                     // standard library (non-runtime)
	PackageUser                       // user or third-party code
	PackageCGo                        // CGo bridge functions
)

func (k PackageKind) String() string {
	switch k {
	case PackageRuntime:
		return "runtime"
	case PackageStdlib:
		return "stdlib"
	case PackageUser:
		return "user"
	case PackageCGo:
		return "cgo"
	default:
		return "unknown"
	}
}

type FunctionSource string

const (
	SourcePclntab     FunctionSource = "pclntab"      // normal: name from gopclntab
	SourceSymbolTable FunctionSource = "symbol_table" // name from ELF/PE symbol table fallback
	SourceSynthetic   FunctionSource = "synthetic"    // generated name: sub_0x<addr>
)

type ConstantInfo struct {
	Value      int64  `json:"value"`
	Category   string `json:"category"`   // "port", "crypto_key_size", "magic"
	Confidence string `json:"confidence"` // "high", "medium"
}

type Function struct {
	Name         string
	Addr         uint64
	Size         uint64
	Package      string
	PackageKind  PackageKind
	Source       FunctionSource // where the name came from
	IsRuntime    bool
	IsConcurrent bool
	Calls        []string       // callee names (populated by callgraph)
	CalledBy     []string       // caller names (populated by callgraph)
	Strings      []string       // referenced strings (populated by string extractor)
	Tags         []string       // behavior tags (populated by tagger)
	Constants    []ConstantInfo // interesting immediates (populated by constants extractor)
	Pseudocode   string         // simplified pseudocode (populated by CFG)
}
