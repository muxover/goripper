package functions

// PackageKind classifies the origin of a function's package.
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

// FunctionSource describes where a function's name was obtained.
type FunctionSource string

const (
	SourcePclntab     FunctionSource = "pclntab"       // normal: name from gopclntab
	SourceSymbolTable FunctionSource = "symbol_table"  // name from ELF/PE symbol table fallback
	SourceSynthetic   FunctionSource = "synthetic"     // generated name: sub_0x<addr>
)

// Function represents a parsed and classified function from a Go binary.
type Function struct {
	Name         string
	Addr         uint64
	Size         uint64
	Package      string
	PackageKind  PackageKind
	Source       FunctionSource // where the name came from
	IsRuntime    bool
	IsConcurrent bool
	Calls        []string // callee names (populated by callgraph)
	CalledBy     []string // caller names (populated by callgraph)
	Strings      []string // referenced strings (populated by string extractor)
	Tags         []string // behavior tags (populated by tagger)
	Pseudocode   string   // simplified pseudocode (populated by CFG)
}
