package output

// BinaryInfo holds metadata about the analyzed binary.
type BinaryInfo struct {
	Path      string `json:"path"`
	Format    string `json:"format"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	SizeBytes int64  `json:"size_bytes"`
}

// FunctionOutput is the JSON representation of an analyzed function.
type FunctionOutput struct {
	Name         string   `json:"name"`
	Addr         string   `json:"addr"` // hex string e.g. "0x401000"
	Package      string   `json:"package"`
	PackageKind  string   `json:"package_kind"` // "runtime", "stdlib", "user", "cgo"
	Size         uint64   `json:"size"`
	Calls        []string `json:"calls"`
	CalledBy     []string `json:"called_by"`
	Strings      []string `json:"strings,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	IsRuntime    bool     `json:"is_runtime"`
	IsConcurrent bool     `json:"is_concurrent"`
	Pseudocode   string   `json:"pseudocode,omitempty"`
}

// StringOutput is the JSON representation of an extracted string.
type StringOutput struct {
	Value        string   `json:"value"`
	Type         string   `json:"type"`
	ReferencedBy []string `json:"referenced_by,omitempty"`
}

// TypeOutput is the JSON representation of a recovered Go type.
type TypeOutput struct {
	Name   string        `json:"name"`
	Kind   string        `json:"kind"`
	Size   uint32        `json:"size,omitempty"`
	Fields []FieldOutput `json:"fields,omitempty"`
}

// FieldOutput describes a struct field.
type FieldOutput struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset uint32 `json:"offset"`
}

// SummaryOutput contains aggregate statistics.
type SummaryOutput struct {
	TotalFunctions      int `json:"total_functions"`
	UserFunctions       int `json:"user_functions"`
	StdlibFunctions     int `json:"stdlib_functions"`
	RuntimeFunctions    int `json:"runtime_functions"`
	SuspiciousFunctions int `json:"suspicious_functions"`
	TotalStrings        int `json:"total_strings"`
	URLStrings          int `json:"url_strings"`
	RecoveredTypes      int `json:"recovered_types"`
	ConcurrentFunctions int `json:"concurrent_functions"`
}

// AnalysisResult is the top-level output structure.
type AnalysisResult struct {
	BinaryInfo BinaryInfo          `json:"binary_info"`
	Functions  []FunctionOutput    `json:"functions"`
	Strings    []StringOutput      `json:"strings"`
	CallGraph  map[string][]string `json:"call_graph"`
	Types      []TypeOutput        `json:"types"`
	Summary    SummaryOutput       `json:"summary"`
}
