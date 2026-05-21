package output

type SectionInfo struct {
	Name    string  `json:"name"`
	Entropy float64 `json:"entropy"`
	Size    uint64  `json:"size"`
	Verdict string  `json:"verdict"` // "normal", "compressed", "encrypted", "packed"
}

type AssetOutput struct {
	Path     string `json:"path"`
	SizeHint int    `json:"size_hint"`
}

type ConstantOutput struct {
	Value      int64  `json:"value"`
	Category   string `json:"category"`   // "port", "crypto_key_size", "magic"
	Confidence string `json:"confidence"` // "high", "medium"
}

type BinaryInfo struct {
	Path                  string        `json:"path"`
	Format                string        `json:"format"`
	Arch                  string        `json:"arch"`
	GoVersion             string        `json:"go_version"`
	PclntabVersion        string        `json:"pclntab_version,omitempty"` // e.g. "go1.20+"
	PclntabMagic          string        `json:"pclntab_magic,omitempty"`   // e.g. "0xFFFFFFF1"
	SizeBytes             int64         `json:"size_bytes"`
	Packer                string        `json:"packer,omitempty"`
	Sections              []SectionInfo `json:"sections,omitempty"`
	ObfuscationScore      float64       `json:"obfuscation_score"`
	ObfuscationLevel      string        `json:"obfuscation_level"`
	ObfuscationIndicators []string      `json:"obfuscation_indicators,omitempty"`
}

type FunctionOutput struct {
	Name           string           `json:"name"`
	Addr           string           `json:"addr"` // hex e.g. "0x401000"
	Package        string           `json:"package"`
	PackageKind    string           `json:"package_kind"`    // "runtime","stdlib","user","cgo"
	FunctionSource string           `json:"function_source"` // "pclntab","symbol_table","synthetic"
	Size           uint64           `json:"size"`
	Calls          []string         `json:"calls"`
	CalledBy       []string         `json:"called_by"`
	Strings        []string         `json:"strings,omitempty"`
	Tags           []string         `json:"tags,omitempty"`
	Constants      []ConstantOutput `json:"constants,omitempty"`
	IsRuntime      bool             `json:"is_runtime"`
	IsConcurrent   bool             `json:"is_concurrent"`
	Pseudocode     string           `json:"pseudocode,omitempty"`
	SimilarityHash string           `json:"similarity_hash,omitempty"`
}

type StringOutput struct {
	Value        string   `json:"value"`
	Type         string   `json:"type"`
	ReferencedBy []string `json:"referenced_by,omitempty"`
}

type TypeOutput struct {
	Name   string        `json:"name"`
	Kind   string        `json:"kind"`
	Size   uint32        `json:"size,omitempty"`
	Fields []FieldOutput `json:"fields,omitempty"`
}

type FieldOutput struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset uint32 `json:"offset"`
}

type InterfaceImplOutput struct {
	Interface string `json:"interface"`
	Concrete  string `json:"concrete"`
	ItabAddr  string `json:"itab_addr"` // hex VA
}

type DecryptorStubOutput struct {
	Name        string `json:"name"`
	Addr        string `json:"addr"`
	CallerCount int    `json:"caller_count"`
	XORKey      string `json:"xor_key,omitempty"` // hex e.g. "0x3f"; empty if not detected
}

type TaintFlowOutput struct {
	Source     string   `json:"source"`
	SourceFunc string   `json:"source_func"`
	Sink       string   `json:"sink"`
	SinkFunc   string   `json:"sink_func"`
	Path       []string `json:"path"`
	Confidence string   `json:"confidence"`
}

type ModuleGraphOutput struct {
	MainModule   string                   `json:"main_module"`
	GoVersion    string                   `json:"go_version"`
	Dependencies []ModuleDependencyOutput `json:"dependencies"`
}

type ModuleDependencyOutput struct {
	Path          string   `json:"path"`
	Version       string   `json:"version"`
	UsedFunctions int      `json:"used_functions"`
	CVEs          []string `json:"cves,omitempty"`
}

type SummaryOutput struct {
	TotalFunctions      int      `json:"total_functions"`
	UserFunctions       int      `json:"user_functions"`
	StdlibFunctions     int      `json:"stdlib_functions"`
	RuntimeFunctions    int      `json:"runtime_functions"`
	CGOFunctions        int      `json:"cgo_functions"`
	SyntheticFunctions  int      `json:"synthetic_functions"`
	SuspiciousFunctions int      `json:"suspicious_functions"`
	TotalStrings        int      `json:"total_strings"`
	URLStrings          int      `json:"url_strings"`
	IPStrings           int      `json:"ip_strings"`
	PathStrings         int      `json:"path_strings"`
	SecretStrings       int      `json:"secret_strings"`
	PkgPathStrings      int      `json:"pkg_path_strings"`
	PlainStrings        int      `json:"plain_strings"`
	RecoveredTypes      int      `json:"recovered_types"`
	InterfaceImpls      int      `json:"interface_impls"`
	EmbeddedAssets      int      `json:"embedded_assets"`
	ConcurrentFunctions int      `json:"concurrent_functions"`
	CgoCallSites        []string `json:"cgo_call_sites,omitempty"`
	DecryptorStubs      int      `json:"decryptor_stubs"`
	TaintFlows          int      `json:"taint_flows"`
	ModuleDeps          int      `json:"module_deps,omitempty"`
	ThreatClass         string   `json:"threat_class,omitempty"`
	ThreatConfidence    string   `json:"threat_confidence,omitempty"`
	ThreatIndicators    []string `json:"threat_indicators,omitempty"`
}

type AnalysisResult struct {
	BinaryInfo     BinaryInfo            `json:"binary_info"`
	Functions      []FunctionOutput      `json:"functions"`
	Strings        []StringOutput        `json:"strings"`
	CallGraph      map[string][]string   `json:"call_graph"`
	Types          []TypeOutput          `json:"types"`
	Interfaces     []InterfaceImplOutput `json:"interfaces,omitempty"`
	EmbeddedAssets []AssetOutput         `json:"embedded_assets,omitempty"`
	DecryptorStubs []DecryptorStubOutput `json:"decryptor_stubs,omitempty"`
	TaintFlows     []TaintFlowOutput     `json:"taint_flows,omitempty"`
	ModuleGraph    *ModuleGraphOutput    `json:"module_graph,omitempty"`
	Summary        SummaryOutput         `json:"summary"`
	Warnings       []string              `json:"warnings,omitempty"`
}
