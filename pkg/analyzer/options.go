package analyzer

// Options controls the analysis pipeline behavior.
type Options struct {
	BinaryPath    string
	NoRuntime     bool
	OnlyUser      bool
	OutputDir     string
	Verbose       bool
	JSONOutput    bool
	StringFilter  string // "url", "ip", "path", "secret", or "" for all
	CallDepth     int    // max depth for callgraph traversal (0 = unlimited)
	PackageFilter string // filter output to this package name
	CFGEnabled    bool   // enable CFG + pseudocode generation (slow)
	TypesEnabled  bool   // enable type recovery
	MinStringLen  int    // minimum string length filter (0 = use default of 6)
	NoPlain       bool   // suppress plain-text strings from output
	MinRefs       int    // minimum user-code reference count (0 = no filter)
	ShowRefs      bool   // show top-3 referencing functions in text output
}
