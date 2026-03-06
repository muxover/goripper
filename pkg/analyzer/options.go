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
}
