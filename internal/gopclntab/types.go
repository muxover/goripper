package gopclntab

// PclntabVersion encodes which wire format was detected.
type PclntabVersion uint8

const (
	VersionUnknown PclntabVersion = iota
	Version12                     // Go 1.2–1.15  magic 0xFFFFFAFF
	Version116                    // Go 1.16–1.17 magic 0xFFFFFBFF
	Version118                    // Go 1.18–1.19 magic 0xFFFFFCFF
	Version120                    // Go 1.20+     magic 0xFFFFFF00–0x05
)

func (v PclntabVersion) String() string {
	switch v {
	case Version12:
		return "go1.2-1.15"
	case Version116:
		return "go1.16-1.17"
	case Version118:
		return "go1.18-1.19"
	case Version120:
		return "go1.20+"
	default:
		return "unknown"
	}
}

// FuncEntry is one parsed row from the function table.
type FuncEntry struct {
	Name    string // null-terminated name from funcnametab
	EntryPC uint64 // resolved virtual address
	Size    uint64 // derived from next entry's EntryPC (0 for last entry)
	NameOff uint32 // raw offset into funcnametab (for debug)
}

// ParsedPclntab is the output of a successful parse.
type ParsedPclntab struct {
	Version   PclntabVersion
	GoVersion string     // inferred version range from magic
	PtrSize   uint8      // 4 or 8
	MinLC     uint8      // minimum instruction size (quantum)
	Funcs     []FuncEntry
	TextStart uint64 // base VA of text section (used in 1.18+ offset adjustment)
}
