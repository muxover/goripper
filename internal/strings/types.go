package strings

// StringType classifies what kind of string was extracted.
type StringType string

const (
	StringTypeURL     StringType = "url"
	StringTypeIP      StringType = "ip"
	StringTypePath    StringType = "path"
	StringTypeSecret  StringType = "secret"
	StringTypePkgPath StringType = "pkgpath"
	StringTypePlain   StringType = "plain"
)

// ExtractedString is a string found in the binary with metadata.
type ExtractedString struct {
	Value          string
	Type           StringType
	Offset         uint64   // VA of string start
	ReferencedBy   []string // function names that reference this string
	IsFallbackBlob bool     // true when length was not inferred (512-byte printable run)
}
