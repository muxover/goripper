package functions

import (
	"strings"

	"github.com/muxover/goripper/internal/gopclntab"
)

// Extract converts raw pclntab FuncEntry records into Function structs.
// It filters out entries with empty names or zero addresses.
func Extract(entries []gopclntab.FuncEntry) []Function {
	seen := make(map[string]bool, len(entries))
	funcs := make([]Function, 0, len(entries))

	for _, e := range entries {
		if e.Name == "" || e.EntryPC == 0 {
			continue
		}
		// Deduplicate by name (some versions emit duplicates)
		if seen[e.Name] {
			continue
		}
		seen[e.Name] = true

		pkg := ExtractPackageName(e.Name)
		funcs = append(funcs, Function{
			Name:    e.Name,
			Addr:    e.EntryPC,
			Size:    e.Size,
			Package: pkg,
		})
	}

	return funcs
}

// ExtractPackageName derives the package path from a fully qualified Go function name.
//
// Examples:
//   "main.main"                          -> "main"
//   "main.(*Server).HandleRequest"       -> "main"
//   "github.com/foo/bar.NewClient"       -> "github.com/foo/bar"
//   "runtime.newobject"                  -> "runtime"
//   "main.main.func1"                    -> "main"
//   "main.main.func1:1"                  -> "main"  (Go 1.20 closure format)
func ExtractPackageName(funcName string) string {
	// Strip method receiver: "pkg.(*Type).Method" -> "pkg.(*Type).Method"
	// We want everything before the first dot that is preceded by a valid pkg path char.

	// Handle Go 1.20 colon in closure names: strip ":N" suffix first
	if idx := strings.LastIndex(funcName, ":"); idx > 0 {
		// Only strip if there's no slash after the colon (not a URL-like path)
		if !strings.Contains(funcName[idx:], "/") {
			funcName = funcName[:idx]
		}
	}

	// Find the package path: everything up to (but not including) the last
	// dot-separated component that follows the package separator.
	//
	// Strategy: find the last '.' that is not inside parentheses and where
	// everything before it looks like a valid package path (may contain '/').

	// Remove receiver: "foo.(*Bar).Baz" -> find package "foo"
	// Simple approach: split on '.' and work backwards
	parts := strings.Split(funcName, ".")
	if len(parts) == 1 {
		return funcName
	}

	// Build package path: keep parts while they look like a package (contain '/' or are lowercase or are import path components)
	// The function name is the last part(s).
	// For "github.com/foo/bar.Func", parts = ["github", "com/foo/bar", "Func"]
	// Wait, that split won't work for paths with /

	// Better approach: find the last dot that separates package from function name.
	// The package name cannot contain '(' (method receivers start with '(').
	// Find rightmost '.' where everything before it has no unmatched '('

	// Simplest robust approach: find the dot separator between package path and function name.
	// Package paths contain only: lowercase letters, digits, '_', '/', '.'
	// Function names start with uppercase or lowercase letters.

	// Find the last '.' that is preceded by a path-like string and followed by
	// an identifier (not '(' or '*')
	dotIdx := -1
	for i := len(funcName) - 1; i >= 0; i-- {
		if funcName[i] == '.' {
			// Check if this could be the package/func separator
			// The part before the dot should not contain '(' or '-'
			before := funcName[:i]
			if !strings.ContainsAny(before, "(-") {
				dotIdx = i
				break
			}
		}
	}

	if dotIdx < 0 {
		return funcName
	}

	pkg := funcName[:dotIdx]

	// Strip closure suffixes like ".func1", ".func1.1" from package name
	// These appear in nested functions: "main.outer.func1" -> package is "main"
	// But "github.com/foo/bar.Func" -> package is "github.com/foo/bar"
	// Heuristic: if pkg contains a dot and the part after the last dot is "funcN"
	// or a pure number, strip it
	for {
		lastDot := strings.LastIndex(pkg, ".")
		if lastDot < 0 {
			break
		}
		suffix := pkg[lastDot+1:]
		if isClosureSuffix(suffix) {
			pkg = pkg[:lastDot]
		} else {
			break
		}
	}

	return pkg
}

func isClosureSuffix(s string) bool {
	if s == "" {
		return false
	}
	// Matches "func1", "func2", "1", "2", etc.
	if strings.HasPrefix(s, "func") {
		rest := s[4:]
		return isDigits(rest)
	}
	return isDigits(s)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
