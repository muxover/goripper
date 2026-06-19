package functions

import (
	"fmt"
	"strings"

	"github.com/muxover/goripper/internal/gopclntab"
)

func Extract(entries []gopclntab.FuncEntry) []Function {
	seen := make(map[string]bool, len(entries))
	funcs := make([]Function, 0, len(entries))

	for _, e := range entries {
		if e.Name == "" || e.EntryPC == 0 {
			continue
		}
		// Deduplicate by name (some versions emit duplicates)
		if seen[e.Name] {
			continue // pclntab emits duplicates in some versions
		}
		seen[e.Name] = true

		pkg := ExtractPackageName(e.Name)
		funcs = append(funcs, Function{
			Name:    e.Name,
			Addr:    e.EntryPC,
			Size:    e.Size,
			Package: pkg,
			Source:  SourcePclntab,
		})
	}

	return funcs
}

func SyntheticFromAddrs(addrs [][2]uint64) []Function {
	funcs := make([]Function, 0, len(addrs))
	for _, pair := range addrs {
		addr, size := pair[0], pair[1]
		if addr == 0 {
			continue
		}
		name := fmt.Sprintf("sub_0x%x", addr)
		funcs = append(funcs, Function{
			Name:    name,
			Addr:    addr,
			Size:    size,
			Package: "",
			Source:  SourceSynthetic,
		})
	}
	return funcs
}

func ExtractPackageName(funcName string) string {
	// Go 1.20+ closure format: strip ":N" suffix, but only when no slash follows (not a URL-style path).
	if idx := strings.LastIndex(funcName, ":"); idx > 0 {
		if !strings.Contains(funcName[idx:], "/") {
			funcName = funcName[:idx]
		}
	}

	// Strip generic type-parameter suffix: "slices.Sort[go.shape.string]" → "slices.Sort"
	if idx := strings.Index(funcName, "["); idx > 0 {
		funcName = funcName[:idx]
	}

	parts := strings.Split(funcName, ".")
	if len(parts) == 1 {
		return funcName
	}

	dotIdx := -1
	for i := len(funcName) - 1; i >= 0; i-- {
		if funcName[i] == '.' {
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

	// strip closure suffixes: "main.outer.func1" → "main", but "github.com/foo/bar.Func" stays intact
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

	// "hash.Hash" or "mime.setExtensionType" → these are package.TypeName paths from
	// method/defer-wrapper entries in pclntab.  Module paths always contain at least
	// one "/" (e.g. "github.com/foo/bar"), so a dotted name with no slash is always
	// a simple stdlib package.TypeName — strip to the root component.
	if strings.Contains(pkg, ".") && !strings.Contains(pkg, "/") {
		if idx := strings.Index(pkg, "."); idx > 0 {
			pkg = pkg[:idx]
		}
	}

	// "internal/abi.Kind" → "internal/abi": after the last "/" in a module path a dot
	// introduces a type name, not another package segment — strip the TypeName suffix.
	if idx := strings.LastIndex(pkg, "/"); idx >= 0 {
		afterSlash := pkg[idx+1:]
		if dotPos := strings.Index(afterSlash, "."); dotPos >= 0 {
			pkg = pkg[:idx+1+dotPos]
		}
	}

	return pkg
}

func isClosureSuffix(s string) bool {
	if s == "" {
		return false
	}
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
