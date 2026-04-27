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
