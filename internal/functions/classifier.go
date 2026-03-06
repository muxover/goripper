package functions

import "strings"

// runtimePrefixes lists package prefixes considered part of the Go runtime layer.
// Functions in these packages are noise for behavioral analysis.
var runtimePrefixes = []string{
	"runtime",
	"runtime/internal",
	"internal/",
	"reflect",
	"sync",
	"sync/atomic",
	"syscall",
	"os/signal",
	"math",
	"math/bits",
	"math/rand",
	"unicode",
	"unicode/utf8",
	"unicode/utf16",
	"strconv",
	"unsafe",
	"abi",
}

// stdlibPrefixes lists packages that are stdlib but not runtime-critical.
var stdlibPrefixes = []string{
	"fmt",
	"errors",
	"io",
	"io/fs",
	"io/ioutil",
	"os",
	"os/exec",
	"net",
	"net/http",
	"net/url",
	"net/rpc",
	"net/smtp",
	"crypto",
	"encoding",
	"encoding/json",
	"encoding/xml",
	"encoding/base64",
	"bufio",
	"bytes",
	"strings",
	"regexp",
	"sort",
	"path",
	"path/filepath",
	"log",
	"flag",
	"time",
	"context",
	"database",
	"compress",
	"archive",
	"html",
	"text",
	"testing",
	"plugin",
	"expvar",
}

// Classify assigns PackageKind and IsRuntime to each function.
func Classify(funcs []Function) []Function {
	result := make([]Function, len(funcs))
	for i, f := range funcs {
		f.PackageKind = classifyPackage(f.Package)
		f.IsRuntime = f.PackageKind == PackageRuntime
		result[i] = f
	}
	return result
}

func classifyPackage(pkg string) PackageKind {
	if pkg == "" {
		return PackageRuntime // likely internal runtime stub
	}

	// CGo bridge functions
	if strings.HasPrefix(pkg, "_cgo") || pkg == "runtime/cgo" {
		return PackageCGo
	}

	// Check runtime prefixes
	for _, prefix := range runtimePrefixes {
		if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") || strings.HasPrefix(pkg, prefix+".") {
			return PackageRuntime
		}
	}

	// Special runtime markers
	if strings.HasPrefix(pkg, "go:") || strings.HasPrefix(pkg, "type:") {
		return PackageRuntime
	}

	// Check stdlib prefixes
	for _, prefix := range stdlibPrefixes {
		if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") || strings.HasPrefix(pkg, prefix+".") {
			return PackageStdlib
		}
	}

	// Check if it looks like a stdlib package (no dots in import path except for subpkgs)
	// Stdlib packages never have a domain-like structure (e.g., "github.com/...")
	if !strings.Contains(pkg, ".") || isKnownStdlibRoot(pkg) {
		return PackageStdlib
	}

	return PackageUser
}

// IsRuntimePackage returns true for packages considered part of the Go runtime.
func IsRuntimePackage(pkg string) bool {
	return classifyPackage(pkg) == PackageRuntime
}

func isKnownStdlibRoot(pkg string) bool {
	// Simple heuristic: if the package root (before first '/') has no dot,
	// it's likely stdlib (e.g., "net/http" root is "net", no dot)
	root := pkg
	if idx := strings.Index(pkg, "/"); idx >= 0 {
		root = pkg[:idx]
	}
	return !strings.Contains(root, ".")
}
