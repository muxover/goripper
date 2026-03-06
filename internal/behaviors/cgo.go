package behaviors

import (
	"strings"

	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/functions"
)

// CGoBoundaries identifies Go functions that directly call into CGo and the
// CGo functions themselves. Returns:
//   - callSites: names of Go (non-CGo) functions that call a CGo function
//   - cgoFuncs:  names of the CGo functions being called
func CGoBoundaries(
	funcs []functions.Function,
	graph *callgraph.CallGraph,
) (callSites []string, cgoFuncs []string) {
	if graph == nil {
		return nil, nil
	}

	// Build set of CGo function names for fast lookup.
	cgoSet := make(map[string]bool)
	for _, fn := range funcs {
		if fn.PackageKind == functions.PackageCGo {
			cgoSet[fn.Name] = true
			cgoFuncs = append(cgoFuncs, fn.Name)
		}
	}

	if len(cgoSet) == 0 {
		return nil, nil
	}

	// Find Go (user/stdlib) functions that call into CGo.
	siteSet := make(map[string]bool)
	for _, fn := range funcs {
		if fn.PackageKind == functions.PackageCGo {
			continue
		}
		for _, callee := range graph.Calls[fn.Name] {
			if cgoSet[callee] || isCGOCall(callee) {
				if !siteSet[fn.Name] {
					siteSet[fn.Name] = true
					callSites = append(callSites, fn.Name)
				}
				break
			}
		}
	}

	return callSites, cgoFuncs
}

// isCGOCall returns true for known CGo bridge call patterns that may not appear
// in the function list but do appear as call targets (e.g. _cgo_runtime_cgocall).
func isCGOCall(name string) bool {
	return strings.HasPrefix(name, "_cgo") ||
		strings.HasPrefix(name, "runtime/cgo.") ||
		name == "runtime.cgocall" ||
		name == "runtime.asmcgocall"
}
