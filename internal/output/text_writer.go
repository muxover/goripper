package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteText writes a human-readable analysis report to w.
func WriteText(result *AnalysisResult, w io.Writer, opts TextOptions) {
	writeBinaryInfo(result.BinaryInfo, w)
	writeSummary(result.Summary, w)

	if !opts.OnlyStrings {
		writeFunctions(result.Functions, w, opts)
	}
	if !opts.OnlyFunctions {
		writeStrings(result.Strings, w, opts)
	}
	if opts.ShowCallGraph {
		writeCallGraph(result.CallGraph, w, opts)
	}
	if opts.ShowTypes && len(result.Types) > 0 {
		writeTypes(result.Types, w)
	}
}

// TextOptions controls what the text writer emits.
type TextOptions struct {
	NoRuntime     bool
	OnlyUser      bool
	OnlyStrings   bool
	OnlyFunctions bool
	ShowCallGraph bool
	ShowTypes     bool
	ShowPseudo    bool
	MaxFunctions  int
	StringFilter  string // "url", "ip", "path", "secret", or ""
	CallDepth     int
}

func writeBinaryInfo(info BinaryInfo, w io.Writer) {
	fmt.Fprintf(w, "=== GoRipper Analysis Report ===\n")
	fmt.Fprintf(w, "Binary:     %s\n", info.Path)
	fmt.Fprintf(w, "Format:     %s\n", info.Format)
	fmt.Fprintf(w, "Arch:       %s\n", info.Arch)
	fmt.Fprintf(w, "Go Version: %s\n", info.GoVersion)
	fmt.Fprintf(w, "Size:       %d bytes\n\n", info.SizeBytes)
}

func writeSummary(sum SummaryOutput, w io.Writer) {
	fmt.Fprintf(w, "=== Summary ===\n")
	fmt.Fprintf(w, "Total functions:      %d\n", sum.TotalFunctions)
	fmt.Fprintf(w, "  User:               %d\n", sum.UserFunctions)
	fmt.Fprintf(w, "  Stdlib:             %d\n", sum.StdlibFunctions)
	fmt.Fprintf(w, "  Runtime:            %d\n", sum.RuntimeFunctions)
	fmt.Fprintf(w, "Suspicious:           %d\n", sum.SuspiciousFunctions)
	fmt.Fprintf(w, "Concurrent:           %d\n", sum.ConcurrentFunctions)
	fmt.Fprintf(w, "Total strings:        %d (%d URLs)\n", sum.TotalStrings, sum.URLStrings)
	fmt.Fprintf(w, "Recovered types:      %d\n\n", sum.RecoveredTypes)
}

func writeFunctions(funcs []FunctionOutput, w io.Writer, opts TextOptions) {
	filtered := filterFunctions(funcs, opts)
	if len(filtered) == 0 {
		return
	}

	fmt.Fprintf(w, "=== Functions (%d) ===\n", len(filtered))

	// Group by package
	byPkg := make(map[string][]FunctionOutput)
	var pkgs []string
	for _, f := range filtered {
		if byPkg[f.Package] == nil {
			pkgs = append(pkgs, f.Package)
		}
		byPkg[f.Package] = append(byPkg[f.Package], f)
	}
	sort.Strings(pkgs)

	for _, pkg := range pkgs {
		fns := byPkg[pkg]
		fmt.Fprintf(w, "\n[%s]\n", pkg)
		for _, f := range fns {
			tags := ""
			if len(f.Tags) > 0 {
				tags = " [" + strings.Join(f.Tags, "|") + "]"
			}
			concurrent := ""
			if f.IsConcurrent {
				concurrent = " [CONCURRENT]"
			}
			fmt.Fprintf(w, "  %s  %-60s  size=%d%s%s\n",
				f.Addr, f.Name, f.Size, tags, concurrent)

			if opts.ShowPseudo && f.Pseudocode != "" {
				lines := strings.Split(strings.TrimSpace(f.Pseudocode), "\n")
				for _, line := range lines {
					fmt.Fprintf(w, "    %s\n", line)
				}
			}

			if len(f.Calls) > 0 {
				fmt.Fprintf(w, "    calls: %s\n", strings.Join(f.Calls, ", "))
			}
		}
	}
	fmt.Fprintln(w)
}

func filterFunctions(funcs []FunctionOutput, opts TextOptions) []FunctionOutput {
	var result []FunctionOutput
	for _, f := range funcs {
		if opts.NoRuntime && (f.IsRuntime || f.PackageKind == "runtime") {
			continue
		}
		if opts.OnlyUser && f.PackageKind != "user" {
			continue
		}
		result = append(result, f)
	}
	return result
}

func writeStrings(strs []StringOutput, w io.Writer, opts TextOptions) {
	filtered := filterStrings(strs, opts)
	if len(filtered) == 0 {
		return
	}

	fmt.Fprintf(w, "=== Strings (%d) ===\n", len(filtered))

	// Group by type
	byType := make(map[string][]StringOutput)
	var types []string
	for _, s := range filtered {
		if byType[s.Type] == nil {
			types = append(types, s.Type)
		}
		byType[s.Type] = append(byType[s.Type], s)
	}
	sort.Strings(types)

	for _, t := range types {
		ss := byType[t]
		fmt.Fprintf(w, "\n[%s]\n", strings.ToUpper(t))
		for _, s := range ss {
			refs := ""
			if len(s.ReferencedBy) > 0 {
				refs = fmt.Sprintf("  (ref: %s)", strings.Join(s.ReferencedBy, ", "))
			}
			// Truncate very long strings
			val := s.Value
			if len(val) > 120 {
				val = val[:117] + "..."
			}
			fmt.Fprintf(w, "  %q%s\n", val, refs)
		}
	}
	fmt.Fprintln(w)
}

func filterStrings(strs []StringOutput, opts TextOptions) []StringOutput {
	if opts.StringFilter == "" {
		return strs
	}
	var result []StringOutput
	for _, s := range strs {
		if s.Type == opts.StringFilter {
			result = append(result, s)
		}
	}
	return result
}

func writeCallGraph(graph map[string][]string, w io.Writer, opts TextOptions) {
	if len(graph) == 0 {
		return
	}

	fmt.Fprintf(w, "=== Call Graph ===\n")

	// Sort callers for deterministic output
	callers := make([]string, 0, len(graph))
	for caller := range graph {
		callers = append(callers, caller)
	}
	sort.Strings(callers)

	for _, caller := range callers {
		callees := graph[caller]
		fmt.Fprintf(w, "\n%s\n", caller)
		for i, callee := range callees {
			if i == len(callees)-1 {
				fmt.Fprintf(w, "  └── %s\n", callee)
			} else {
				fmt.Fprintf(w, "  ├── %s\n", callee)
			}
		}
	}
	fmt.Fprintln(w)
}

func writeTypes(types []TypeOutput, w io.Writer) {
	fmt.Fprintf(w, "=== Recovered Types (%d) ===\n", len(types))
	for _, t := range types {
		fmt.Fprintf(w, "\ntype %s %s", t.Name, t.Kind)
		if t.Kind == "struct" && len(t.Fields) > 0 {
			fmt.Fprintf(w, " {\n")
			for _, f := range t.Fields {
				fmt.Fprintf(w, "    %-30s %s  // offset=%d\n", f.Name, f.Type, f.Offset)
			}
			fmt.Fprintf(w, "}")
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)
}
