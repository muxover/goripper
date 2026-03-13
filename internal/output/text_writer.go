package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteText writes a human-readable analysis report to w.
func WriteText(result *AnalysisResult, w io.Writer, opts TextOptions) {
	// Warnings first so the analyst sees them immediately.
	if len(result.Warnings) > 0 {
		for _, warn := range result.Warnings {
			fmt.Fprintf(w, "WARNING: %s\n", warn)
		}
		fmt.Fprintln(w)
	}

	writeBinaryInfo(result.BinaryInfo, w)
	writeSummary(result.Summary, w)

	if len(result.DecryptorStubs) > 0 {
		writeDecryptorStubs(result.DecryptorStubs, w)
	}
	if len(result.Summary.CgoCallSites) > 0 {
		writeCGoBoundaries(result.Summary.CgoCallSites, w)
	}

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
	ShowRefs      bool   // show top-3 referencing functions per string
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
	if info.PclntabVersion != "" {
		fmt.Fprintf(w, "Pclntab:    version=%s  magic=%s\n", info.PclntabVersion, info.PclntabMagic)
	}
	fmt.Fprintf(w, "Size:       %d bytes\n", info.SizeBytes)
	if info.ObfuscationScore > 0 || info.ObfuscationLevel != "" {
		level := info.ObfuscationLevel
		if level == "" {
			level = "none"
		}
		fmt.Fprintf(w, "Obfuscation: %.2f [%s]", info.ObfuscationScore, level)
		if len(info.ObfuscationIndicators) > 0 {
			fmt.Fprintf(w, "  (%s)", strings.Join(info.ObfuscationIndicators, ", "))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)
}

func writeSummary(sum SummaryOutput, w io.Writer) {
	fmt.Fprintf(w, "=== Summary ===\n")
	fmt.Fprintf(w, "Total functions:      %d\n", sum.TotalFunctions)
	fmt.Fprintf(w, "  User:               %d\n", sum.UserFunctions)
	fmt.Fprintf(w, "  Stdlib:             %d\n", sum.StdlibFunctions)
	fmt.Fprintf(w, "  Runtime:            %d\n", sum.RuntimeFunctions)
	if sum.CGOFunctions > 0 {
		fmt.Fprintf(w, "  CGo:                %d\n", sum.CGOFunctions)
	}
	if sum.SyntheticFunctions > 0 {
		fmt.Fprintf(w, "  Synthetic:          %d  (sub_0x* — pclntab unavailable)\n", sum.SyntheticFunctions)
	}
	fmt.Fprintf(w, "Suspicious:           %d\n", sum.SuspiciousFunctions)
	fmt.Fprintf(w, "Concurrent:           %d\n", sum.ConcurrentFunctions)
	fmt.Fprintf(w, "Strings:              %d total  (%d URLs · %d IPs · %d paths · %d secrets · %d pkg-paths · %d plain)\n",
		sum.TotalStrings, sum.URLStrings, sum.IPStrings, sum.PathStrings,
		sum.SecretStrings, sum.PkgPathStrings, sum.PlainStrings)
	fmt.Fprintf(w, "Recovered types:      %d\n", sum.RecoveredTypes)
	if sum.DecryptorStubs > 0 {
		fmt.Fprintf(w, "Decryptor stubs:      %d  (possible string encryption)\n", sum.DecryptorStubs)
	}
	fmt.Fprintln(w)
}

func writeDecryptorStubs(stubs []DecryptorStubOutput, w io.Writer) {
	fmt.Fprintf(w, "=== String Decryptor Stubs (%d) ===\n", len(stubs))
	fmt.Fprintf(w, "These small, high-fan-in functions are likely string-decryption stubs (garble).\n")
	for _, s := range stubs {
		xor := ""
		if s.XORKey != "" {
			xor = fmt.Sprintf("  xor_key=%s", s.XORKey)
		}
		fmt.Fprintf(w, "  %s  %-40s  callers=%d%s\n", s.Addr, s.Name, s.CallerCount, xor)
	}
	fmt.Fprintln(w)
}

func writeCGoBoundaries(callSites []string, w io.Writer) {
	fmt.Fprintf(w, "=== CGo Boundaries (%d call sites) ===\n", len(callSites))
	fmt.Fprintf(w, "Go memory safety ends at these transition points.\n")
	for _, site := range callSites {
		fmt.Fprintf(w, "  %s\n", site)
	}
	fmt.Fprintln(w)
}

func writeFunctions(funcs []FunctionOutput, w io.Writer, opts TextOptions) {
	filtered := filterFunctions(funcs, opts)
	if len(filtered) == 0 {
		return
	}

	fmt.Fprintf(w, "=== Functions (%d) ===\n", len(filtered))

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
			src := ""
			if f.FunctionSource == "synthetic" {
				src = " [SYNTHETIC]"
			}
			fmt.Fprintf(w, "  %s  %-60s  size=%d%s%s%s\n",
				f.Addr, f.Name, f.Size, tags, concurrent, src)

			if opts.ShowPseudo && f.Pseudocode != "" {
				for _, line := range strings.Split(strings.TrimSpace(f.Pseudocode), "\n") {
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
			val := s.Value
			if len(val) > 120 {
				val = val[:117] + "..."
			}
			fmt.Fprintf(w, "  %q\n", val)
			if opts.ShowRefs && len(s.ReferencedBy) > 0 {
				top := s.ReferencedBy
				suffix := ""
				if len(top) > 3 {
					top = top[:3]
					suffix = fmt.Sprintf(" (+%d more)", len(s.ReferencedBy)-3)
				}
				fmt.Fprintf(w, "       └ %s%s\n", strings.Join(top, ", "), suffix)
			}
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
