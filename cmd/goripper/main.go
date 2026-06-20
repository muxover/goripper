package main

import (
	"fmt"
	"os"

	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/pkg/analyzer"
	"github.com/spf13/cobra"
)

var quietFlag bool

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "goripper",
		Short: "Go binary intelligence extraction framework",
		Long: `GoRipper analyzes compiled Go binaries (PE/ELF) and extracts behavioral
intelligence: function names, call graph, strings, type info, and more.`,
	}

	root.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "suppress headers and decorative output; emit data rows only")

	analyzeCmd := newAnalyzeCmd()
	functionsCmd := newFunctionsCmd()
	stringsCmd := newStringsCmd()
	callgraphCmd := newCallgraphCmd()
	diffCmd := newDiffCmd()
	yaraCmd := newYaraCmd()
	compareCmd := newCompareCmd()
	scandirCmd := newScandirCmd()

	root.AddCommand(
		analyzeCmd,
		functionsCmd,
		stringsCmd,
		callgraphCmd,
		diffCmd,
		yaraCmd,
		compareCmd,
		scandirCmd,
		newTraceCmd(),
		newDecompileCmd(),
		newVersionCmd(),
	)

	registerCompletions(analyzeCmd, functionsCmd, stringsCmd, callgraphCmd, diffCmd, compareCmd, scandirCmd)

	return root
}

type commonFlags struct {
	jsonOut   bool
	noRuntime bool
	onlyUser  bool
	outFile   string
	verbose   bool
	cfgMode   bool
	typeMode  bool
}

func addCommonFlags(cmd *cobra.Command, f *commonFlags) {
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&f.noRuntime, "no-runtime", false, "exclude runtime functions")
	cmd.Flags().BoolVar(&f.onlyUser, "only-user", false, "show only user-defined packages")
	cmd.Flags().StringVarP(&f.outFile, "output", "o", "", "write output to file instead of stdout")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "verbose logging")
}

func newAnalyzeCmd() *cobra.Command {
	var flags commonFlags
	var minLen int
	var noPlain bool
	var minRefs int
	var showRefs bool
	var jsonlOut bool
	var htmlOut bool
	var idaOut bool
	var ghidraOut bool
	var maxFunctions int
	var maxMemoryMB int
	var assetsEnabled bool
	var taintEnabled bool
	var modulesEnabled bool
	var traceDataFile string

	cmd := &cobra.Command{
		Use:   "analyze <binary>",
		Short: "Full analysis: functions, strings, call graph, types, behavior tags",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := analyzer.Options{
				BinaryPath:     args[0],
				NoRuntime:      flags.noRuntime,
				OnlyUser:       flags.onlyUser,
				Verbose:        flags.verbose,
				JSONOutput:     flags.jsonOut,
				CFGEnabled:     flags.cfgMode,
				TypesEnabled:   flags.typeMode,
				AssetsEnabled:  assetsEnabled,
				TaintEnabled:   taintEnabled,
				MinStringLen:   minLen,
				NoPlain:        noPlain,
				MinRefs:        minRefs,
				MaxMemoryMB:    maxMemoryMB,
				ModulesEnabled: modulesEnabled,
			}

			result, err := runAnalysis(opts)
			if err != nil {
				return err
			}

			if traceDataFile != "" {
				if mergeErr := mergeTraceData(result, traceDataFile); mergeErr != nil {
					return fmt.Errorf("merge trace data: %w", mergeErr)
				}
			}

			if jsonlOut {
				w, cleanup, err := resolveWriter(flags.outFile)
				if err != nil {
					return err
				}
				defer cleanup()
				return output.WriteJSONL(w, result)
			}

			if htmlOut {
				w, cleanup, err := resolveWriter(flags.outFile)
				if err != nil {
					return err
				}
				defer cleanup()
				return output.WriteHTML(result, w)
			}

			if idaOut {
				w, cleanup, err := resolveWriter(flags.outFile)
				if err != nil {
					return err
				}
				defer cleanup()
				return output.WriteIDA(result, w)
			}

			if ghidraOut {
				w, cleanup, err := resolveWriter(flags.outFile)
				if err != nil {
					return err
				}
				defer cleanup()
				return output.WriteGhidra(result, w)
			}

			return writeOutput(result, flags, output.TextOptions{
				NoRuntime:    flags.noRuntime,
				OnlyUser:     flags.onlyUser,
				ShowTypes:    flags.typeMode,
				ShowPseudo:   flags.cfgMode,
				ShowRefs:     showRefs,
				Quiet:        quietFlag,
				MaxFunctions: maxFunctions,
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().BoolVar(&flags.cfgMode, "cfg", false, "generate pseudocode for each function (slow)")
	cmd.Flags().BoolVar(&flags.typeMode, "types", false, "recover Go type information")
	cmd.Flags().BoolVar(&assetsEnabled, "assets", false, "detect embedded assets (embed.FS)")
	cmd.Flags().BoolVar(&taintEnabled, "taint", false, "run inter-procedural taint analysis")
	cmd.Flags().IntVar(&minLen, "min-len", 0, "minimum string length (default 6)")
	cmd.Flags().BoolVar(&noPlain, "no-plain", false, "suppress plain-text strings")
	cmd.Flags().IntVar(&minRefs, "min-refs", 0, "minimum user-code reference count")
	cmd.Flags().BoolVar(&showRefs, "show-refs", false, "show referencing functions per string")
	cmd.Flags().BoolVar(&jsonlOut, "jsonl", false, "output as newline-delimited JSON (JSONL)")
	cmd.Flags().BoolVar(&htmlOut, "html", false, "write a self-contained HTML report")
	cmd.Flags().BoolVar(&idaOut, "ida", false, "emit an IDAPython rename script")
	cmd.Flags().BoolVar(&ghidraOut, "ghidra", false, "emit a GhidraScript (Java) rename script")
	cmd.Flags().IntVar(&maxFunctions, "max-functions", 0, "cap function list at N (0 = unlimited)")
	cmd.Flags().IntVar(&maxMemoryMB, "max-memory-mb", 0, "skip memory-intensive stages when binary exceeds N MB (0 = no limit)")
	cmd.Flags().BoolVar(&modulesEnabled, "modules", false, "recover module dependency graph from build info")
	cmd.Flags().StringVar(&traceDataFile, "trace-data", "", "path to a JSONL trace file to merge into analysis result")
	cmd.MarkFlagsMutuallyExclusive("json", "jsonl")
	cmd.MarkFlagsMutuallyExclusive("json", "html")
	cmd.MarkFlagsMutuallyExclusive("json", "ida")
	cmd.MarkFlagsMutuallyExclusive("json", "ghidra")
	cmd.MarkFlagsMutuallyExclusive("jsonl", "html")
	cmd.MarkFlagsMutuallyExclusive("jsonl", "ida")
	cmd.MarkFlagsMutuallyExclusive("jsonl", "ghidra")
	cmd.MarkFlagsMutuallyExclusive("html", "ida")
	cmd.MarkFlagsMutuallyExclusive("html", "ghidra")
	cmd.MarkFlagsMutuallyExclusive("ida", "ghidra")

	return cmd
}

func newFunctionsCmd() *cobra.Command {
	var flags commonFlags
	var pkgFilter string
	var maxFunctions int

	cmd := &cobra.Command{
		Use:   "functions <binary>",
		Short: "List functions with classification and call info",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := analyzer.Options{
				BinaryPath:    args[0],
				NoRuntime:     flags.noRuntime,
				OnlyUser:      flags.onlyUser,
				Verbose:       flags.verbose,
				JSONOutput:    flags.jsonOut,
				PackageFilter: pkgFilter,
				CFGEnabled:    flags.cfgMode,
			}

			result, err := runAnalysis(opts)
			if err != nil {
				return err
			}

			if pkgFilter != "" {
				result = filterByPackage(result, pkgFilter)
			}

			return writeOutput(result, flags, output.TextOptions{
				NoRuntime:     flags.noRuntime,
				OnlyUser:      flags.onlyUser,
				OnlyFunctions: true,
				ShowPseudo:    flags.cfgMode,
				Quiet:         quietFlag,
				MaxFunctions:  maxFunctions,
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().StringVar(&pkgFilter, "pkg", "", "filter to specific package name")
	cmd.Flags().BoolVar(&flags.cfgMode, "cfg", false, "generate pseudocode")
	cmd.Flags().IntVar(&maxFunctions, "max-functions", 0, "cap function list at N (0 = unlimited)")

	return cmd
}

func newStringsCmd() *cobra.Command {
	var flags commonFlags
	var strType string
	var minLen int
	var noPlain bool
	var minRefs int
	var showRefs bool

	cmd := &cobra.Command{
		Use:   "strings <binary>",
		Short: "Extract and classify strings from the binary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := analyzer.Options{
				BinaryPath:   args[0],
				Verbose:      flags.verbose,
				JSONOutput:   flags.jsonOut,
				StringFilter: strType,
				MinStringLen: minLen,
				NoPlain:      noPlain,
				MinRefs:      minRefs,
			}

			result, err := runAnalysis(opts)
			if err != nil {
				return err
			}

			if strType != "" {
				filtered := make([]output.StringOutput, 0)
				for _, s := range result.Strings {
					if s.Type == strType {
						filtered = append(filtered, s)
					}
				}
				result.Strings = filtered
			}

			return writeOutput(result, flags, output.TextOptions{
				OnlyStrings:  true,
				StringFilter: strType,
				ShowRefs:     showRefs,
				Quiet:        quietFlag,
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().StringVar(&strType, "type", "", "filter string type: url|ip|path|secret|pkgpath")
	cmd.Flags().IntVar(&minLen, "min-len", 0, "minimum string length (default 6)")
	cmd.Flags().BoolVar(&noPlain, "no-plain", false, "suppress plain-text strings")
	cmd.Flags().IntVar(&minRefs, "min-refs", 0, "minimum user-code reference count")
	cmd.Flags().BoolVar(&showRefs, "show-refs", false, "show referencing functions per string")

	return cmd
}

func newCallgraphCmd() *cobra.Command {
	var flags commonFlags
	var depth int

	cmd := &cobra.Command{
		Use:   "callgraph <binary>",
		Short: "Build and display the call graph",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := analyzer.Options{
				BinaryPath: args[0],
				NoRuntime:  flags.noRuntime,
				Verbose:    flags.verbose,
				JSONOutput: flags.jsonOut,
				CallDepth:  depth,
			}

			result, err := runAnalysis(opts)
			if err != nil {
				return err
			}

			if flags.noRuntime {
				result.CallGraph = filterCallGraph(result.CallGraph, result.Functions)
			}

			return writeOutput(result, flags, output.TextOptions{
				NoRuntime:     flags.noRuntime,
				OnlyFunctions: true,
				ShowCallGraph: true,
				Quiet:         quietFlag,
				CallDepth:     depth,
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().IntVar(&depth, "depth", 0, "max call graph traversal depth (0=unlimited)")

	return cmd
}

func runAnalysis(opts analyzer.Options) (*output.AnalysisResult, error) {
	a := analyzer.New(opts)
	result, err := a.Run()
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}
	return result, nil
}

func writeOutput(result *output.AnalysisResult, flags commonFlags, textOpts output.TextOptions) error {
	w, cleanup, err := resolveWriter(flags.outFile)
	if err != nil {
		return err
	}
	defer cleanup()

	return writeOutputTo(result, w, flags, textOpts)
}

func filterByPackage(result *output.AnalysisResult, pkg string) *output.AnalysisResult {
	filtered := make([]output.FunctionOutput, 0)
	for _, f := range result.Functions {
		if f.Package == pkg {
			filtered = append(filtered, f)
		}
	}
	result.Functions = filtered
	return result
}

func filterCallGraph(graph map[string][]string, funcs []output.FunctionOutput) map[string][]string {
	nonRuntime := make(map[string]bool)
	for _, f := range funcs {
		if !f.IsRuntime {
			nonRuntime[f.Name] = true
		}
	}

	filtered := make(map[string][]string)
	for caller, callees := range graph {
		if !nonRuntime[caller] {
			continue
		}
		filteredCallees := append([]string(nil), callees...)
		if len(filteredCallees) > 0 {
			filtered[caller] = filteredCallees
		}
	}
	return filtered
}
