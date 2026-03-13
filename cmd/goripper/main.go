package main

import (
	"fmt"
	"os"

	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/pkg/analyzer"
	"github.com/spf13/cobra"
)

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

	root.AddCommand(
		newAnalyzeCmd(),
		newFunctionsCmd(),
		newStringsCmd(),
		newCallgraphCmd(),
	)

	return root
}

// --- Shared flags helpers ---

type commonFlags struct {
	jsonOut   bool
	noRuntime bool
	onlyUser  bool
	outDir    string
	verbose   bool
	cfgMode   bool
	typeMode  bool
}

func addCommonFlags(cmd *cobra.Command, f *commonFlags) {
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "output as JSON")
	cmd.Flags().BoolVar(&f.noRuntime, "no-runtime", false, "exclude runtime functions")
	cmd.Flags().BoolVar(&f.onlyUser, "only-user", false, "show only user-defined packages")
	cmd.Flags().StringVar(&f.outDir, "out", "", "output directory (default: stdout)")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "verbose logging")
}

// --- analyze command ---

func newAnalyzeCmd() *cobra.Command {
	var flags commonFlags

	cmd := &cobra.Command{
		Use:   "analyze <binary>",
		Short: "Full analysis: functions, strings, call graph, types, behavior tags",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := analyzer.Options{
				BinaryPath:   args[0],
				NoRuntime:    flags.noRuntime,
				OnlyUser:     flags.onlyUser,
				OutputDir:    flags.outDir,
				Verbose:      flags.verbose,
				JSONOutput:   flags.jsonOut,
				CFGEnabled:   flags.cfgMode,
				TypesEnabled: flags.typeMode,
			}

			result, err := runAnalysis(opts)
			if err != nil {
				return err
			}

			return writeOutput(result, flags, output.TextOptions{
				NoRuntime:     flags.noRuntime,
				OnlyUser:      flags.onlyUser,
				ShowCallGraph: false,
				ShowTypes:     flags.typeMode,
				ShowPseudo:    flags.cfgMode,
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().BoolVar(&flags.cfgMode, "cfg", false, "generate pseudocode for each function (slow)")
	cmd.Flags().BoolVar(&flags.typeMode, "types", false, "recover Go type information")

	return cmd
}

// --- functions command ---

func newFunctionsCmd() *cobra.Command {
	var flags commonFlags
	var pkgFilter string

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

			// Filter by package if specified
			if pkgFilter != "" {
				result = filterByPackage(result, pkgFilter)
			}

			return writeOutput(result, flags, output.TextOptions{
				NoRuntime:     flags.noRuntime,
				OnlyUser:      flags.onlyUser,
				OnlyFunctions: true,
				ShowPseudo:    flags.cfgMode,
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().StringVar(&pkgFilter, "pkg", "", "filter to specific package name")
	cmd.Flags().BoolVar(&flags.cfgMode, "cfg", false, "generate pseudocode")

	return cmd
}

// --- strings command ---

func newStringsCmd() *cobra.Command {
	var flags commonFlags
	var strType string

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
			}

			result, err := runAnalysis(opts)
			if err != nil {
				return err
			}

			// Filter strings by type
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
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().StringVar(&strType, "type", "", "filter string type: url|ip|path|secret")

	return cmd
}

// --- callgraph command ---

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

			// Filter call graph if no-runtime
			if flags.noRuntime {
				result.CallGraph = filterCallGraph(result.CallGraph, result.Functions)
			}

			return writeOutput(result, flags, output.TextOptions{
				NoRuntime:     flags.noRuntime,
				OnlyFunctions: true,
				ShowCallGraph: true,
			})
		},
	}

	addCommonFlags(cmd, &flags)
	cmd.Flags().IntVar(&depth, "depth", 0, "max call graph traversal depth (0=unlimited)")

	return cmd
}

// --- helpers ---

func runAnalysis(opts analyzer.Options) (*output.AnalysisResult, error) {
	a := analyzer.New(opts)
	result, err := a.Run()
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}
	return result, nil
}

func writeOutput(result *output.AnalysisResult, flags commonFlags, textOpts output.TextOptions) error {
	if flags.jsonOut {
		if flags.outDir != "" {
			return output.WriteJSONFile(result, flags.outDir)
		}
		return output.WriteJSON(result, os.Stdout)
	}

	output.WriteText(result, os.Stdout, textOpts)
	return nil
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
	// Build set of non-runtime function names
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
