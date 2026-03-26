package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/muxover/goripper/internal/diff"
	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/pkg/analyzer"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var jsonOut bool
	var outFile string

	cmd := &cobra.Command{
		Use:   "diff <binary1> <binary2>",
		Short: "Compare two Go binaries and report what changed",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := runAnalysis(analyzer.Options{BinaryPath: args[0]})
			if err != nil {
				return fmt.Errorf("analyzing %s: %w", args[0], err)
			}
			b, err := runAnalysis(analyzer.Options{BinaryPath: args[1]})
			if err != nil {
				return fmt.Errorf("analyzing %s: %w", args[1], err)
			}

			result := diff.Compare(a, b)

			w, cleanup, err := resolveWriter(outFile)
			if err != nil {
				return err
			}
			defer cleanup()

			if jsonOut {
				return writeDiffJSON(result, w)
			}
			writeDiffText(result, args[0], args[1], w)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write output to file instead of stdout")
	return cmd
}

func writeDiffJSON(result *diff.Result, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func writeDiffText(result *diff.Result, pathA, pathB string, w io.Writer) {
	fmt.Fprintf(w, "=== GoRipper Diff ===\n")
	fmt.Fprintf(w, "  baseline:  %s\n", pathA)
	fmt.Fprintf(w, "  candidate: %s\n\n", pathB)

	if len(result.Added) > 0 {
		fmt.Fprintf(w, "=== New Functions (%d) ===\n", len(result.Added))
		for _, f := range result.Added {
			fmt.Fprintf(w, "  %-60s  size=%d\n", f.Name, f.Size)
		}
		fmt.Fprintln(w)
	}

	if len(result.Removed) > 0 {
		fmt.Fprintf(w, "=== Removed Functions (%d) ===\n", len(result.Removed))
		for _, f := range result.Removed {
			fmt.Fprintf(w, "  %-60s  size=%d\n", f.Name, f.Size)
		}
		fmt.Fprintln(w)
	}

	if len(result.Modified) > 0 {
		fmt.Fprintf(w, "=== Modified Functions (%d) ===\n", len(result.Modified))
		for _, m := range result.Modified {
			delta := int64(m.SizeAfter) - int64(m.SizeBefore)
			sign := "+"
			if delta < 0 {
				sign = ""
			}
			fmt.Fprintf(w, "  %-60s  size: %d → %d (%s%d bytes)\n",
				m.Name, m.SizeBefore, m.SizeAfter, sign, delta)
		}
		fmt.Fprintln(w)
	}

	if len(result.NewStrings) > 0 {
		fmt.Fprintf(w, "=== New Strings (%d) ===\n", len(result.NewStrings))
		for _, s := range result.NewStrings {
			val := s.Value
			if len(val) > 100 {
				val = val[:97] + "..."
			}
			fmt.Fprintf(w, "  [%-6s]  %q\n", s.Type, val)
		}
		fmt.Fprintln(w)
	}

	if len(result.NewBehaviors) > 0 {
		fmt.Fprintf(w, "=== New Behaviors (%d) ===\n", len(result.NewBehaviors))
		for _, tag := range result.NewBehaviors {
			fmt.Fprintf(w, "  %s\n", tag)
		}
		fmt.Fprintln(w)
	}

	if len(result.Added) == 0 && len(result.Removed) == 0 &&
		len(result.Modified) == 0 && len(result.NewStrings) == 0 &&
		len(result.NewBehaviors) == 0 {
		fmt.Fprintln(w, "No differences found.")
	}
}

// resolveWriter returns a writer for outFile (or stdout), plus a cleanup func.
func resolveWriter(outFile string) (io.Writer, func(), error) {
	if outFile == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(outFile)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open output file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "writing output to %s\n", outFile)
	return f, func() { f.Close() }, nil
}

// writeOutputTo writes analysis output to the given writer.
func writeOutputTo(result *output.AnalysisResult, w io.Writer, flags commonFlags, textOpts output.TextOptions) error {
	if flags.jsonOut {
		return output.WriteJSON(result, w)
	}
	output.WriteText(result, w, textOpts)
	return nil
}
