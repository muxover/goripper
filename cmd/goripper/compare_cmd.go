package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/muxover/goripper/internal/similarity"
	"github.com/muxover/goripper/pkg/analyzer"
	"github.com/spf13/cobra"
)

func newCompareCmd() *cobra.Command {
	var jsonOut bool
	var outFile string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "compare <binary-a> <binary-b>",
		Short: "Detect shared functions between two Go binaries via similarity hashing",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			optsA := analyzer.Options{BinaryPath: args[0], Verbose: verbose}
			optsB := analyzer.Options{BinaryPath: args[1], Verbose: verbose}

			a, err := runAnalysis(optsA)
			if err != nil {
				return fmt.Errorf("analyzing %s: %w", args[0], err)
			}
			b, err := runAnalysis(optsB)
			if err != nil {
				return fmt.Errorf("analyzing %s: %w", args[1], err)
			}

			cr := similarity.Compare(a, b)

			w, cleanup, err := resolveWriter(outFile)
			if err != nil {
				return err
			}
			defer cleanup()

			if jsonOut {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(cr)
			}
			writeCompareText(cr, w)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write output to file instead of stdout")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	return cmd
}

func writeCompareText(cr similarity.CompareResult, w io.Writer) {
	fmt.Fprintf(w, "=== GoRipper Compare ===\n")
	fmt.Fprintf(w, "  Binary A: %s\n", cr.BinaryA)
	fmt.Fprintf(w, "  Binary B: %s\n\n", cr.BinaryB)
	fmt.Fprintf(w, "Shared functions:  %d\n", cr.SharedFunctions)
	fmt.Fprintf(w, "Unique to A:       %d\n", cr.UniqueToA)
	fmt.Fprintf(w, "Unique to B:       %d\n", cr.UniqueToB)
	fmt.Fprintf(w, "Similarity score:  %.4f", cr.SimilarityScore)
	if cr.SimilarityScore >= 0.7 {
		fmt.Fprintf(w, "  (shared codebase likely)")
	}
	fmt.Fprintln(w)
	if len(cr.SharedPackages) > 0 {
		fmt.Fprintf(w, "Shared packages:   %s\n", strings.Join(cr.SharedPackages, ", "))
	}
	fmt.Fprintln(w)
}
