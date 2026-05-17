package main

import (
	"github.com/muxover/goripper/internal/yara"
	"github.com/muxover/goripper/pkg/analyzer"
	"github.com/spf13/cobra"
)

func newYaraCmd() *cobra.Command {
	var outFile string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "yara <binary>",
		Short: "Generate a YARA rule from binary strings and function names",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := runAnalysis(analyzer.Options{
				BinaryPath: args[0],
				Verbose:    verbose,
			})
			if err != nil {
				return err
			}

			w, cleanup, err := resolveWriter(outFile)
			if err != nil {
				return err
			}
			defer cleanup()

			_, err = w.Write([]byte(yara.Generate(result)))
			return err
		},
	}

	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write rule to file instead of stdout")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	return cmd
}
