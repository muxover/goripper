package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	gobinary "github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/cluster"
	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/pkg/analyzer"
	"github.com/spf13/cobra"
)

func newScandirCmd() *cobra.Command {
	var outFile string
	var verbose bool
	var workers int
	var jsonlOut bool
	var jsonOut bool
	var onlyGo bool
	var doClusters bool

	cmd := &cobra.Command{
		Use:   "scan-dir <directory>",
		Short: "Parallel batch analysis of all binaries in a directory tree",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := args[0]

			paths, err := collectBinaries(root, onlyGo)
			if err != nil {
				return fmt.Errorf("walking %s: %w", root, err)
			}
			if len(paths) == 0 {
				fmt.Fprintln(os.Stderr, "no binaries found")
				return nil
			}

			numWorkers := workers
			if numWorkers <= 0 {
				numWorkers = runtime.NumCPU()
			}

			results := analyzePaths(paths, numWorkers, verbose)

			w, cleanup, err := resolveWriter(outFile)
			if err != nil {
				return err
			}
			defer cleanup()

			if doClusters {
				return writeClusterOutput(results, w, jsonOut)
			}
			if jsonOut {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(results)
			}
			// default: JSONL — one result per line
			enc := json.NewEncoder(w)
			for _, r := range results {
				if err := enc.Encode(r); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write output to file instead of stdout")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	cmd.Flags().IntVar(&workers, "workers", 0, "number of parallel workers (default: number of CPUs)")
	cmd.Flags().BoolVar(&jsonlOut, "jsonl", false, "output as newline-delimited JSON (default)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as a single JSON array")
	cmd.Flags().BoolVar(&onlyGo, "only-go", false, "skip binaries without a Go pclntab")
	cmd.Flags().BoolVar(&doClusters, "cluster", false, "cluster results by function similarity (threshold 0.6)")
	cmd.MarkFlagsMutuallyExclusive("json", "jsonl")
	_ = jsonlOut // jsonl is the default behavior when neither flag is set

	return cmd
}

// When onlyGo is set, each file is opened and checked for a gopclntab magic.
func collectBinaries(root string, onlyGo bool) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		if !isExecutable(path) {
			return nil
		}
		if onlyGo {
			b, openErr := gobinary.Open(path)
			if openErr != nil {
				return nil
			}
			_, _, pErr := b.FindGopclntab()
			b.Close()
			if pErr != nil {
				return nil
			}
		}
		paths = append(paths, path)
		return nil
	})
	return paths, err
}

// On Windows we read magic bytes instead of relying on the execute bit (which is always
// set), so non-binary files like source code and docs are not passed to the analyzer.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if runtime.GOOS != "windows" {
		return info.Mode()&0o111 != 0
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	n, _ := f.Read(magic[:])
	if n < 2 {
		return false
	}
	// PE: "MZ"; ELF: 0x7F "ELF"
	return (magic[0] == 0x4D && magic[1] == 0x5A) ||
		(n == 4 && magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46)
}

// Results are returned in an unspecified order (whichever finishes first).
func analyzePaths(paths []string, workers int, verbose bool) []*output.AnalysisResult {
	type work struct {
		path string
	}
	type result struct {
		r *output.AnalysisResult
	}

	jobs := make(chan work, len(paths))
	results := make(chan result, len(paths))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				opts := analyzer.Options{
					BinaryPath: j.path,
					Verbose:    verbose,
				}
				r, err := runAnalysis(opts)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "skip %s: %v\n", j.path, err)
					}
					continue
				}
				results <- result{r}
			}
		}()
	}

	for _, p := range paths {
		jobs <- work{p}
	}
	close(jobs)

	wg.Wait()
	close(results)

	var out []*output.AnalysisResult
	for res := range results {
		out = append(out, res.r)
	}
	return out
}

func writeClusterOutput(results []*output.AnalysisResult, w io.Writer, jsonOut bool) error {
	groups := cluster.Cluster(results, 0.6)
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(groups)
	}
	if len(groups) == 0 {
		fmt.Fprintln(w, "No clusters found (no binary pairs exceed the 0.6 similarity threshold).")
		return nil
	}
	fmt.Fprintf(w, "=== Malware Family Clusters (%d groups) ===\n\n", len(groups))
	for i, g := range groups {
		fmt.Fprintf(w, "Group %d  (similarity=%.4f)\n", i+1, g.Similarity)
		for _, m := range g.Members {
			fmt.Fprintf(w, "  %s\n", m)
		}
		if len(g.SharedPackages) > 0 {
			fmt.Fprintf(w, "  shared packages: ")
			for j, p := range g.SharedPackages {
				if j > 0 {
					fmt.Fprintf(w, ", ")
				}
				fmt.Fprintf(w, "%s", p)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}
	return nil
}
