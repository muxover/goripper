package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	gobinary "github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/internal/trace"
	"github.com/muxover/goripper/pkg/analyzer"
	"github.com/spf13/cobra"
)

func newTraceCmd() *cobra.Command {
	var timeout time.Duration
	var jsonlOut bool
	var analyzeFlag bool
	var hotPath bool
	var outFile string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "trace <binary> [-- <args>...]",
		Short: "Trace function calls, syscalls, network, and file access at runtime",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binaryPath := args[0]

			// Everything after "--" is passed to the traced binary.
			var binaryArgs []string
			if cmd.ArgsLenAtDash() >= 0 {
				binaryArgs = args[cmd.ArgsLenAtDash():]
			} else if len(args) > 1 {
				binaryArgs = args[1:]
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "[*] running static analysis on %s...\n", binaryPath)
			}
			result, err := runAnalysis(analyzer.Options{
				BinaryPath: binaryPath,
				Verbose:    verbose,
			})
			if err != nil {
				return fmt.Errorf("static analysis: %w", err)
			}

			userFuncs := userFunctionsFrom(result)
			if verbose {
				fmt.Fprintf(os.Stderr, "[*] attaching tracer to %d user functions...\n", len(userFuncs))
			}

			// Resolve the binary's preferred image base so the tracer can compute
			// the ASLR slide if the OS loads the binary at a different address.
			var preferredBase uint64
			if bin, binErr := gobinary.Open(binaryPath); binErr == nil {
				preferredBase = bin.ImageBase()
				bin.Close()
			}

			w, cleanup, err := resolveWriter(outFile)
			if err != nil {
				return err
			}
			defer cleanup()

			opts := trace.Options{Timeout: timeout, PreferredBase: preferredBase}
			eventCh := make(chan trace.Event, 256)
			tracer := trace.New()

			traceErrCh := make(chan error, 1)
			go func() {
				traceErrCh <- tracer.Trace(binaryPath, binaryArgs, userFuncs, opts, eventCh)
				close(eventCh)
			}()

			var collected []trace.Event

			if jsonlOut {
				bw := bufio.NewWriter(w)
				enc := json.NewEncoder(bw)
				for ev := range eventCh {
					collected = append(collected, ev)
					if encErr := enc.Encode(ev); encErr != nil {
						return fmt.Errorf("encode event: %w", encErr)
					}
				}
				bw.Flush()
			} else {
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "TYPE\tFUNC/NAME\tADDR\tTS_NS\tDURATION_NS\tDETAIL")
				for ev := range eventCh {
					collected = append(collected, ev)
					detail := eventDetail(ev)
					fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n",
						ev.Type, funcOrName(ev), ev.Addr, ev.TsNs, ev.DurationNs, detail)
				}
				tw.Flush()
			}

			if err := <-traceErrCh; err != nil {
				return fmt.Errorf("tracer: %w", err)
			}

			if analyzeFlag {
				trace.Merge(result, collected)
				return writeOutputTo(result, w, commonFlags{jsonOut: jsonlOut}, output.TextOptions{})
			}

			if hotPath {
				fmt.Fprintln(w)
				trace.PrintHotPath(w, collected, result.Functions)
			}

			return nil
		},
	}

	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "stop tracing after this duration")
	cmd.Flags().BoolVar(&jsonlOut, "jsonl", false, "stream events as JSONL (default: human-readable table)")
	cmd.Flags().BoolVar(&analyzeFlag, "analyze", false, "merge trace with static analysis and emit result")
	cmd.Flags().BoolVar(&hotPath, "hot-path", false, "print hot path tree after tracing")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write output to file")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")

	return cmd
}

func userFunctionsFrom(result *output.AnalysisResult) []functions.Function {
	out := make([]functions.Function, 0, len(result.Functions))
	for _, fo := range result.Functions {
		if fo.PackageKind != "user" {
			continue
		}
		var addr uint64
		fmt.Sscanf(fo.Addr, "0x%x", &addr)
		out = append(out, functions.Function{
			Name:        fo.Name,
			Addr:        addr,
			Size:        fo.Size,
			Package:     fo.Package,
			PackageKind: functions.PackageUser,
		})
	}
	return out
}

func funcOrName(ev trace.Event) string {
	if ev.Func != "" {
		return ev.Func
	}
	return ev.Name
}

func eventDetail(ev trace.Event) string {
	if ev.Path != "" {
		return ev.Path
	}
	if ev.NetAddr != "" {
		return ev.NetAddr
	}
	if len(ev.Args) > 0 {
		return ev.Args[0]
	}
	return ""
}
