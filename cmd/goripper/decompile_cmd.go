package main

import (
	"fmt"
	"log"
	"os"

	"github.com/muxover/goripper/internal/decompile"
	"github.com/muxover/goripper/internal/pipeline"
	"github.com/spf13/cobra"
)

func newDecompileCmd() *cobra.Command {
	var outDir string
	var verbose bool
	var maxFuncs int

	cmd := &cobra.Command{
		Use:   "decompile <binary>",
		Short: "[EXPERIMENTAL] Lift Go binary functions to C or Go (structural aid)",
		Long: `[EXPERIMENTAL] Lift each user-defined function to three-address IR and emit C or
Go. The output is a structural aid for reading control flow, not a faithful or
compilable reconstruction — register/stack math and unresolved logic are
approximated or elided.

  --lang c  (default) — C skeleton files.
  --lang go           — Go files; runtime patterns (goroutine, defer, channel ops,
                        panic/recover, make) lifted to Go idioms where recognized.

C output layout:
  out/
    <package>.c   — one file per user package
    structs.h     — Go runtime type definitions (GoString, GoSlice, GoIface)
    stubs.h       — extern declarations for referenced external functions

Go output layout:
  out/
    go.mod              — module "recovered"; go 1.21
    <package>/
      <pkg>.go          — recovered package source
      stubs.go          — stub bodies for unresolved external calls`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lang, _ := cmd.Flags().GetString("lang")
			return runDecompile(args[0], outDir, verbose, maxFuncs, lang)
		},
	}

	cmd.Flags().StringVarP(&outDir, "output", "o", "out", "output directory")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose progress logging")
	cmd.Flags().IntVar(&maxFuncs, "max-funcs", 0, "limit number of functions decompiled (0 = all)")
	cmd.Flags().String("lang", "c", "output language: c or go")

	return cmd
}

func runDecompile(binaryPath, outDir string, verbose bool, maxFuncs int, lang string) error {
	fmt.Fprintln(os.Stderr, "[EXPERIMENTAL] decompile output is a structural aid for reading "+
		"control flow, not a faithful or compilable reconstruction.")

	if verbose {
		log.Printf("[*] lifting %s", binaryPath)
	}
	irFuncs, err := pipeline.LiftBinary(binaryPath, maxFuncs)
	if err != nil {
		return err
	}
	if verbose {
		log.Printf("[*] lifted %d user functions", len(irFuncs))
	}

	opts := decompile.Options{OutDir: outDir, Lang: lang}
	if lang == "go" {
		if verbose {
			log.Printf("[*] emitting Go module to %s/", outDir)
		}
		return decompile.EmitGo(irFuncs, opts)
	}
	if verbose {
		log.Printf("[*] emitting C to %s/", outDir)
	}
	return decompile.Emit(irFuncs, opts)
}
