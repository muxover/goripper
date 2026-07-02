package main

import (
	"fmt"
	"log"

	gobinary "github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/cfg"
	"github.com/muxover/goripper/internal/decompile"
	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/gopclntab"
	"github.com/muxover/goripper/internal/ir"
	"github.com/spf13/cobra"
)

func newDecompileCmd() *cobra.Command {
	var outDir string
	var verbose bool
	var maxFuncs int

	cmd := &cobra.Command{
		Use:   "decompile <binary>",
		Short: "Lift Go binary functions to IR and emit C or Go source",
		Long: `Lift each user-defined function in a Go binary to three-address IR and emit
source files. Two output languages are supported:

  --lang c  (default) — C skeleton files; structural aid, not fully readable source.
  --lang go           — Go module; runtime patterns (goroutine, defer, channel ops,
                        panic/recover, make) lifted to Go idioms. Per-package stubs.go
                        holds stub bodies so the output compiles with: go build ./...

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
	bin, err := gobinary.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer bin.Close()

	arch := bin.Arch()
	d := disasm.New(arch)

	if verbose {
		log.Printf("[*] arch: %s", arch)
		log.Printf("[*] parsing pclntab...")
	}

	pclntabData, _, err := bin.FindGopclntab()
	if err != nil {
		return fmt.Errorf("find pclntab: %w", err)
	}
	parsed, err := gopclntab.Parse(pclntabData, bin.ImageBase())
	if err != nil {
		return fmt.Errorf("parse pclntab: %w", err)
	}

	allFuncs := functions.Extract(parsed.Funcs)
	allFuncs = functions.Classify(allFuncs)

	// Only decompile user-defined functions.
	var userFuncs []functions.Function
	for _, fn := range allFuncs {
		if fn.PackageKind == functions.PackageUser {
			userFuncs = append(userFuncs, fn)
		}
	}

	if maxFuncs > 0 && len(userFuncs) > maxFuncs {
		userFuncs = userFuncs[:maxFuncs]
	}

	if verbose {
		log.Printf("[*] %d user functions to decompile", len(userFuncs))
	}

	textData, err := bin.Section(".text")
	if err != nil {
		return fmt.Errorf("read .text section: %w", err)
	}
	textVA, err := bin.SectionVA(".text")
	if err != nil {
		return fmt.Errorf("get .text VA: %w", err)
	}

	// Build address-to-name map for call target resolution.
	addrToName := make(map[uint64]string, len(allFuncs))
	for _, fn := range allFuncs {
		addrToName[fn.Addr] = fn.Name
	}

	var irFuncs []*ir.IRFunc
	for i, fn := range userFuncs {
		if verbose && i%100 == 0 {
			log.Printf("[*] lifting %d/%d: %s", i+1, len(userFuncs), fn.Name)
		}

		c, cfgErr := cfg.Build(fn, textData, textVA, d)
		if cfgErr != nil || c == nil || len(c.Blocks) == 0 {
			stub := &ir.IRFunc{
				Name:    fn.Name,
				Package: fn.Package,
				Addr:    fn.Addr,
				Vars:    map[string]string{},
				Blocks: []*ir.IRBlock{{
					ID:    0,
					Label: "L0",
					Instrs: []ir.IRInstr{{
						Op:   ir.OpComment,
						Meta: fmt.Sprintf("could not lift: %v", cfgErr),
					}},
				}},
			}
			irFuncs = append(irFuncs, stub)
			continue
		}

		f := ir.LiftArch(fn, c, textData, textVA, addrToName, arch)
		ir.FilterBoilerplate(f)
		ir.RenameVars(f)
		ir.RecoverVars(f)
		ir.PropTypes(f, nil)
		irFuncs = append(irFuncs, f)
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
