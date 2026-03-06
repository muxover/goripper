package analyzer

import (
	"fmt"
	"log"
	"sort"

	gobinary "github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/behaviors"
	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/cfg"
	"github.com/muxover/goripper/internal/concurrency"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/gopclntab"
	"github.com/muxover/goripper/internal/output"
	gstrings "github.com/muxover/goripper/internal/strings"
	gtypes "github.com/muxover/goripper/internal/types"
)

// Analyzer orchestrates the full GoRipper analysis pipeline.
type Analyzer struct {
	opts   Options
	binary gobinary.Binary

	// Intermediate state
	pclntab    *gopclntab.ParsedPclntab
	funcs      []functions.Function
	strs       []gstrings.ExtractedString
	graph      *callgraph.CallGraph
	cfgs       map[string]*cfg.CFG
	rtypes     []gtypes.RecoveredType
	concurrent []concurrency.ConcurrencyPattern
}

// New creates a new Analyzer with the given options.
func New(opts Options) *Analyzer {
	return &Analyzer{
		opts: opts,
		cfgs: make(map[string]*cfg.CFG),
	}
}

// Run executes the full analysis pipeline and returns the result.
func (a *Analyzer) Run() (*output.AnalysisResult, error) {
	stages := []struct {
		name string
		fn   func() error
	}{
		{"load binary", a.loadBinary},
		{"parse pclntab", a.parsePclntab},
		{"extract functions", a.extractFunctions},
		{"extract strings", a.extractStrings},
		{"build call graph", a.buildCallGraph},
		{"build CFGs", a.buildCFGs},
		{"recover types", a.recoverTypes},
		{"detect concurrency", a.detectConcurrency},
		{"tag behaviors", a.tagBehaviors},
	}

	for _, stage := range stages {
		if a.opts.Verbose {
			log.Printf("[*] %s...", stage.name)
		}
		if err := stage.fn(); err != nil {
			return nil, fmt.Errorf("%s: %w", stage.name, err)
		}
	}

	return a.buildOutput(), nil
}

// loadBinary opens the binary file.
func (a *Analyzer) loadBinary() error {
	bin, err := gobinary.Open(a.opts.BinaryPath)
	if err != nil {
		return err
	}
	a.binary = bin
	return nil
}

// parsePclntab finds and parses the gopclntab section.
func (a *Analyzer) parsePclntab() error {
	pclntabData, _, err := a.binary.FindGopclntab()
	if err != nil {
		return fmt.Errorf("find gopclntab: %w", err)
	}

	textStart, _, err := a.binary.TextSectionRange()
	if err != nil {
		textStart = 0
	}

	parsed, err := gopclntab.Parse(pclntabData, textStart)
	if err != nil {
		return fmt.Errorf("parse gopclntab: %w", err)
	}

	a.pclntab = parsed

	if a.opts.Verbose {
		log.Printf("    pclntab version: %s, %d functions found", parsed.Version, len(parsed.Funcs))
	}

	return nil
}

// extractFunctions converts pclntab entries to Function structs and classifies them.
func (a *Analyzer) extractFunctions() error {
	extracted := functions.Extract(a.pclntab.Funcs)
	a.funcs = functions.Classify(extracted)
	return nil
}

// extractStrings scans .rodata for strings and cross-references them to functions.
func (a *Analyzer) extractStrings() error {
	rodataData, err := a.binary.Section(".rodata")
	if err != nil {
		// PE uses .rdata
		rodataData, err = a.binary.Section(".rdata")
		if err != nil {
			// Non-fatal: just skip strings
			return nil
		}
	}

	rodataVA := uint64(0)
	for _, name := range []string{".rodata", ".rdata"} {
		va, e := a.binary.SectionVA(name)
		if e == nil {
			rodataVA = va
			break
		}
	}

	strs := gstrings.Extract(rodataData, rodataVA)

	// Cross-reference strings to functions via disassembly.
	// CrossReference may also emit new strings found via LEA but missed by the
	// header-pair scan, so Classify runs after both passes.
	textData, err2 := a.binary.Section(".text")
	if err2 == nil {
		textVA, _ := a.binary.SectionVA(".text")
		rodataEnd := rodataVA + uint64(len(rodataData))

		strs = gstrings.CrossReference(strs, a.funcs, textData, textVA, rodataData, rodataVA, rodataEnd)
		// Also try simple address scan as supplementary method
		strs = gstrings.CrossReferenceSimple(strs, a.funcs, textData, textVA)
	}

	strs = gstrings.Classify(strs)
	strs = gstrings.SplitConcatenatedURLs(strs)

	// Attach referenced strings to function structs
	funcStringMap := make(map[string][]string)
	for _, s := range strs {
		for _, fn := range s.ReferencedBy {
			funcStringMap[fn] = appendUniq(funcStringMap[fn], s.Value)
		}
	}
	for i, fn := range a.funcs {
		a.funcs[i].Strings = funcStringMap[fn.Name]
	}

	a.strs = strs
	return nil
}

// buildCallGraph disassembles functions and builds the call graph.
func (a *Analyzer) buildCallGraph() error {
	textData, err := a.binary.Section(".text")
	if err != nil {
		return nil // non-fatal
	}
	textVA, _ := a.binary.SectionVA(".text")

	graph, err := callgraph.Build(a.funcs, textData, textVA)
	if err != nil {
		return fmt.Errorf("callgraph.Build: %w", err)
	}
	a.graph = graph

	// Annotate functions with call data
	for i, fn := range a.funcs {
		if calls, ok := graph.Calls[fn.Name]; ok {
			a.funcs[i].Calls = calls
		}
		if calledBy, ok := graph.CalledBy[fn.Name]; ok {
			a.funcs[i].CalledBy = calledBy
		}
	}

	return nil
}

// buildCFGs generates CFGs and pseudocode for each function (if enabled).
func (a *Analyzer) buildCFGs() error {
	if !a.opts.CFGEnabled {
		return nil
	}

	textData, err := a.binary.Section(".text")
	if err != nil {
		return nil
	}
	textVA, _ := a.binary.SectionVA(".text")

	// Build addr->name map for pseudocode labels
	addrToName := make(map[uint64]string, len(a.funcs))
	for _, fn := range a.funcs {
		addrToName[fn.Addr] = fn.Name
	}

	for i, fn := range a.funcs {
		// Skip runtime functions to reduce noise unless specifically requested
		if fn.IsRuntime && a.opts.NoRuntime {
			continue
		}

		g, err := cfg.Build(fn, textData, textVA)
		if err != nil {
			continue
		}
		a.cfgs[fn.Name] = g

		pseudo := cfg.Emit(g, addrToName)
		a.funcs[i].Pseudocode = pseudo
	}

	return nil
}

// recoverTypes parses type descriptors from binary reflection metadata.
func (a *Analyzer) recoverTypes() error {
	if !a.opts.TypesEnabled {
		return nil
	}

	types, err := gtypes.Recover(a.binary)
	if err != nil {
		if a.opts.Verbose {
			log.Printf("    type recovery: %v (continuing)", err)
		}
		return nil
	}
	a.rtypes = types
	return nil
}

// detectConcurrency identifies goroutine and channel patterns.
func (a *Analyzer) detectConcurrency() error {
	if a.graph == nil {
		return nil
	}
	patterns, updated := concurrency.Detect(a.graph, a.funcs)
	a.concurrent = patterns
	a.funcs = updated
	return nil
}

// tagBehaviors applies behavior tags to functions.
func (a *Analyzer) tagBehaviors() error {
	if a.graph == nil {
		return nil
	}
	a.funcs = behaviors.Tag(a.funcs, a.graph, a.strs)
	return nil
}

// buildOutput assembles the final AnalysisResult from all pipeline stages.
func (a *Analyzer) buildOutput() *output.AnalysisResult {
	result := &output.AnalysisResult{}

	// Binary info
	goVer := a.binary.GoVersion()
	if goVer == "" && a.pclntab != nil {
		goVer = a.pclntab.GoVersion
	}
	result.BinaryInfo = output.BinaryInfo{
		Path:      a.binary.Path(),
		Format:    a.binary.Format(),
		Arch:      a.binary.Arch(),
		GoVersion: goVer,
		SizeBytes: a.binary.Size(),
	}

	// Functions
	result.Functions = make([]output.FunctionOutput, 0, len(a.funcs))
	for _, fn := range a.funcs {
		fo := output.FunctionOutput{
			Name:         fn.Name,
			Addr:         fmt.Sprintf("0x%x", fn.Addr),
			Package:      fn.Package,
			PackageKind:  fn.PackageKind.String(),
			Size:         fn.Size,
			Calls:        nilSafe(fn.Calls),
			CalledBy:     nilSafe(fn.CalledBy),
			Strings:      nilSafe(fn.Strings),
			Tags:         nilSafe(fn.Tags),
			IsRuntime:    fn.IsRuntime,
			IsConcurrent: fn.IsConcurrent,
			Pseudocode:   fn.Pseudocode,
		}
		result.Functions = append(result.Functions, fo)
	}

	// Strings
	result.Strings = make([]output.StringOutput, 0, len(a.strs))
	for _, s := range a.strs {
		result.Strings = append(result.Strings, output.StringOutput{
			Value:        s.Value,
			Type:         string(s.Type),
			ReferencedBy: nilSafe(s.ReferencedBy),
		})
	}

	// Call graph
	result.CallGraph = make(map[string][]string)
	if a.graph != nil {
		for caller, callees := range a.graph.Calls {
			sorted := make([]string, len(callees))
			copy(sorted, callees)
			sort.Strings(sorted)
			result.CallGraph[caller] = sorted
		}
	}

	// Types
	result.Types = make([]output.TypeOutput, 0, len(a.rtypes))
	for _, t := range a.rtypes {
		to := output.TypeOutput{
			Name: t.Name,
			Kind: string(t.Kind),
			Size: t.Size,
		}
		for _, f := range t.Fields {
			to.Fields = append(to.Fields, output.FieldOutput{
				Name:   f.Name,
				Type:   f.Type,
				Offset: f.Offset,
			})
		}
		result.Types = append(result.Types, to)
	}

	// Summary
	sum := output.SummaryOutput{
		TotalFunctions: len(a.funcs),
		RecoveredTypes: len(a.rtypes),
	}
	for _, fn := range a.funcs {
		switch fn.PackageKind {
		case functions.PackageUser:
			sum.UserFunctions++
		case functions.PackageStdlib:
			sum.StdlibFunctions++
		case functions.PackageRuntime:
			sum.RuntimeFunctions++
		}
		if len(fn.Tags) > 0 {
			sum.SuspiciousFunctions++
		}
		if fn.IsConcurrent {
			sum.ConcurrentFunctions++
		}
	}
	for _, s := range a.strs {
		sum.TotalStrings++
		if s.Type == gstrings.StringTypeURL {
			sum.URLStrings++
		}
	}
	result.Summary = sum

	return result
}

func nilSafe(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
