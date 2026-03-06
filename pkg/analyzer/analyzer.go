package analyzer

import (
	"debug/buildinfo"
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
	"github.com/muxover/goripper/internal/obfuscation"
	"github.com/muxover/goripper/internal/output"
	gstrings "github.com/muxover/goripper/internal/strings"
	gtypes "github.com/muxover/goripper/internal/types"
)

// Analyzer orchestrates the full GoRipper analysis pipeline.
type Analyzer struct {
	opts   Options
	binary gobinary.Binary

	pclntab    *gopclntab.ParsedPclntab
	funcs      []functions.Function
	strs       []gstrings.ExtractedString
	graph      *callgraph.CallGraph
	cfgs       map[string]*cfg.CFG
	rtypes     []gtypes.RecoveredType
	concurrent []concurrency.ConcurrencyPattern

	// v0.0.4-pre additions
	obfResult      obfuscation.Result
	decryptorStubs []obfuscation.StubMatch
	xorKeys        map[string]byte
	cgoCallSites   []string
	warnings       []string
	hasBuildInfo   bool
}

// New creates a new Analyzer with the given options.
func New(opts Options) *Analyzer {
	return &Analyzer{
		opts:    opts,
		cfgs:    make(map[string]*cfg.CFG),
		xorKeys: make(map[string]byte),
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
		{"detect obfuscation", a.detectObfuscation},
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

func (a *Analyzer) loadBinary() error {
	bin, err := gobinary.Open(a.opts.BinaryPath)
	if err != nil {
		return err
	}
	a.binary = bin
	if _, err2 := buildinfo.ReadFile(a.opts.BinaryPath); err2 == nil {
		a.hasBuildInfo = true
	}
	return nil
}

func (a *Analyzer) parsePclntab() error {
	pclntabData, _, err := a.binary.FindGopclntab()
	if err != nil {
		a.warnings = append(a.warnings,
			fmt.Sprintf("gopclntab not found (%v) - function names will be synthetic", err))
		return nil
	}

	textStart, _, err := a.binary.TextSectionRange()
	if err != nil {
		textStart = 0
	}

	parsed, err := gopclntab.Parse(pclntabData, textStart)
	if err != nil {
		a.warnings = append(a.warnings,
			fmt.Sprintf("gopclntab parse failed (%v) - function names will be synthetic", err))
		return nil
	}

	a.pclntab = parsed
	if a.opts.Verbose {
		log.Printf("    pclntab version: %s, %d functions found", parsed.Version, len(parsed.Funcs))
	}
	return nil
}

func (a *Analyzer) extractFunctions() error {
	if a.pclntab != nil {
		extracted := functions.Extract(a.pclntab.Funcs)
		a.funcs = functions.Classify(extracted)
		return nil
	}

	// Stripped/garbled fallback: recover function boundaries from .pdata (PE).
	addrs, _ := a.syntheticAddrs()
	if len(addrs) == 0 {
		a.warnings = append(a.warnings,
			"could not recover any function boundaries - output will be empty")
		return nil
	}
	a.funcs = functions.Classify(functions.SyntheticFromAddrs(addrs))

	synCount := 0
	for _, fn := range a.funcs {
		if fn.Source == functions.SourceSynthetic {
			synCount++
		}
	}
	if synCount > 0 && synCount*100/len(a.funcs) > 50 {
		a.warnings = append(a.warnings,
			fmt.Sprintf("%d%% of functions are synthetic (sub_0x*) - pclntab absent or garbled",
				synCount*100/len(a.funcs)))
	}
	return nil
}

// syntheticAddrs recovers (addr, size) pairs from the PE .pdata section.
// Each entry: BeginRVA uint32, EndRVA uint32, UnwindInfoRVA uint32 (12 bytes total).
func (a *Analyzer) syntheticAddrs() ([][2]uint64, error) {
	data, err := a.binary.Section(".pdata")
	if err != nil || len(data) < 12 {
		return nil, nil
	}
	imageBase := a.binary.ImageBase()
	var addrs [][2]uint64
	for i := 0; i+12 <= len(data); i += 12 {
		begin := uint64(data[i]) | uint64(data[i+1])<<8 |
			uint64(data[i+2])<<16 | uint64(data[i+3])<<24
		end := uint64(data[i+4]) | uint64(data[i+5])<<8 |
			uint64(data[i+6])<<16 | uint64(data[i+7])<<24
		if begin == 0 || end <= begin {
			continue
		}
		addrs = append(addrs, [2]uint64{imageBase + begin, end - begin})
	}
	return addrs, nil
}

func (a *Analyzer) extractStrings() error {
	rodataData, err := a.binary.Section(".rodata")
	if err != nil {
		rodataData, err = a.binary.Section(".rdata")
		if err != nil {
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

	textData, err2 := a.binary.Section(".text")
	if err2 == nil {
		textVA, _ := a.binary.SectionVA(".text")
		rodataEnd := rodataVA + uint64(len(rodataData))
		strs = gstrings.CrossReference(strs, a.funcs, textData, textVA, rodataData, rodataVA, rodataEnd)
		strs = gstrings.CrossReferenceSimple(strs, a.funcs, textData, textVA)
	}

	strs = gstrings.Classify(strs)
	strs = gstrings.SplitConcatenatedURLs(strs)

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

func (a *Analyzer) buildCallGraph() error {
	textData, err := a.binary.Section(".text")
	if err != nil {
		return nil
	}
	textVA, _ := a.binary.SectionVA(".text")

	graph, err := callgraph.Build(a.funcs, textData, textVA)
	if err != nil {
		return fmt.Errorf("callgraph.Build: %w", err)
	}
	a.graph = graph

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

func (a *Analyzer) buildCFGs() error {
	if !a.opts.CFGEnabled {
		return nil
	}
	textData, err := a.binary.Section(".text")
	if err != nil {
		return nil
	}
	textVA, _ := a.binary.SectionVA(".text")

	addrToName := make(map[uint64]string, len(a.funcs))
	for _, fn := range a.funcs {
		addrToName[fn.Addr] = fn.Name
	}
	for i, fn := range a.funcs {
		if fn.IsRuntime && a.opts.NoRuntime {
			continue
		}
		g, err := cfg.Build(fn, textData, textVA)
		if err != nil {
			continue
		}
		a.cfgs[fn.Name] = g
		a.funcs[i].Pseudocode = cfg.Emit(g, addrToName)
	}
	return nil
}

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

func (a *Analyzer) detectConcurrency() error {
	if a.graph == nil {
		return nil
	}
	patterns, updated := concurrency.Detect(a.graph, a.funcs)
	a.concurrent = patterns
	a.funcs = updated
	return nil
}

func (a *Analyzer) tagBehaviors() error {
	if a.graph == nil {
		return nil
	}
	a.funcs = behaviors.Tag(a.funcs, a.graph, a.strs)
	a.cgoCallSites, _ = behaviors.CGoBoundaries(a.funcs, a.graph)
	return nil
}

func (a *Analyzer) detectObfuscation() error {
	a.obfResult = obfuscation.Detect(a.funcs, a.strs, a.hasBuildInfo)

	stubs := obfuscation.FindDecryptorStubs(a.funcs, a.graph)

	textData, err := a.binary.Section(".text")
	if err == nil {
		textVA, _ := a.binary.SectionVA(".text")
		for i, stub := range stubs {
			for _, fn := range a.funcs {
				if fn.Name != stub.FuncName {
					continue
				}
				if key, ok := obfuscation.TryDecodeXOR(fn, textData, textVA); ok {
					stubs[i].XORKey = key
					stubs[i].HasXORKey = true
					a.xorKeys[stub.FuncName] = key
				}
				break
			}
		}
	}
	a.decryptorStubs = stubs
	a.funcs = obfuscation.TagDecryptorStubs(a.funcs, stubs, a.xorKeys)
	a.funcs = obfuscation.Relabel(a.funcs, a.obfResult.Score)
	return nil
}

func (a *Analyzer) buildOutput() *output.AnalysisResult {
	result := &output.AnalysisResult{
		Warnings: nilSafe(a.warnings),
	}

	goVer := a.binary.GoVersion()
	if goVer == "" && a.pclntab != nil {
		goVer = a.pclntab.GoVersion
	}
	result.BinaryInfo = output.BinaryInfo{
		Path:                  a.binary.Path(),
		Format:                a.binary.Format(),
		Arch:                  a.binary.Arch(),
		GoVersion:             goVer,
		SizeBytes:             a.binary.Size(),
		ObfuscationScore:      a.obfResult.Score,
		ObfuscationLevel:      a.obfResult.Level,
		ObfuscationIndicators: a.obfResult.Indicators,
	}

	result.Functions = make([]output.FunctionOutput, 0, len(a.funcs))
	for _, fn := range a.funcs {
		result.Functions = append(result.Functions, output.FunctionOutput{
			Name:           fn.Name,
			Addr:           fmt.Sprintf("0x%x", fn.Addr),
			Package:        fn.Package,
			PackageKind:    fn.PackageKind.String(),
			FunctionSource: string(fn.Source),
			Size:           fn.Size,
			Calls:          nilSafe(fn.Calls),
			CalledBy:       nilSafe(fn.CalledBy),
			Strings:        nilSafe(fn.Strings),
			Tags:           nilSafe(fn.Tags),
			IsRuntime:      fn.IsRuntime,
			IsConcurrent:   fn.IsConcurrent,
			Pseudocode:     fn.Pseudocode,
		})
	}

	result.Strings = make([]output.StringOutput, 0, len(a.strs))
	for _, s := range a.strs {
		result.Strings = append(result.Strings, output.StringOutput{
			Value:        s.Value,
			Type:         string(s.Type),
			ReferencedBy: nilSafe(s.ReferencedBy),
		})
	}

	result.CallGraph = make(map[string][]string)
	if a.graph != nil {
		for caller, callees := range a.graph.Calls {
			sorted := make([]string, len(callees))
			copy(sorted, callees)
			sort.Strings(sorted)
			result.CallGraph[caller] = sorted
		}
	}

	result.Types = make([]output.TypeOutput, 0, len(a.rtypes))
	for _, t := range a.rtypes {
		to := output.TypeOutput{Name: t.Name, Kind: string(t.Kind), Size: t.Size}
		for _, f := range t.Fields {
			to.Fields = append(to.Fields, output.FieldOutput{
				Name: f.Name, Type: f.Type, Offset: f.Offset,
			})
		}
		result.Types = append(result.Types, to)
	}

	result.DecryptorStubs = make([]output.DecryptorStubOutput, 0, len(a.decryptorStubs))
	for _, s := range a.decryptorStubs {
		dso := output.DecryptorStubOutput{
			Name:        s.FuncName,
			Addr:        fmt.Sprintf("0x%x", s.FuncAddr),
			CallerCount: s.CallerCount,
		}
		if s.HasXORKey {
			dso.XORKey = fmt.Sprintf("0x%02x", s.XORKey)
		}
		result.DecryptorStubs = append(result.DecryptorStubs, dso)
	}

	sum := output.SummaryOutput{
		TotalFunctions: len(a.funcs),
		RecoveredTypes: len(a.rtypes),
		DecryptorStubs: len(a.decryptorStubs),
		CgoCallSites:   nilSafe(a.cgoCallSites),
	}
	for _, fn := range a.funcs {
		switch fn.PackageKind {
		case functions.PackageUser:
			sum.UserFunctions++
		case functions.PackageStdlib:
			sum.StdlibFunctions++
		case functions.PackageRuntime:
			sum.RuntimeFunctions++
		case functions.PackageCGo:
			sum.CGOFunctions++
		}
		if fn.Source == functions.SourceSynthetic {
			sum.SyntheticFunctions++
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
