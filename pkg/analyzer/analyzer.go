package analyzer

import (
	"debug/buildinfo"
	"fmt"
	"log"
	"sort"

	"github.com/muxover/goripper/internal/assets"
	"github.com/muxover/goripper/internal/behaviors"
	gobinary "github.com/muxover/goripper/internal/binary"
	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/cfg"
	"github.com/muxover/goripper/internal/classify"
	"github.com/muxover/goripper/internal/concurrency"
	"github.com/muxover/goripper/internal/constants"
	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/entropy"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/gopclntab"
	"github.com/muxover/goripper/internal/modules"
	"github.com/muxover/goripper/internal/obfuscation"
	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/internal/similarity"
	gstrings "github.com/muxover/goripper/internal/strings"
	"github.com/muxover/goripper/internal/taint"
	gtypes "github.com/muxover/goripper/internal/types"
)

type Analyzer struct {
	opts   Options
	binary gobinary.Binary

	pclntab    *gopclntab.ParsedPclntab
	funcs      []functions.Function
	strs       []gstrings.ExtractedString
	graph      *callgraph.CallGraph
	cfgs       map[string]*cfg.CFG
	rtypes     []gtypes.RecoveredType
	itabs      []gtypes.InterfaceImpl
	concurrent []concurrency.ConcurrencyPattern
	sections   []entropy.SectionInfo
	packer     string
	embAssets  []assets.EmbeddedAsset

	obfResult      obfuscation.Result
	decryptorStubs []obfuscation.StubMatch
	xorKeys        map[string]byte
	cgoCallSites   []string
	taintFlows     []taint.TaintFlow
	warnings       []string
	hasBuildInfo   bool
	disasm         disasm.Disassembler
	simHashes      map[string]string
	moduleInfo     *modules.ModuleInfo
}

func New(opts Options) *Analyzer {
	return &Analyzer{
		opts:    opts,
		cfgs:    make(map[string]*cfg.CFG),
		xorKeys: make(map[string]byte),
	}
}

// Load is fatal; all other stages are crash-safe via safeRun.
func (a *Analyzer) Run() (*output.AnalysisResult, error) {
	if a.opts.Verbose {
		log.Printf("[*] load binary...")
	}
	if err := a.loadBinary(); err != nil {
		return nil, fmt.Errorf("load binary: %w", err)
	}

	stages := []struct {
		name string
		fn   func() error
	}{
		{"analyze sections", a.analyzeSections},
		{"parse pclntab", a.parsePclntab},
		{"extract functions", a.extractFunctions},
		{"extract strings", a.extractStrings},
		{"build call graph", a.buildCallGraph},
		{"build CFGs", a.buildCFGs},
		{"recover types", a.recoverTypes},
		{"detect concurrency", a.detectConcurrency},
		{"tag behaviors", a.tagBehaviors},
		{"extract constants", a.extractConstants},
		{"detect assets", a.detectAssets},
		{"detect obfuscation", a.detectObfuscation},
		{"taint analysis", a.runTaint},
		{"similarity hashing", a.runSimilarity},
		{"module graph", a.runModules},
	}

	for _, stage := range stages {
		if a.opts.Verbose {
			log.Printf("[*] %s...", stage.name)
		}
		if err := safeRun(stage.name, stage.fn); err != nil {
			a.warnings = append(a.warnings, err.Error())
		}
	}

	return a.buildOutput(), nil
}

func safeRun(stage string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("stage %q panicked: %v", stage, r)
		}
	}()
	return fn()
}

func (a *Analyzer) loadBinary() error {
	bin, err := gobinary.Open(a.opts.BinaryPath)
	if err != nil {
		return err
	}
	a.binary = bin
	a.disasm = disasm.New(bin.Arch())
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
		strs = gstrings.CrossReference(strs, a.funcs, textData, textVA, rodataData, rodataVA, rodataEnd, a.disasm)
		strs = gstrings.CrossReferenceSimple(strs, a.funcs, textData, textVA)
	}

	strs = gstrings.Classify(strs)
	strs = gstrings.SplitConcatenatedURLs(strs)
	strs = gstrings.SuppressBlobs(strs)
	strs = gstrings.Deduplicate(strs)

	if a.opts.MinStringLen > 0 {
		filtered := strs[:0]
		for _, s := range strs {
			if len(s.Value) >= a.opts.MinStringLen {
				filtered = append(filtered, s)
			}
		}
		strs = filtered
	}

	if a.opts.NoPlain {
		filtered := strs[:0]
		for _, s := range strs {
			if s.Type != gstrings.StringTypePlain {
				filtered = append(filtered, s)
			}
		}
		strs = filtered
	}

	if a.opts.MinRefs > 0 {
		userKind := make(map[string]bool, len(a.funcs))
		for _, fn := range a.funcs {
			if fn.PackageKind == functions.PackageUser {
				userKind[fn.Name] = true
			}
		}
		filtered := strs[:0]
		for _, s := range strs {
			count := 0
			for _, fn := range s.ReferencedBy {
				if userKind[fn] {
					count++
				}
			}
			if count >= a.opts.MinRefs {
				filtered = append(filtered, s)
			}
		}
		strs = filtered
	}

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

	graph, err := callgraph.Build(a.funcs, textData, textVA, a.disasm)
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
	if a.opts.MaxMemoryMB > 0 && a.binary.Size() > int64(a.opts.MaxMemoryMB)*1024*1024 {
		a.warnings = append(a.warnings,
			fmt.Sprintf("skipping CFG stage — binary (%d MB) exceeds --max-memory-mb %d",
				a.binary.Size()/(1024*1024), a.opts.MaxMemoryMB))
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
		g, err := cfg.Build(fn, textData, textVA, a.disasm)
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

	itabs, _ := gtypes.RecoverItabs(a.binary)
	a.itabs = itabs
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

func (a *Analyzer) analyzeSections() error {
	names := a.binary.SectionNames()
	a.packer = entropy.DetectPacker(names)
	for _, name := range names {
		data, err := a.binary.Section(name)
		if err != nil || len(data) == 0 {
			continue
		}
		e := entropy.Calculate(data)
		a.sections = append(a.sections, entropy.SectionInfo{
			Name:    name,
			Entropy: e,
			Size:    uint64(len(data)),
			Verdict: entropy.Verdict(e),
		})
	}
	return nil
}

func (a *Analyzer) extractConstants() error {
	if a.disasm.Arch() != "x86_64" {
		return nil
	}
	textData, err := a.binary.Section(".text")
	if err != nil {
		return nil
	}
	textVA, _ := a.binary.SectionVA(".text")

	for i, fn := range a.funcs {
		if fn.PackageKind != functions.PackageUser {
			continue
		}
		consts := constants.Extract(fn, textData, textVA)
		if len(consts) > 0 {
			a.funcs[i].Constants = consts
		}
	}
	return nil
}

func (a *Analyzer) detectAssets() error {
	if !a.opts.AssetsEnabled || a.graph == nil {
		return nil
	}
	a.embAssets = assets.Detect(a.strs, a.graph.Calls)
	return nil
}

func (a *Analyzer) runTaint() error {
	if !a.opts.TaintEnabled || a.graph == nil {
		return nil
	}
	userFuncCount := 0
	for _, fn := range a.funcs {
		if fn.PackageKind == functions.PackageUser {
			userFuncCount++
		}
	}
	if userFuncCount > 5000 {
		a.warnings = append(a.warnings,
			"taint analysis on large binary (>5000 user functions) — consider --only-user to narrow scope")
	}
	a.taintFlows = taint.Analyze(a.graph.Calls, a.graph.CalledBy)
	return nil
}

func (a *Analyzer) runSimilarity() error {
	textData, err := a.binary.Section(".text")
	if err != nil {
		return nil
	}
	textVA, _ := a.binary.SectionVA(".text")
	a.simHashes = make(map[string]string)
	for _, fn := range a.funcs {
		if fn.PackageKind != functions.PackageUser {
			continue
		}
		h := similarity.HashFunction(textData, textVA, fn, a.disasm)
		if h != "" {
			a.simHashes[fn.Name] = h
		}
	}
	return nil
}

func (a *Analyzer) runModules() error {
	if !a.opts.ModulesEnabled {
		return nil
	}
	pkgs := make([]string, 0, len(a.funcs))
	for _, fn := range a.funcs {
		pkgs = append(pkgs, fn.Package)
	}
	info, err := modules.Extract(a.opts.BinaryPath, pkgs)
	if err != nil {
		return nil // buildinfo absent — skip silently
	}
	a.moduleInfo = info
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
	pclntabVer := ""
	pclntabMagic := ""
	if a.pclntab != nil {
		pclntabVer = a.pclntab.Version.String()
		switch a.pclntab.Version {
		case gopclntab.Version12:
			pclntabMagic = "0xFFFFFFFB"
		case gopclntab.Version116:
			pclntabMagic = "0xFFFFFFFA"
		case gopclntab.Version118:
			pclntabMagic = "0xFFFFFFF0"
		case gopclntab.Version120:
			pclntabMagic = "0xFFFFFFF1"
		}
	}
	sectionOut := make([]output.SectionInfo, 0, len(a.sections))
	for _, s := range a.sections {
		sectionOut = append(sectionOut, output.SectionInfo{
			Name:    s.Name,
			Entropy: s.Entropy,
			Size:    s.Size,
			Verdict: s.Verdict,
		})
	}

	result.BinaryInfo = output.BinaryInfo{
		Path:                  a.binary.Path(),
		Format:                a.binary.Format(),
		Arch:                  a.binary.Arch(),
		GoVersion:             goVer,
		PclntabVersion:        pclntabVer,
		PclntabMagic:          pclntabMagic,
		SizeBytes:             a.binary.Size(),
		Packer:                a.packer,
		Sections:              sectionOut,
		ObfuscationScore:      a.obfResult.Score,
		ObfuscationLevel:      a.obfResult.Level,
		ObfuscationIndicators: a.obfResult.Indicators,
	}

	result.Functions = make([]output.FunctionOutput, 0, len(a.funcs))
	for _, fn := range a.funcs {
		fo := output.FunctionOutput{
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
			SimilarityHash: a.simHashes[fn.Name],
		}
		if len(fn.Constants) > 0 {
			fo.Constants = make([]output.ConstantOutput, len(fn.Constants))
			for i, c := range fn.Constants {
				fo.Constants[i] = output.ConstantOutput{
					Value:      c.Value,
					Category:   c.Category,
					Confidence: c.Confidence,
				}
			}
		}
		result.Functions = append(result.Functions, fo)
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

	result.Interfaces = make([]output.InterfaceImplOutput, 0, len(a.itabs))
	for _, it := range a.itabs {
		result.Interfaces = append(result.Interfaces, output.InterfaceImplOutput{
			Interface: it.Interface,
			Concrete:  it.Concrete,
			ItabAddr:  fmt.Sprintf("0x%x", it.ItabAddr),
		})
	}

	result.EmbeddedAssets = make([]output.AssetOutput, 0, len(a.embAssets))
	for _, ea := range a.embAssets {
		result.EmbeddedAssets = append(result.EmbeddedAssets, output.AssetOutput{
			Path:     ea.Path,
			SizeHint: ea.SizeHint,
		})
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

	result.TaintFlows = make([]output.TaintFlowOutput, 0, len(a.taintFlows))
	for _, tf := range a.taintFlows {
		result.TaintFlows = append(result.TaintFlows, output.TaintFlowOutput{
			Source:     tf.Source,
			SourceFunc: tf.SourceFunc,
			Sink:       tf.Sink,
			SinkFunc:   tf.SinkFunc,
			Path:       tf.Path,
			Confidence: tf.Confidence,
		})
	}

	if a.moduleInfo != nil {
		mg := &output.ModuleGraphOutput{
			MainModule:   a.moduleInfo.MainModule,
			GoVersion:    a.moduleInfo.GoVersion,
			Dependencies: make([]output.ModuleDependencyOutput, len(a.moduleInfo.Dependencies)),
		}
		for i, d := range a.moduleInfo.Dependencies {
			mg.Dependencies[i] = output.ModuleDependencyOutput{
				Path:          d.Path,
				Version:       d.Version,
				UsedFunctions: d.UsedFunctions,
				CVEs:          d.CVEs,
			}
		}
		result.ModuleGraph = mg
	}

	sum := output.SummaryOutput{
		TotalFunctions: len(a.funcs),
		RecoveredTypes: len(a.rtypes),
		InterfaceImpls: len(a.itabs),
		EmbeddedAssets: len(a.embAssets),
		DecryptorStubs: len(a.decryptorStubs),
		TaintFlows:     len(a.taintFlows),
		CgoCallSites:   nilSafe(a.cgoCallSites),
	}
	allTags := make(map[string]bool)
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
			for _, t := range fn.Tags {
				allTags[t] = true
			}
		}
		if fn.IsConcurrent {
			sum.ConcurrentFunctions++
		}
	}
	for _, s := range a.strs {
		sum.TotalStrings++
		switch s.Type {
		case gstrings.StringTypeURL:
			sum.URLStrings++
		case gstrings.StringTypeIP:
			sum.IPStrings++
		case gstrings.StringTypePath:
			sum.PathStrings++
		case gstrings.StringTypeSecret:
			sum.SecretStrings++
		case gstrings.StringTypePkgPath:
			sum.PkgPathStrings++
		case gstrings.StringTypePlain:
			sum.PlainStrings++
		}
	}

	tagList := make([]string, 0, len(allTags))
	for t := range allTags {
		tagList = append(tagList, t)
	}
	allStrVals := make([]string, 0, len(a.strs))
	for _, s := range a.strs {
		allStrVals = append(allStrVals, s.Value)
	}
	threat := classify.Classify(classify.Input{
		BehaviorTags:   tagList,
		StringValues:   allStrVals,
		URLCount:       sum.URLStrings,
		HasConcurrency: sum.ConcurrentFunctions > 0,
		HasCrypto:      allTags["CRYPTO"],
		HasNetwork:     allTags["NETWORK"],
		HasFileWrite:   allTags["FILE_WRITE"],
		HasFileRead:    allTags["FILE_READ"],
		HasExecution:   allTags["EXECUTION"],
		HasRegistry:    allTags["REGISTRY"],
		HasDNS:         allTags["DNS"],
		HasHTTP:        allTags["HTTP"],
		HasMemory:      allTags["MEMORY"],
		ObfScore:       a.obfResult.Score,
	})
	sum.ThreatClass = string(threat.Class)
	sum.ThreatConfidence = threat.Confidence
	sum.ThreatIndicators = threat.Indicators
	if a.moduleInfo != nil {
		sum.ModuleDeps = len(a.moduleInfo.Dependencies)
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
