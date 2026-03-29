# GoRipper Architecture

This document describes the internal structure of GoRipper for contributors and advanced users.

---

## Pipeline Overview

Every analysis runs through a linear pipeline. Each stage receives the output of the previous one. If a stage panics or errors, the pipeline records a warning and continues — the caller always gets a partial result.

```
binary file
    │
    ▼
┌─────────────────┐
│  binary loader  │  debug/pe or debug/elf — sections, VA, image base
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   gopclntab     │  debug/gosym — function names, entry PCs, sizes (Go 1.2–1.24)
└────────┬────────┘       │ absent → synthetic sub_0x<addr> from .pdata
         │
         ▼
┌─────────────────┐
│   functions     │  extract + classify (runtime / stdlib / user / cgo)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    strings      │  .rodata header pairs + LEA RIP-relative cross-reference
└────────┬────────┘       → classify → split URLs → suppress blobs → deduplicate
         │
         ▼
┌─────────────────┐
│   call graph    │  x86 CALL disassembly via golang.org/x/arch/x86/x86asm
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      CFG        │  basic block splitting + pseudocode emission (--cfg only)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  type recovery  │  rtype descriptor scan in .rodata / .typelinks (--types only)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  concurrency    │  goroutine / channel / mutex patterns via call graph
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   behaviors     │  rule-based tagging: NETWORK, CRYPTO, FILE_WRITE, etc.
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  obfuscation    │  entropy + prefix ratio + string density → 0.0–1.0 score
└────────┬────────┘       → decryptor stub detection → XOR key recovery → relabel
         │
         ▼
┌─────────────────┐
│  AnalysisResult │  output.AnalysisResult — JSON / JSONL / text
└─────────────────┘
```

---

## Package Reference

| Package | Path | Owns | Key types |
|---------|------|------|-----------|
| binary | `internal/binary` | PE + ELF loading, section access, gopclntab scanning | `Binary` (interface), `PEBinary`, `ELFBinary` |
| gopclntab | `internal/gopclntab` | PC-line table parsing via `debug/gosym` | `ParsedPclntab`, `PclntabVersion` |
| functions | `internal/functions` | Extraction, deduplication, package classification | `Function`, `PackageKind`, `FunctionSource` |
| strings | `internal/strings` | `.rodata` extraction, LEA cross-reference, classification | `ExtractedString`, `StringType` |
| callgraph | `internal/callgraph` | x86 CALL disassembly, edge building, addr→name resolution | `CallGraph`, `Edge`, `AddrName` |
| cfg | `internal/cfg` | Basic block splitting, branch resolution, pseudocode | `CFG`, `Block` |
| types | `internal/types` | rtype descriptor recovery from `.rodata` / `.typelinks` | `RecoveredType`, `TypeKind`, `FieldDescriptor` |
| concurrency | `internal/concurrency` | Goroutine / channel / sync pattern detection | `ConcurrencyPattern` |
| behaviors | `internal/behaviors` | Rule-based behavior tagging, CGo boundary mapping | `Rule`, `Tag` |
| obfuscation | `internal/obfuscation` | Garble scoring, decryptor stub detection, XOR recovery | `Result`, `StubMatch` |
| analyzer | `pkg/analyzer` | Pipeline orchestration, crash-safe stage runner | `Analyzer`, `Options` |
| output | `internal/output` | JSON, JSONL, and text writers | `AnalysisResult`, `TextOptions` |
| diff | `internal/diff` | Binary-to-binary comparison | `Result` |
| version | `internal/version` | Build-time version vars (ldflags injection) | `Version`, `Commit`, `Date` |

---

## Data Flow

The central type is `output.AnalysisResult`. The analyzer builds it in `buildOutput()` after all pipeline stages complete:

```
internal/functions.Function      →  output.FunctionOutput
internal/strings.ExtractedString →  output.StringOutput
internal/callgraph.CallGraph     →  map[string][]string
internal/types.RecoveredType     →  output.TypeOutput
internal/obfuscation.StubMatch   →  output.DecryptorStubOutput
(aggregated counts)              →  output.SummaryOutput
```

`AnalysisResult` is the only thing that crosses the `internal/` boundary into `cmd/` and `pkg/`. All three output writers (`WriteJSON`, `WriteJSONL`, `WriteText`) consume it.

---

## Binary Interface

`internal/binary.Binary` is the abstraction over PE and ELF:

```go
type Binary interface {
    Path() string
    Format() string        // "PE" or "ELF"
    Arch() string          // "x86_64"
    GoVersion() string
    ImageBase() uint64
    Size() int64
    Section(name string) ([]byte, error)
    SectionVA(name string) (uint64, error)
    TextSectionRange() (uint64, uint64, error)
    FindGopclntab() ([]byte, uint64, error)
}
```

`binary.Open()` auto-detects the format from the file magic and returns the appropriate implementation. All downstream stages call only this interface — none import `debug/pe` or `debug/elf` directly.

---

## String Extraction

String extraction is the most complex stage. It runs in three passes:

**Pass 1 — header pairs:** Scans `.rodata` for Go string header `(ptr, len)` pairs. A valid header has a pointer into `.rodata` and a length in `[6, 4096]`. This finds strings that have a header in the data section.

**Pass 2 — LEA cross-reference:** Disassembles `.text` looking for RIP-relative LEA instructions that point into `.rodata`. For each LEA, scans ±30 instructions for a `MOV reg, imm` to infer the exact string length. This finds hardcoded strings passed directly to functions without a header pair (e.g. URLs passed straight to `http.Get`).

**Pass 3 — post-processing:**
- `Classify` — assigns `StringType` (url, ip, path, secret, pkgpath, plain)
- `SplitConcatenatedURLs` — splits CMOVNE-pattern URL blobs at scheme boundaries
- `SuppressBlobs` — removes 512-byte fallback blobs already covered by extracted components
- `Deduplicate` — merges identical `(value, type)` pairs, unions `ReferencedBy` lists

---

## Adding a New Pipeline Stage

1. Create a package under `internal/` with your logic.
2. Add a field to `pkg/analyzer/Analyzer` to hold the stage result.
3. Add a method `(a *Analyzer) myStage() error` implementing the stage.
4. Register it in the `stages` slice in `Run()`.
5. Populate the result in `buildOutput()` and add the output type to `output.AnalysisResult`.

The `safeRun` wrapper handles panics automatically — your stage does not need to recover from panics itself.

---

## Adding a New Behavior Tag

Behavior tags are defined in `internal/behaviors/tagger.go`. Each rule specifies:

```go
{
    Tag:            "MY_TAG",
    CallTargets:    []string{"somepackage.SomeFunc"},  // call graph matches
    StringPatterns: []string{"keyword"},               // string content matches
}
```

A function receives the tag if any of its direct callees match `CallTargets` OR any of its associated strings contain a `StringPatterns` entry. Add your rule to the `rules` slice — no other changes required.

---

## Limitations

- **x86_64 only.** The string extractor, call graph builder, and CFG builder all use `golang.org/x/arch/x86/x86asm`. ARM64 support is planned for v0.2.0.
- **PE and ELF only.** Mach-O is planned for v0.2.0.
- **Standard Go toolchain only.** AGC and TinyGo binaries use different metadata layouts and are not supported.
- **Static analysis only.** No dynamic instrumentation or runtime tracing.
- **Type field recovery is partial.** `--types` recovers type names and kinds from rtype descriptors. Struct field layouts require following additional pointer chains and are not yet populated.

---

## Links

[Repository](https://github.com/muxover/goripper) · [Changelog](../CHANGELOG.md) · [Contributing](../CONTRIBUTING.md)

---

<p align="center">Made with ❤️ by Jax (@muxover)</p>
