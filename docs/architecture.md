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
│  binary loader  │  PE, ELF, or Mach-O — auto-detected from magic bytes
└────────┬────────┘  arch detected from ELF e_machine / PE Machine field
         │
         ▼
┌─────────────────┐
│    disasm       │  internal/disasm.New(arch) → x86_64 or arm64 backend
└────────┬────────┘  single Disassembler interface used by all downstream stages
         │
         ▼
┌─────────────────┐
│   gopclntab     │  debug/gosym — function names, entry PCs, sizes (Go 1.2–1.25)
└────────┬────────┘       │ absent → synthetic sub_0x<addr> from .pdata
         │
         ▼
┌─────────────────┐
│   functions     │  extract + classify (runtime / stdlib / user / cgo)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    strings      │  .rodata header pairs + LEA/ADRP+ADD cross-reference
└────────┬────────┘       → classify → split URLs → suppress blobs → deduplicate
         │
         ▼
┌─────────────────┐
│   call graph    │  arch-neutral CALL disassembly (x86 CALL/JMP, arm64 BL/BLR)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      CFG        │  basic block splitting + pseudocode emission (--cfg only)
└────────┬────────┘  skipped when binary.Size() > MaxMemoryMB * 1024 * 1024
         │
         ▼
┌─────────────────┐
│  type recovery  │  rtype descriptor scan; struct field layout; itab recovery
└────────┬────────┘  (--types only)
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
│   constants     │  per-function immediate scan: ports, magic numbers, key sizes
└────────┬────────┘  x86_64 only; runs after behaviors so CRYPTO tag is set
         │
         ▼
┌─────────────────┐
│  obfuscation    │  entropy + prefix ratio + string density → 0.0–1.0 score
└────────┬────────┘       → decryptor stub detection → XOR key recovery → relabel
         │
         ▼
┌─────────────────┐
│    entropy      │  Shannon entropy per section → verdict; packer name detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    assets       │  embed/io/fs callgraph → embedded file path detection (--assets)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     taint       │  inter-procedural source→sink reachability via CalledBy edges (--taint)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    classify     │  rule-based threat classification from tag union + string signals
└────────┬────────┘  always runs; no flag required
         │
         ▼
┌─────────────────┐
│   similarity    │  per-user-function normalized opcode hash (FNV-64a, always runs)
└────────┬────────┘       → FunctionOutput.SimilarityHash; used by compare + scan-dir --cluster
         │
         ▼
┌─────────────────┐
│    modules      │  debug/buildinfo → module dependency graph + CVE cross-ref (--modules)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AnalysisResult │  output.AnalysisResult — JSON / JSONL / text / HTML / IDA / Ghidra
└─────────────────┘

(optional post-analysis: --trace-data merges a captured trace into AnalysisResult)
```

---

## Package Reference

| Package | Path | Owns | Key types |
|---------|------|------|-----------|
| binary | `internal/binary` | PE, ELF, and Mach-O loading; format + arch detection | `Binary` (interface), `PEBinary`, `ELFBinary`, `MachoBinary` |
| disasm | `internal/disasm` | Arch-neutral instruction decoder (x86_64 + ARM64) | `Disassembler` (interface), `Instr`, `Op` |
| gopclntab | `internal/gopclntab` | PC-line table parsing via `debug/gosym` | `ParsedPclntab`, `PclntabVersion` |
| functions | `internal/functions` | Extraction, deduplication, package classification | `Function`, `PackageKind`, `FunctionSource` |
| strings | `internal/strings` | `.rodata` extraction, LEA/ADRP cross-reference, classification | `ExtractedString`, `StringType` |
| callgraph | `internal/callgraph` | Arch-neutral CALL disassembly, edge building, addr→name resolution | `CallGraph`, `Edge`, `AddrName` |
| cfg | `internal/cfg` | Basic block splitting, branch resolution, pseudocode | `CFG`, `BasicBlock` |
| types | `internal/types` | rtype recovery, struct field parsing, itab recovery | `RecoveredType`, `TypeKind`, `FieldDescriptor`, `InterfaceImpl` |
| concurrency | `internal/concurrency` | Goroutine / channel / sync pattern detection | `ConcurrencyPattern` |
| behaviors | `internal/behaviors` | Rule-based behavior tagging, CGo boundary mapping | `Rule`, `Tag` |
| obfuscation | `internal/obfuscation` | Garble scoring, decryptor stub detection, XOR recovery | `Result`, `StubMatch` |
| entropy | `internal/entropy` | Shannon entropy per section; packer signature detection | `SectionInfo` |
| assets | `internal/assets` | Embedded asset path detection via callgraph | `EmbeddedAsset` |
| constants | `internal/constants` | Per-function interesting-immediate extraction (x86_64) | `ConstantInfo` |
| taint | `internal/taint` | Inter-procedural source-to-sink reachability via call graph | `TaintFlow` |
| classify | `internal/classify` | Rule-based threat classification (RAT, DOWNLOADER, RANSOMWARE, …) | `Result`, `Input`, `Class` |
| yara | `internal/yara` | YARA rule generation from high-signal strings | — |
| similarity | `internal/similarity` | Per-function normalized instruction hash; cross-binary comparison | `CompareResult` |
| cluster | `internal/cluster` | Single-linkage clustering on pairwise similarity scores | `Group` |
| modules | `internal/modules` | Module dependency graph via `debug/buildinfo`; bundled CVE table | `ModuleInfo`, `Dependency` |
| trace | `internal/trace` | Live tracing: event types, Linux/macOS/Windows backends, static+dynamic merge, hot path | `Event`, `Tracer`, `Options` |
| ir | `internal/ir` | Three-address IR lifter (x86_64 + ARM64), SSA renaming, variable recovery, type propagation | `IRFunc`, `IRBlock`, `IRInstr`, `OpKind` |
| decompile | `internal/decompile` | C emitter: groups IRFuncs by package, emits `.c` + `structs.h` + `stubs.h` | `Options` |
| analyzer | `pkg/analyzer` | Pipeline orchestration, crash-safe stage runner | `Analyzer`, `Options` |
| output | `internal/output` | JSON, JSONL, text, HTML, IDA, and Ghidra writers | `AnalysisResult`, `TextOptions` |
| diff | `internal/diff` | Binary-to-binary comparison | `Result` |
| version | `internal/version` | Build-time version vars (ldflags injection) | `Version`, `Commit`, `Date` |

---

## Data Flow

The central type is `output.AnalysisResult`. The analyzer builds it in `buildOutput()` after all pipeline stages complete:

```
internal/functions.Function       →  output.FunctionOutput
internal/strings.ExtractedString  →  output.StringOutput
internal/callgraph.CallGraph      →  map[string][]string
internal/types.RecoveredType      →  output.TypeOutput
internal/types.InterfaceImpl      →  output.InterfaceImplOutput
internal/obfuscation.StubMatch    →  output.DecryptorStubOutput
internal/entropy.SectionInfo      →  output.SectionInfo  (+ BinaryInfo.Packer)
internal/assets.EmbeddedAsset     →  output.AssetOutput
internal/functions.ConstantInfo   →  output.ConstantOutput  (nested in FunctionOutput)
internal/taint.TaintFlow          →  output.TaintFlowOutput
internal/classify.Result          →  SummaryOutput.ThreatClass / ThreatConfidence / ThreatIndicators
internal/similarity hashes        →  FunctionOutput.SimilarityHash
internal/modules.ModuleInfo       →  output.ModuleGraphOutput  (+ SummaryOutput.ModuleDeps)
internal/trace.[]Event            →  FunctionOutput.CallCount / TotalTimeNs / IsHot
                                      + AnalysisResult.ObservedNetworkAddrs / ObservedFilePaths / ObservedSyscalls
(aggregated counts)               →  output.SummaryOutput
```

`AnalysisResult` is the only thing that crosses the `internal/` boundary into `cmd/` and `pkg/`. All output writers (`WriteJSON`, `WriteJSONL`, `WriteText`, `WriteHTML`) consume it.

---

## Binary Interface

`internal/binary.Binary` is the abstraction over PE, ELF, and Mach-O:

```go
type Binary interface {
    Path() string
    Format() string        // "PE", "ELF", or "Mach-O"
    Arch() string          // "x86_64", "arm64", "x86", "arm"
    GoVersion() string
    ImageBase() uint64
    Size() int64
    Section(name string) ([]byte, error)
    SectionVA(name string) (uint64, error)
    SectionNames() []string
    TextSectionRange() (uint64, uint64, error)
    FindGopclntab() ([]byte, uint64, error)
    Close() error
}
```

`binary.Open()` auto-detects the format from the file magic (ELF `\x7FELF`, PE `MZ`, Mach-O `0xFEEDFACE`/`0xFEEDFACF`/`0xCAFEBABE` and their byte-swapped variants) and returns the appropriate implementation. All downstream stages call only this interface.

---

## Disassembler Interface

`internal/disasm.Disassembler` decouples all analysis stages from specific architectures:

```go
type Disassembler interface {
    Arch() string
    Decode(data []byte, va uint64) (Instr, error)
}

type Instr struct {
    VA       uint64
    Len      int
    Op       Op       // OpCall, OpRet, OpCondBranch, OpUncondBranch, OpAddrLoad, OpOther
    Target   uint64   // branch/call target VA; 0 if indirect
    AddrRef  uint64   // data VA for OpAddrLoad (LEA, ADRP+ADD, ADR)
    Indirect bool     // true for register-target calls/jumps
}
```

`disasm.New(arch)` returns the right backend. ARM64 ADRP+ADD pairs are decoded as a single `OpAddrLoad` instruction with the full resolved address in `AddrRef`.

---

## String Extraction

String extraction runs in three passes:

`.rodata` is scanned in 4 MB chunks with a 512-byte overlap between adjacent chunks, keeping peak allocation bounded on large binaries without affecting extraction results.

**Pass 1 — header pairs:** Scans `.rodata` for Go string header `(ptr, len)` pairs. A valid header has a pointer into `.rodata` and a length in `[6, 4096]`.

**Pass 2 — disassembler cross-reference:** Decodes `.text` using the arch-neutral `Disassembler`, looking for `OpAddrLoad` instructions (LEA on x86, ADRP+ADD/ADR on ARM64) that point into `.rodata`. For x86, scans ±30 instructions for a `MOV reg, imm` to infer exact string length; ARM64 length inference is skipped (ADRP addresses are typically passed with explicit length args).

**Pass 3 — post-processing:**
- `Classify` — assigns `StringType` (url, ip, path, secret, pkgpath, plain)
- `SplitConcatenatedURLs` — splits CMOVNE-pattern URL blobs at scheme boundaries
- `SuppressBlobs` — removes 512-byte fallback blobs already covered by extracted components
- `Deduplicate` — merges identical `(value, type)` pairs, unions `ReferencedBy` lists

---

## Type Recovery

Type recovery runs in two parts when `--types` is enabled:

**rtype recovery:** Scans `.typelinks` (ELF/Mach-O) for `int32` offsets into `.rodata` pointing at `rtype` descriptors. For each rtype, reads the 48-byte header, extracts the type name (via `nameOff`), and for struct kinds additionally parses the `structType` layout to extract field names, types, and byte offsets.

**Itab recovery:** Reads the `.itablink` section, which contains an array of pointers to `itab` structs. Each itab holds a pointer to an `interfacetype` and a pointer to the concrete `rtype`. Both are resolved to type names, producing `InterfaceImpl{Interface, Concrete, ItabAddr}` records. These appear in `AnalysisResult.Interfaces`.

---

## Section Entropy

`internal/entropy.Calculate(data)` computes Shannon entropy H = -Σ p·log₂(p) over the byte frequency distribution. `Verdict(H)` maps the result:

| Range | Verdict |
|-------|---------|
| H < 1.0 | `packed` |
| H ≤ 6.5 | `normal` |
| H ≤ 7.2 | `compressed` |
| H > 7.2 | `encrypted` |

`DetectPacker(sectionNames)` checks for known packer section name signatures (`UPX0/1/2`, `MPRESS1/2`, `.packed`, `.themida`) and returns a packer label when found.

---

## Constant Extraction

`internal/constants.Extract` runs on x86_64 user functions **after** behavior tagging so the `CRYPTO` tag is already set. It decodes each instruction and checks immediates against three tables:

- **port** — known network ports (21, 22, 80, 443, 4444, 31337, …)
- **magic** — known binary magic numbers (PE `0x5A4D`, ELF `0x7F454C46`, ZIP `0x504B0304`, …)
- **crypto_key_size** — AES/SHA key sizes (16, 24, 32, 48, 64) — only emitted when the function carries the `CRYPTO` tag

ARM64 is explicitly skipped: ADRP immediates and other ARM64 encoded values are not reliably distinguishable from normal arithmetic without full semantic analysis.

---

## Embedded Asset Detection

`internal/assets.Detect` takes the full string list and the call graph. It first identifies functions that call into `embed.*` or `io/fs.*` (the `findEmbedUsers` pass), then filters strings to those that look like file paths (has extension, not absolute, no shell-special chars, 4–256 chars) and are referenced by one of those embed-using functions.

---

## Taint Analysis

`internal/taint.Analyze(calls, calledBy)` performs inter-procedural source-to-sink reachability using the call graph.

1. **Seed**: find all functions that directly call a source API (e.g. `os.Args`, `net/http.(*Request).`). These are "tainted producers."
2. **Propagate**: BFS upward through `CalledBy` edges. A caller of a tainted function may receive tainted return values — conservative but avoids register-level tracking.
3. **Terminate**: when a reachable function also calls a sink API (e.g. `os/exec.Command`), emit a `TaintFlow` with the full call path.

Confidence is derived from path length: `high` (≤2 hops), `medium` (3–4), `low` (5–8). BFS is capped at 8 hops to prevent combinatorial explosion on densely-connected graphs.

The stage is gated by `Options.TaintEnabled` and skipped unless `--taint` is passed. On binaries with >5000 user functions, a warning is emitted.

---

## Threat Classification

`internal/classify.Classify(Input)` applies a fixed rule table over the union of all behavior tags and string content — no ML, no external calls.

`Input` is assembled in `buildOutput()` after all pipeline stages complete. It contains the tag union across all functions, all extracted string values, the URL count, concurrency flag, and the obfuscation score.

The classifier checks ordered match conditions. The first matching rule wins:

| Class | Match condition |
|-------|----------------|
| `RAT` | NETWORK ∧ EXECUTION ∧ (FILE_READ ∨ FILE_WRITE) ∧ concurrency |
| `DOWNLOADER` | NETWORK ∧ FILE_WRITE ∧ URL > 0 ∧ ¬EXECUTION |
| `RANSOMWARE` | CRYPTO ∧ FILE_WRITE ∧ file-extension strings present |
| `C2_AGENT` | NETWORK ∧ DNS ∧ CRYPTO ∧ concurrency |
| `KEYLOGGER` | FILE_WRITE ∧ keylog string patterns |
| `CRYPTOMINER` | NETWORK ∧ mining pool URL strings |
| `TOOL` | ¬NETWORK ∧ ¬EXECUTION ∧ ¬MEMORY |
| `UNKNOWN` | no rule matched |

The result is always populated. A binary with no behavior tags receives `TOOL` with `low` confidence.

---

## Adding a New Pipeline Stage

1. Create a package under `internal/` with your logic.
2. Add a field to `pkg/analyzer/Analyzer` to hold the stage result.
3. Add a method `(a *Analyzer) myStage() error` implementing the stage.
4. Register it in the `stages` slice in `Run()`.
5. Populate the result in `buildOutput()` and add the output type to `output.AnalysisResult`.

The `safeRun` wrapper handles panics automatically — your stage does not need to recover from panics itself.

---

## Decompile Pipeline (`goripper decompile`)

`goripper decompile <binary>` lifts each user-defined function to a C approximation. The output is a human-readable analysis aid, not guaranteed to compile without stub editing.

```
┌─────────────────┐
│   binary open   │  gobinary.Open → arch detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   pclntab parse │  gopclntab.Parse → function list
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  classify funcs │  functions.Extract + Classify → filter PackageUser only
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   CFG build     │  cfg.Build per function (falls back to stub on failure)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   IR lift       │  ir.LiftArch → three-address IR (x86_64 or ARM64)
└────────┬────────┘       re-decodes raw bytes via x86asm/arm64asm for full operand detail
         │
         ▼
┌─────────────────┐
│   SSA rename    │  ir.RenameVars → versioned names (_rax_v0, _rax_v1, …)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  var recovery   │  ir.RecoverVars → param0/param1, i/j/k counters, v0/v1 locals
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  type propagate │  ir.PropTypes → forward C type assignment (int64_t, void*, GoString)
└────────┬────────┘       seeded from goRuntimeSigs + heuristics
         │
         ▼
┌─────────────────┐
│   C emit        │  decompile.Emit → one .c per package + structs.h + stubs.h
└─────────────────┘
```

### IR Instruction Set

`IRInstr.Op` (type `OpKind`) covers the operations needed to express x86_64 and ARM64 semantics in three-address form:

| Op | Meaning | Fields used |
|----|---------|-------------|
| `OpAssign` | `dst = src[0]` | Dst, Src[0] |
| `OpLoad` | `dst = *src[0]` | Dst, Src[0] |
| `OpStore` | `*dst = src[0]` | Dst, Src[0] |
| `OpArith` | `dst = src[0] <op> src[1]` | Dst, Src, Meta (add/sub/mul/…) |
| `OpUnary` | `dst = <op> src[0]` | Dst, Src[0], Meta (neg/not) |
| `OpCall` | `dst = Target(src…)` | Dst, Target, Src |
| `OpPhi` | `dst = phi(src…)` | Dst, Src |
| `OpIf` | `if cond goto Label else Label2` | Meta (cond expr), Label, Label2 |
| `OpGoto` | `goto Label` | Label |
| `OpReturn` | `return src…` | Src |
| `OpLabel` | `Label:` | Label |
| `OpComment` | `/* Meta */` | Meta |

### Output Layout

```
out/
  main.c          — user package "main"
  net_http.c      — package "net/http" (sanitized to "net_http")
  structs.h       — GoString, GoSlice, GoIface, _type, error
  stubs.h         — extern declarations for all called external functions
```

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

- Standard Go toolchain only — AGC and TinyGo binaries use different metadata layouts.
- CFG pseudocode is slow on binaries with 10,000+ functions.

---

## Links

[Repository](https://github.com/muxover/goripper) · [Changelog](../CHANGELOG.md) · [Contributing](../CONTRIBUTING.md)

---

<p align="center">Made with ❤️ by Jax (@muxover)</p>
