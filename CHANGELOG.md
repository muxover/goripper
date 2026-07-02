# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **`decompile` relabeled `[EXPERIMENTAL]`** across the CLI, README, and this changelog. The C/Go output is a structural aid for reading control flow — **not a faithful or compilable reconstruction**. The v0.8.0 notes below oversold it as "compilable Go source reconstruction"; this correction sets honest expectations. A production-grade readable-pseudocode decompiler is the v0.9.0+ work.
- `goripper decompile` now prints an experimental-scope notice to stderr before emitting output.

## [0.8.0] - 2026-07-02

> **Correction (post-release):** this feature is **`[EXPERIMENTAL]`**. The emitted Go/C is a rough structural aid, **not faithful or compilable source** — the "compilable module" framing below overstated it. See `[Unreleased]` and the v0.9.0+ roadmap for the real decompiler.

### Added
- **Go source reconstruction** (`internal/decompile/go_emitter.go`, `--lang go` on `decompile`): `goripper decompile --lang go` emits a compilable Go module under the output directory. `go.mod` at the root declares `module recovered; go 1.21`. One subdirectory per user package; per-package `<pkg>.go` holds recovered function bodies; per-package `stubs.go` holds stub bodies for all unresolved external calls so `go build ./...` compiles.
- **14 runtime pattern lifts**: `runtime.gopanic` → `panic(v)`, `runtime.gorecover` → `recover()`, `runtime.newproc` → goroutine spawn via `go func(){}()`, `runtime.deferprocStack`/`runtime.deferproc` → `defer func(){}()`, `runtime.deferreturn` suppressed (implicit), `runtime.chansend1` → `ch <- v`, `runtime.chanrecv1` → `v = <-ch`, `runtime.makeslice`/`runtime.makemap`/`runtime.makechan` → the corresponding `make(...)` call, `runtime.convT2I`/`runtime.convT64`/`runtime.convTstring` → `any(v)`.
- **Go type mapping**: C typeprop types mapped to Go equivalents (`int64_t` → `int64`, `uint64_t` → `uint64`, `void*`/`*_type` → `unsafe.Pointer`, `GoString` → `string`, `GoSlice` → `[]byte`, `GoIface` → `any`, `error` → `error`).
- **Unused-variable suppression**: locals emitted as `var (v0 int64; ...)` followed by `_ = []any{v0, ...}` so SSA variables not read on all paths do not fail `go build`.
- **Unused-import guard**: `var _ unsafe.Pointer` in every package file keeps the `unsafe` import active.
- **Unused-label elision**: `collectReferencedLabels` pass emits only labels that are targets of a `goto` or branch — unreachable labels are dropped.
- **Go keyword collision avoidance**: `init` → `_init`; all Go keywords prefixed with `_` when they appear as recovered function names.
- **Duplicate name disambiguation**: functions sharing the same short name within a package are suffixed `_1`, `_2`, etc.
- **`func main()` injection**: the `main` package always receives `func main() {}` if no `main` function was recovered.
- **`--lang` flag** on `goripper decompile`: `--lang c` (default, unchanged) emits C skeletons; `--lang go` emits the Go module.

## [0.7.0] - 2026-06-21

### Added
- **`goripper decompile <binary>`** (`cmd/goripper/decompile_cmd.go`): **[EXPERIMENTAL]** lifts every user-defined function to three-address IR and emits C skeleton files. Output is structural, not yet fully readable — string constants, stack variables, and control flow reconstruction are planned for v0.8.0. Flags: `-o/--output` (output dir, default `out/`), `-v/--verbose`, `--max-funcs N`.
- **IR lifter** (`internal/ir/lift.go`, `internal/ir/lift_x86.go`, `internal/ir/lift_aarch64.go`): converts CFG basic blocks to three-address IR (`IRFunc` / `IRBlock` / `IRInstr`). x86_64 re-decodes raw bytes via `golang.org/x/arch/x86/x86asm`; ARM64 via `arm64asm`. Handles MOV/LEA/arithmetic/CMP+Jcc/CALL/RET; falls back to Intel-syntax comment for unknown opcodes.
- **SSA renaming** (`internal/ir/ssa.go`): block-level variable renaming — every write to a register variable (`_rax`, `_rbx`, …) creates a versioned name (`_rax_v0`, `_rax_v1`); phi-like assignments are inserted at multi-predecessor block entries.
- **Variable recovery** (`internal/ir/varrecov.go`): maps first-version param-register SSA names to `param0`/`param1`/…; detects loop-counter increments by small constant and names them `i`/`j`/`k`; remaining SSA vars become `v0`/`v1`/….
- **Type propagation** (`internal/ir/typeprop.go`): single-pass forward analysis assigns C types — `void*` for loads and `runtime.new*`/`runtime.make*` call returns, `int64_t` for arithmetic, known-signature types for `fmt.Println`, `runtime.makeslice`, etc.
- **C emitter** (`internal/decompile/c_emitter.go`): groups `IRFunc` results by package, writes one `.c` file per package plus `structs.h` (Go runtime type definitions: `GoString`, `GoSlice`, `GoIface`, `_type`, `error`) and `stubs.h` (extern declarations for all called external functions).
- `internal/ir` package with types `IRFunc`, `IRBlock`, `IRInstr`, `OpKind` (12 opcodes: Assign, Load, Store, Arith, Unary, Call, Phi, If, Goto, Return, Label, Comment).
- `internal/decompile` package with `Emit(funcs, Options)` entry point.

## [0.6.5] - 2026-06-19

### Fixed
- **Function package extraction — generics** (`internal/functions/extractor.go`): `slices.Sort[go.shape.string]` yielded package `"slices.breakPatternsCmpFunc[go.shape"`. Generic type-parameter suffixes are now stripped before dot-parsing.
- **Function package extraction — method entries** (`internal/functions/extractor.go`): pclntab method entries like `hash.Hash.Size` yielded `"hash.Hash"` instead of `"hash"`, misclassifying stdlib interface methods as user functions. Dotted names with no slash are now reduced to their root component.
- **Function package extraction — module path methods** (`internal/functions/extractor.go`): `internal/abi.Kind.String` yielded `"internal/abi.Kind"` instead of `"internal/abi"`. TypeName suffixes after the last `/` in a module path are now stripped.
- **`internal/*` packages classified as stdlib instead of runtime** (`internal/functions/classifier.go`): `runtimePrefixes` had `"internal/"` (trailing slash) so `HasPrefix` against `"internal//"` never matched. Changed to `"internal"` — `internal/abi`, `internal/cpu`, `internal/bytealg` etc. now correctly count as runtime.
- **Obfuscation false positives** (`internal/obfuscation/detect.go`): `FindDecryptorStubs` included stdlib and runtime functions in the high-fan-in heuristic. Now restricted to user-defined functions only.
- **Threat classifier accuracy** (`internal/classify/classifier.go`): ransomware, keylogger, and miner detection used raw string pattern scanning. All three now require explicit behavior tags from the tagger (`KEYLOG`, `MINER`, `FILE_READ`+`CRYPTO`+obfuscation for ransomware), eliminating false positives.
- **`trace --analyze` output mixing** (`cmd/goripper/trace_cmd.go`): raw events were written to the output destination before the merged analysis result. Events are now consumed silently; only the analysis result is written.
- **`trace --analyze --jsonl` not emitting JSONL** (`cmd/goripper/trace_cmd.go`): merged analysis was written as pretty-printed JSON. Now calls `output.WriteJSONL`.
- **`scan-dir` analyzing non-executables on Windows** (`cmd/goripper/scandir_cmd.go`): `isExecutable` returned `true` for every regular file. Now reads the first 4 bytes and only accepts PE (`MZ`) or ELF (`\x7fELF`) magic.
- **Hardcoded `v0.4.0` in script exports** (`internal/output/ida_writer.go`, `internal/output/ghidra_writer.go`, `internal/yara/generator.go`): IDA, Ghidra, and YARA outputs always claimed v0.4.0. Now uses `version.Version` injected at build time.
- **Windows tracer ASLR** (`internal/trace/windbg.go`, `cmd/goripper/trace_cmd.go`): breakpoints were placed at preferred image base addresses without accounting for ASLR. The tracer now reads `lpBaseOfImage` from `CREATE_PROCESS_DEBUG_EVENT` and slides all addresses accordingly.

## [0.6.0] - 2026-05-30

### Added
- **`goripper trace <binary>`** (`cmd/goripper/trace_cmd.go`): live execution tracing — attaches to a binary and streams function call, syscall, file, and network events as JSONL or a human-readable table. Flags: `--timeout`, `--jsonl`, `--analyze`, `--hot-path`, `-o`.
- **Linux backend** (`internal/trace/ebpf.go`): tracefs uprobe interface — attaches one uprobe per user function via `/sys/kernel/debug/tracing/uprobe_events`, reads from `trace_pipe`. Requires `CAP_BPF` or root, kernel 5.8+.
- **macOS backend** (`internal/trace/dtrace.go`): generates a dtrace D script from the pclntab function list, runs `dtrace -q`, parses output into the unified event format.
- **Windows backend** (`internal/trace/windbg.go`): Windows Debug API — `CreateProcess` with `DEBUG_PROCESS`, software INT3 breakpoints at every user function entry, single-step restore via trap flag in thread CONTEXT. No elevated privileges required.
- **Static + dynamic merging** (`internal/trace/merge.go`, `--analyze` flag and `--trace-data <file>` on `analyze`): merges a captured trace into `AnalysisResult`. Populates `FunctionOutput.CallCount`, `TotalTimeNs`, `IsHot` (top 10% by call count), and `AnalysisResult.ObservedNetworkAddrs`, `ObservedFilePaths`, `ObservedSyscalls`.
- **Hot path analysis** (`internal/trace/hotpath.go`, `--hot-path` flag): builds a call tree from sequential call/return events and prints it as an indented text tree with percentage annotations.
- `CallCount int`, `TotalTimeNs int64`, `IsHot bool` on `FunctionOutput`; `ObservedNetworkAddrs`, `ObservedFilePaths`, `ObservedSyscalls []string` on `AnalysisResult`.

## [0.5.0] - 2026-05-21

### Added
- **Function similarity hashing** (`internal/similarity`): each user function is hashed from its normalized instruction sequence (opcodes + indirect flag only; immediates and addresses stripped). Two functions differing only in constants or addresses produce the same hash. New field `FunctionOutput.SimilarityHash` (16-char hex FNV-64a) in all output formats.
- **`goripper compare <a> <b>`** (`cmd/goripper/compare_cmd.go`): compares two Go binaries by similarity hash, reporting shared functions, shared packages, functions unique to each binary, and an overall `SimilarityScore` (shared / max-total). `--json` for machine-readable output.
- **`goripper scan-dir <dir>`** (`cmd/goripper/scandir_cmd.go`): recursively finds and analyzes Go binaries in parallel. `--workers N` (default: CPU count), `--only-go` to skip non-Go files via gopclntab detection, `--json` / `--jsonl` (default) output, `--cluster` to group results by code similarity after scanning.
- **Malware family clustering** (`internal/cluster`): single-linkage clustering on pairwise similarity scores. Threshold 0.6 — pairs above this are merged. Reports cluster members, within-cluster minimum similarity, and shared packages.
- **Module dependency graph** (`internal/modules`, `--modules` on `analyze`): reads `debug/buildinfo` to recover the full Go module dependency tree with path, version, and used-function count per dependency. Cross-references against a bundled CVE table (7 entries for high-impact Go library CVEs). Results in `AnalysisResult.ModuleGraph` and JSONL `"type":"module_graph"` record.
- `ModuleGraphOutput`, `ModuleDependencyOutput` types in `internal/output`; `AnalysisResult.ModuleGraph`; `SummaryOutput.ModuleDeps`.
- `ModulesEnabled bool` on `pkg/analyzer.Options`.
- Module graph appears in JSON, JSONL, and text output (`=== Module Graph ===`).

## [0.4.0] - 2026-05-17

### Added
- **Taint analysis** (`internal/taint`, `--taint` flag on `analyze`): inter-procedural source-to-sink reachability via call graph. Sources: `os.Args`, `os.Stdin`, `os.Getenv`, `os.ReadFile`, `net/http.Request.Body`, `net.Conn.Read`, `bufio.Scanner`. Sinks: `os/exec.Command`, `syscall.Exec`, `database/sql.Query`, `os.WriteFile`, `net.Conn.Write`, `encoding/json.Unmarshal`, `html/template.Execute`. Propagates taint upward through CalledBy edges (conservative: callers of tainted functions may receive tainted return values). Results in `AnalysisResult.TaintFlows []TaintFlowOutput` with source, sink, call path, and confidence (`high`/`medium`/`low`). On binaries with >5000 user functions, emits a warning and suggests `--only-user`.
- **Threat classification** (`internal/classify`): rule-based classifier — no external API, no ML. Runs on every analysis. Classes: `RAT`, `DOWNLOADER`, `RANSOMWARE`, `C2_AGENT`, `KEYLOGGER`, `CRYPTOMINER`, `TOOL`, `UNKNOWN`. Signals: behavior tag union, string content patterns (mining pool URLs, keylog APIs, file-extension enumeration), URL count, concurrency. Results in `SummaryOutput.ThreatClass`, `ThreatConfidence`, `ThreatIndicators`.
- **YARA rule generation** (`internal/yara`, `goripper yara <binary>` subcommand): selects up to 30 high-signal strings (URL/secret > path > function names for obfuscated binaries), emits a valid YARA rule with PE or ELF format condition and `meta` block. Output to stdout or `-o <file>`.
- **IDA Pro export** (`--ida` flag on `analyze`): emits an IDAPython script that renames all pclntab functions to their Go names via `idc.set_name`, applies behavior tags as repeatable comments, and bookmarks concurrent functions. Standalone `.py`, no plugin required.
- **Ghidra export** (`--ghidra` flag on `analyze`): emits a GhidraScript (Java) that renames functions via `f.setName`, applies pre-comments with behavior tags, and annotates recovered struct types. Standalone, runs via Script Manager.
- `TaintFlowOutput` type in `internal/output`; `TaintFlows []TaintFlowOutput` on `AnalysisResult`; `TaintFlows int`, `ThreatClass`, `ThreatConfidence`, `ThreatIndicators` on `SummaryOutput`.
- `TaintEnabled bool` on `pkg/analyzer.Options`.
- Taint flows appear in JSON, JSONL (as `"type":"taint_flow"` records), and text output (`=== Taint Flows ===`). Threat class appears in summary and JSONL summary record.
- `--ida` and `--ghidra` are mutually exclusive with `--json`, `--jsonl`, `--html`, and each other.

## [0.3.0] - 2026-05-15

### Added
- **Section entropy** (`internal/entropy`): Shannon entropy per section with verdicts (`normal`, `compressed`, `encrypted`, `packed`). Packer detection via section name signatures (`UPX0/1/2`, `MPRESS1/2`, `.packed`, `.themida`). `SectionNames() []string` added to the `Binary` interface and all three loaders (PE, ELF, Mach-O).
- **Embedded asset detection** (`internal/assets`, `--assets` flag): finds path-like strings referenced by functions that call `embed.*` or `io/fs.*`. Reported as `embedded_assets` in all output formats.
- **Constant extraction** (`internal/constants`): scans x86_64 function bodies for interesting immediates — ports (known list), magic numbers (PE/ELF/ZIP/PNG/…), and crypto key sizes (16/24/32/48/64, only inside CRYPTO-tagged functions). Skipped on ARM64. Results in `FunctionOutput.constants`.
- **HTML report** (`--html` flag): self-contained dark-theme HTML with inline SVG entropy bar chart, filterable tables (functions, strings, embedded assets, types), and inline JS — no external dependencies. Mutually exclusive with `--json` and `--jsonl`.
- **Memory guard** (`--max-memory-mb N`): skips the CFG stage when the binary exceeds N MB and emits a warning. Default `0` = no limit (backward compatible).
- `ConstantInfo` type on `Function` and `FunctionOutput`; `SectionInfo`, `AssetOutput`, `ConstantOutput` types in `internal/output`; `Packer` field on `BinaryInfo`; `EmbeddedAssets` on `AnalysisResult` and `SummaryOutput`.

### Changed
- `.rodata` string scanner processes data in 4 MB chunks with 512-byte overlap — keeps peak allocation bounded on large binaries.
- Comment cleanup across all new packages: removed AI-style docstrings and WHAT comments.

## [0.2.0] - 2026-04-28

### Added
- **Arch-neutral disassembler** (`internal/disasm`): `Disassembler` interface + `New(arch)` factory.
  - x86_64 backend: CALL (direct/indirect), RET, JMP, all conditional branches, LEA/MOV RIP-relative (`OpAddrLoad`).
  - ARM64 backend: BL (direct call), BLR (indirect call), RET, B/B.cond, BR, CBZ, CBNZ, TBZ, TBNZ, ADRP+ADD pair and ADR (`OpAddrLoad`).
  - All downstream stages (call graph, CFG, string cross-reference) now use this interface — no more x86-only paths.
- **Mach-O support** (`internal/binary/macho_loader.go`): full `Binary` interface implementation for macOS binaries.
  - Fat/universal binary detection — prefers amd64 slice, falls back to arm64.
  - Canonical section name mapping (`.text` → `__text`, `.rodata` → `__rodata`/`__const`, etc.).
  - `FindGopclntab()` tries `__gopclntab` section first, then scans `__text`/`__rodata`/`__data`.
  - `binary.Open()` now auto-detects Mach-O magic (32-bit, 64-bit, fat — both endiannesses).
- **Real arch detection** in ELF and PE loaders: `Arch()` now reads `e_machine` (ELF) and `Machine` (PE) instead of hardcoding `"x86_64"`. ARM64 ELF and PE binaries are correctly identified.
- **Struct field recovery** (`internal/types`): when `--types` is enabled, struct `rtype` descriptors are now fully parsed — field names, field types (resolved from `Typ_` pointer), and byte offsets are populated in `RecoveredType.Fields`.
- **Interface implementation recovery** (`internal/types/itab.go`): `RecoverItabs()` reads the `.itablink` section (ELF/Mach-O) to produce a list of `(interface, concrete, itab_addr)` triples. Exposed in `AnalysisResult.Interfaces` and the text report under `=== Interface Implementations ===`.
- `InterfaceImplOutput` type in `internal/output`, `Interfaces []InterfaceImplOutput` on `AnalysisResult`, `InterfaceImpls` counter in `SummaryOutput`.
- `golang.org/x/arch` bumped from v0.24.0 to v0.26.0; Go toolchain bumped to 1.25.
- 14 new tests in `internal/disasm` (x86 + ARM64 instruction decoding) and Mach-O magic detection tests in `internal/binary`.

### Changed
- Comment cleanup across the entire codebase: removed AI-style docstrings and WHAT comments; only non-obvious WHY comments remain.
- `internal/callgraph/disasm.go` rewritten to use `Disassembler` interface — ARM64 call edges are now resolved.
- `internal/cfg/builder.go`, `types.go`, `pseudocode.go` rewritten to use `disasm.Instr` — CFG is now arch-neutral.

## [0.1.0] - 2026-03-29

### Added
- `callgraph --depth N` now limits callee count per node and appends a trailing
  `... and N more` line. The flag was accepted since v0.0.1-pre but had no effect.
- `docs/architecture.md`: pipeline flowchart, per-package table, data flow diagram,
  string extraction internals, how-to guides for adding stages and behavior tags.
- Cross-platform prebuilt binaries via GitHub Actions release pipeline:
  `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, `windows-amd64`.
  Each release includes `checksums.txt` (SHA-256).

### Fixed
- Dead code removed from `internal/types/recovery.go`: unused `patterns` loop that
  iterated over a slice and discarded every element.
- Duplicate `Run` doc comment removed from `pkg/analyzer/analyzer.go`.
- README status updated to `v0.1.0`; references to `v0.0.9-pre` and "coming in v0.1.0"
  removed.
- `.claude/` added to `.gitignore`.

## [0.0.9-pre] - 2026-03-26

### Added
- `--jsonl` flag on `analyze`: emits newline-delimited JSON (JSONL/ndjson), one object
  per line with a `"type"` discriminator — `binary_info`, `function`, `string`,
  `behavior`, `summary` (always last). Mutually exclusive with `--json`.
  New `internal/output/jsonl_writer.go` with 4 unit tests.
- `--max-functions N` flag on `analyze` and `functions`: caps the function list at N
  entries and appends `... and N more functions (use --max-functions 0 for full list)`.
  Default 0 = unlimited (backward compatible).
- `-q` / `--quiet` persistent flag on the root command (inherited by all subcommands):
  suppresses `===` section headers, grouping lines, binary info block, and summary
  block — emits data rows only. Useful for scripting and grep pipelines.
- Shell completion via cobra's built-in `completion` subcommand (`bash`, `zsh`, `fish`,
  `powershell`). Custom `ValidArgsFunction` for binary path args and
  `RegisterFlagCompletionFunc` for `--type` on `strings`. New `completion.go` (~35 lines).
- 3 new tests: `TestTextWriter_MaxFunctions_Truncates`,
  `TestTextWriter_MaxFunctions_NoTruncateWhenUnderLimit`, `TestTextWriter_Quiet_NoHeaders`.

### Fixed
- README fully rewritten: status reflects v0.0.9-pre, all commands documented (including
  `diff`, `version`, `completion`), all flags accurate, shell completion section added,
  limitations section added, `--depth` default corrected to `0` (was wrongly listed as `3`).
- `goripper diff` now accepts `--no-runtime` and `--only-user` flags — without these,
  comparing binaries built with different Go toolchains would produce thousands of
  spurious runtime function diffs.
- `--out <dir>` legacy flag removed from all subcommands; `-o / --output <file>` is the
  only output-redirection flag.
- `release.yml` now injects version, commit, and build date via `-ldflags -X` so
  `goripper version` shows real values in released binaries instead of `v0.0.0-dev`.

## [0.0.8-pre] - 2026-03-26

### Added
- `goripper diff <binary1> <binary2> [--json] [-o <file>]` subcommand: compares two Go
  binaries and reports added/removed/modified functions, new strings, and new behavior tags.
  New `internal/diff` package with `Compare(a, b *AnalysisResult) *Result` and 5 unit tests.
- `goripper version` subcommand: prints version, Go toolchain, OS/arch, commit, and build
  date. New `internal/version` package; vars injected at release time via ldflags.
- `-o / --output <file>` flag on all subcommands (`analyze`, `functions`, `strings`,
  `callgraph`, `diff`): write output to a file instead of stdout; path is printed to
  stderr so the terminal is not silent.

## [0.0.7-pre] - 2026-03-13

### Added
- `Deduplicate()` post-classification pass in `internal/strings`: entries with the
  same `(Value, Type)` pair are merged — `ReferencedBy` lists are unioned and the
  lower offset is kept. Result is sorted by offset ascending. Wired into the
  extraction pipeline after `SuppressBlobs`.
- Per-type string counts in `SummaryOutput`: `IPStrings`, `PathStrings`,
  `SecretStrings`, `PkgPathStrings`, `PlainStrings` fields (JSON + text).
  Summary line now reads:
  `Strings: N total  (U URLs · I IPs · P paths · S secrets · K pkg-paths · L plain)`
- `BinaryInfo.PclntabVersion` and `BinaryInfo.PclntabMagic` fields (JSON +
  text output). Text header shows `Pclntab: version=go1.20+  magic=0xFFFFFFF1`
  when pclntab was successfully parsed.
- `--min-len N` flag on `strings` and `analyze`: drop strings shorter than N bytes
  (post-extraction, independent of the hardcoded extraction minimum of 6).
- `--no-plain` flag on `strings` and `analyze`: suppress all `plain`-typed strings.
- `--min-refs N` flag on `strings` and `analyze`: drop strings with fewer than N
  user-package references in `ReferencedBy`.
- `--show-refs` flag on `strings` and `analyze`: print up to 3 referencing function
  names per string in text output, with `(+N more)` overflow indicator.
- 6 new tests: `TestDeduplicate_MergesReferencedBy`, `TestDeduplicate_PreservesOrder`,
  `TestDeduplicate_DifferentTypeSameValue`, `TestSummary_PerTypeStringCounts`,
  `TestBinaryInfo_PclntabShown`, `TestTextWriter_ShowRefs`.

## [0.0.6-pre] - 2026-03-13

### Added
- `safeRun` wrapper in `pkg/analyzer`: every pipeline stage after `loadBinary` now
  recovers from panics and appends a warning to `AnalysisResult.Warnings` instead of
  crashing — the pipeline always returns a partial result.
- Test coverage for 5 previously-zero packages: `internal/binary` (65%),
  `internal/behaviors` (82%), `internal/concurrency` (91%), `internal/functions` (78%),
  `internal/output` (74%).
- `internal/binary/binary_test.go` — 9 PE tests: Open, SectionVA, SectionData,
  IsPclntabMagic, ScanForPclntab, TextSectionRange, FindGopclntab, metadata, non-binary error.
- ELF fixture tests (5 tests) using a pre-built `linux/amd64` binary — ELF loader
  coverage runs on any OS without build tags.
- `testdata/hello/main.go`: minimal fixture with `net/http` call and URL constant.
- `testdata/build_elf_fixture.sh`: cross-compiles the fixture to `linux/amd64`.
- `testdata/fixture_linux_amd64`: pre-built ELF binary committed to the repo.
- `internal/binary/elf_test.go` (`//go:build linux`): Linux-native integration test.
- `internal/functions/functions_test.go`: classifier table + extract-on-test-binary (3 tests).
- `internal/behaviors/behaviors_test.go`: NETWORK, CRYPTO, EXEC, FILE_WRITE, FILE_READ,
  no-false-positive (6 tests).
- `internal/output/output_test.go`: sections, warnings, call graph, types, filters,
  JSON validity, round-trip (8 tests).
- `internal/concurrency/concurrency_test.go`: goroutine spawn, channel send,
  no-concurrency (3 tests).
- `pkg/analyzer/analyzer_test.go`: truncated-binary and zero-byte robustness tests.
- `Makefile` with `build`, `test`, `vet`, `lint`, and `check` targets.
- `paths-ignore` on CI and audit workflows — doc-only pushes no longer trigger runs.

### Fixed
- `staticcheck` S1011 in `cmd/goripper/main.go`: loop-over-append replaced with slice copy.
- `staticcheck` U1000 in `internal/strings/extractor_test.go`: removed unused `makeRodata`.

## [0.0.5-pre] - 2026-03-09

### Added
- `SuppressBlobs()` post-extraction pass: fallback blobs (512-byte printable runs) are
  removed when at least 2 individually-extracted component strings already start inside
  their byte range, eliminating Go stdlib error-message concatenations from output.
- `allStdlibRefs()` check in `CrossReference`: when every reference to a fallback blob
  belongs to a stdlib or runtime function, the blob cap is reduced from 512 to 200 bytes.

### Fixed
- `findLengthNearby` window widened from 15 instructions forward-only to
  30 instructions forward + 8 instructions backward, resolving length for
  patterns where the MOV immediate precedes the LEA in the instruction stream.
- `findLengthNearby` now rejects MOV instructions targeting extended registers
  (R8..R15 family), preventing the second string length in a CMOVNE pair from
  being misattributed to the first LEA.
- On a real-world test binary: plain strings > 100 bytes reduced from 522 to 40 (target was < 50).

## [0.0.4-pre] - 2026-03-07

### Added
- `internal/obfuscation` package: Shannon-entropy name analysis, package-prefix ratio,
  string-density check, and build-info absence combine into a 0.0–1.0 `ObfuscationScore`
  with a human-readable `ObfuscationLevel` (none/low/medium/high) and `ObfuscationIndicators`
  list. All fields added to `BinaryInfo` in JSON and text output.
- Heuristic function re-labeling (`obfuscation.Relabel`): when score > 0.5, garbled
  functions receive advisory tags such as `[suspected:network_connect]`,
  `[suspected:exec]`, `[suspected:encryption]`, `[suspected:goroutine_spawn]`,
  `[suspected:large_unknown]`. Clearly marked as heuristic.
- String decryptor stub detection (`obfuscation.FindDecryptorStubs`): small (< 100 byte)
  functions called by ≥ 50 callers are flagged as `[STRING_DECRYPTOR_STUB]` with caller
  count in the tag. XOR key recovery (`TryDecodeXOR`) attempts static extraction of
  single-byte XOR keys from stub bodies; key shown in JSON and text output.
- `DecryptorStubs []DecryptorStubOutput` field added to `AnalysisResult` JSON.
- `=== String Decryptor Stubs ===` section in text output when stubs are found.
- Stripped binary fallback: when gopclntab is absent or fails to parse, the analyzer
  records a `Warning` and falls back to generating synthetic `sub_0x<addr>` function
  names from the PE `.pdata` exception table. `SyntheticFunctions` count added to
  `SummaryOutput`. Text output marks synthetic functions with `[SYNTHETIC]`.
- `FunctionSource` field (`"pclntab"` / `"symbol_table"` / `"synthetic"`) on every
  `FunctionOutput` entry in JSON.
- `Warnings []string` field on `AnalysisResult` — non-fatal pipeline issues
  (pclntab absent, parse failure) are reported here rather than aborting analysis.
  Warnings printed at the top of text output.
- CGo boundary mapping (`behaviors.CGoBoundaries`): Go functions that directly call
  into CGo bridge functions are collected into `SummaryOutput.CgoCallSites`.
  `=== CGo Boundaries ===` section in text output when present.
  `CGOFunctions` count added to `SummaryOutput`.
- `debug/buildinfo` presence check: absence of build info is used as an obfuscation
  signal and reported in `ObfuscationIndicators`.
- 12 new tests across `internal/obfuscation` (entropy, scoring, relabeling) and
  `internal/behaviors` (CGo boundary detection).

### Fixed
- `parsePclntab` and `extractFunctions` no longer abort the pipeline when gopclntab
  is missing — they record a warning and continue with synthetic names.

## [0.0.3-pre] - 2026-03-03

### Added
- LEA string length inference: `CrossReference()` now scans forward up to 15 instructions
  from each LEA for a `MOV reg, <imm>` immediate in range `[6, 4096]`, using it as the
  exact string length — eliminates dirty 512-byte concatenated blobs when a clean length
  is available nearby.
- `SplitConcatenatedURLs()` post-classification pass: any URL-typed string that starts with
  `https?://` and embeds additional URL starts is split at each boundary — fully resolves
  the CMOVNE-pattern dirty blobs that LEA length inference cannot fix (e.g. four consecutive
  Discord webhook URLs now appear as four clean individual strings).
- URL classifier now matches any valid URI scheme (`[a-z][a-z0-9+\-.]*://`) instead of only
  `https?|ftp|ws|wss`, correctly classifying `mongodb://`, `redis://`, `git://`, etc.
- First test suite (17 tests): unit tests for string extraction (`extractor_test.go`) and
  classification (`classifier_test.go`); integration tests for pclntab parsing and the full
  analysis pipeline that run on the test binary itself.

### Fixed
- URL classifier no longer uses `strings.Contains(s, "://")` as a fallback — strings that
  merely embed a URL in the middle (error messages, format strings, dirty blobs) are no longer
  misclassified as URL. The URL type now exclusively matches strings that START with a URI scheme.
- Type recovery (`internal/types`) now returns `[]RecoveredType{}` instead of `nil` when no
  types are found, preventing nil-dereference in any caller that ranges over the result.
- PE/ELF pclntab scanner now requires `nfunc > 10` after header validation, reducing false
  positives from random data in stripped or unusual binaries.

### Shipped in commit 633d054 (included in this release)
- LEA-guided string extraction: `CrossReference()` emits strings that are referenced only
  from code (no `(ptr, len)` header pair in `.rodata`), enabling extraction of hardcoded
  URLs passed directly to HTTP clients (Discord webhook URLs, Instagram API endpoints).

## [0.0.2-pre] - 2026-03-03

### Added
- `StringTypePkgPath` classification for Go import paths (e.g. `golang.org/x/crypto`, `github.com/user/repo`).
- Relaxed URL detection: strings containing `"://"` are now classified as URL regardless of scheme format.

### Fixed
- String extraction rewritten to use Go string header `(ptr, len)` layout instead of a raw printable-byte scan — reduces output from 13,000+ garbage entries to ~500–2000 high-quality strings.
- LEA RIP-relative displacement now handled as signed `int64` — backward references no longer underflow to huge addresses and are correctly matched.
- CFG builder now skips synthesized non-code stubs (`go:buildid`, `go:cgo_*`, `_cgo_*`, `type:.*`) by name and by prologue validation, eliminating garbage disassembly blocks.
- Removed dead helper functions from `internal/gopclntab/detect.go` (`readUintPtr`, `readUint32`, `readUint64`, `readNullString`) left over from before the `debug/gosym` migration.

## [0.0.1-pre] - 2026-03-03

### Added
- Binary loader supporting PE (Windows `.exe`) and ELF (Linux) formats via `debug/pe` and `debug/elf`.
- Go version detection via `debug/buildinfo` with pclntab magic fallback.
- `gopclntab` parsing via `debug/gosym` — handles Go 1.2 through 1.24, all pclntab versions.
- Function extraction: name, address, size for every function in the binary.
- Package classification: `runtime`, `stdlib`, `user`, `cgo` categories.
- Call graph construction via x86 CALL instruction disassembly (`golang.org/x/arch/x86/x86asm`).
- String extraction from `.rodata` with cross-reference to functions via LEA/MOV RIP-relative scanning.
- String classification: URL, IP, file path, secret, Go package path, plain text.
- Type recovery from Go runtime `rtype` descriptors (struct names, kinds).
- Concurrency detection: goroutine spawns, channel ops, mutex usage.
- Behavior tagging: NETWORK, CRYPTO, FILE_WRITE, FILE_READ, EXEC, REGISTRY, HTTP, DNS, MEMORY tags.
- CFG basic block splitting and pseudocode emission (optional, `--cfg` flag).
- JSON output mode (`--json` flag).
- Human-readable text report with grouped, sorted output.
- CLI subcommands: `analyze`, `functions`, `strings`, `callgraph`.
- Filters: `--only-user`, `--no-runtime`, `--pkg`, `--type`, `--depth`.

[Unreleased]: https://github.com/muxover/goripper/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/muxover/goripper/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/muxover/goripper/compare/v0.6.5...v0.7.0
[0.6.5]: https://github.com/muxover/goripper/compare/v0.6.0...v0.6.5
[0.6.0]: https://github.com/muxover/goripper/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/muxover/goripper/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muxover/goripper/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muxover/goripper/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muxover/goripper/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muxover/goripper/compare/v0.0.9-pre...v0.1.0
[0.0.9-pre]: https://github.com/muxover/goripper/compare/v0.0.8-pre...v0.0.9-pre
[0.0.8-pre]: https://github.com/muxover/goripper/compare/v0.0.7-pre...v0.0.8-pre
[0.0.7-pre]: https://github.com/muxover/goripper/compare/v0.0.6-pre...v0.0.7-pre
[0.0.6-pre]: https://github.com/muxover/goripper/compare/v0.0.5-pre...v0.0.6-pre
[0.0.5-pre]: https://github.com/muxover/goripper/compare/v0.0.4-pre...v0.0.5-pre
[0.0.4-pre]: https://github.com/muxover/goripper/compare/v0.0.3-pre...v0.0.4-pre
[0.0.3-pre]: https://github.com/muxover/goripper/compare/v0.0.2-pre...v0.0.3-pre
[0.0.2-pre]: https://github.com/muxover/goripper/compare/v0.0.1-pre...v0.0.2-pre
[0.0.1-pre]: https://github.com/muxover/goripper/releases/tag/v0.0.1-pre
