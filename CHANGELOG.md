# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- v0.0.8-pre: TBD -->

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

[Unreleased]: https://github.com/muxover/goripper/compare/v0.0.7-pre...HEAD
[0.0.7-pre]: https://github.com/muxover/goripper/compare/v0.0.6-pre...v0.0.7-pre
[0.0.6-pre]: https://github.com/muxover/goripper/compare/v0.0.5-pre...v0.0.6-pre
[0.0.5-pre]: https://github.com/muxover/goripper/compare/v0.0.4-pre...v0.0.5-pre
[0.0.4-pre]: https://github.com/muxover/goripper/compare/v0.0.3-pre...v0.0.4-pre
[0.0.3-pre]: https://github.com/muxover/goripper/compare/v0.0.2-pre...v0.0.3-pre
[0.0.2-pre]: https://github.com/muxover/goripper/compare/v0.0.1-pre...v0.0.2-pre
[0.0.1-pre]: https://github.com/muxover/goripper/releases/tag/v0.0.1-pre
