# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- v0.0.4-pre: Garble/Obfuscation Detection & Stripped Binary Resilience -->
<!-- v0.0.5-pre: General-purpose CMOVNE plain-blob splitting -->

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

[Unreleased]: https://github.com/muxover/goripper/compare/v0.0.3-pre...HEAD
[0.0.3-pre]: https://github.com/muxover/goripper/compare/v0.0.2-pre...v0.0.3-pre
[0.0.2-pre]: https://github.com/muxover/goripper/compare/v0.0.1-pre...v0.0.2-pre
[0.0.1-pre]: https://github.com/muxover/goripper/releases/tag/v0.0.1-pre
