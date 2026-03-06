# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/muxover/goripper/compare/v0.0.1-pre...HEAD
[0.0.1-pre]: https://github.com/muxover/goripper/releases/tag/v0.0.1-pre
