# GoRipper

<div align="center">

[![CI](https://github.com/muxover/goripper/actions/workflows/ci.yml/badge.svg)](https://github.com/muxover/goripper/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/muxover/goripper.svg)](https://pkg.go.dev/github.com/muxover/goripper)
[![Go Report Card](https://goreportcard.com/badge/github.com/muxover/goripper)](https://goreportcard.com/report/github.com/muxover/goripper)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/muxover/goripper)](https://github.com/muxover/goripper/releases)

**Extract behavioral intelligence from compiled Go binaries.**

</div>

---

GoRipper analyzes compiled Go binaries (PE `.exe`, ELF, and Mach-O) without source code. It parses Go-specific metadata, disassembles code, extracts strings, recovers types and interface implementations, detects concurrency patterns, and tags suspicious behaviors — outputting structured JSON or human-readable reports. Built for security researchers, reverse engineers, and incident responders.

> **Status:** `v0.2.0` — ARM64 support, Mach-O loader, arch-neutral disassembler abstraction, struct field recovery, and interface implementation recovery from `.itablink`.

---

## Features

- **Function Extraction** — Parses `gopclntab` via Go's standard library (`debug/gosym`) to recover all function names, addresses, and sizes for Go 1.2 through 1.25.
- **Package Classification** — Automatically separates `runtime`, `stdlib`, `user`, and `cgo` packages.
- **Multi-format Support** — PE (Windows), ELF (Linux), and Mach-O (macOS) including fat/universal binaries.
- **Multi-arch Support** — x86_64 and ARM64 (including ADRP+ADD address materialization).
- **Call Graph** — Arch-neutral disassembler maps every `CALL` edge across the binary; ARM64 BL/BLR and x86 CALL/JMP fully supported.
- **String Extraction** — Scans `.rodata` and cross-references strings to functions via LEA/ADRP+ADD instruction analysis.
- **String Classification** — Categorizes strings as URLs, IPs, file paths, secrets, Go package paths, or plain text.
- **Obfuscation Detection** — Scores each binary for garble/obfuscation (0.0–1.0) using entropy, prefix ratio, string density, and build-info signals.
- **Binary Diff** — Compares two Go binaries: added/removed/modified functions, new strings, new behavior tags.
- **Stripped Binary Fallback** — Falls back to `.pdata` exception table when gopclntab is absent, generating synthetic `sub_0x<addr>` names.
- **Type Recovery** — Parses Go runtime `rtype` descriptors to recover struct names, kinds, and struct field layouts (name, type, byte offset).
- **Interface Recovery** — Reads `.itablink` to map every concrete type to the interface it satisfies.
- **Concurrency Detection** — Identifies goroutine spawns, channel operations, and mutex usage via call graph patterns.
- **Behavior Tagging** — Tags functions with `NETWORK`, `CRYPTO`, `FILE_WRITE`, `FILE_READ`, `EXEC`, `REGISTRY`, `HTTP`, `DNS`, and more.
- **CFG + Pseudocode** — Builds basic-block control flow graphs and emits simplified pseudocode per function (optional, slow on large binaries).
- **JSON + JSONL + Text Output** — Machine-readable JSON, streaming JSONL for pipelines, or analyst-friendly tabular text.

---

## Installation

**From source (requires Go 1.25+):**

```bash
go install github.com/muxover/goripper/cmd/goripper@latest
```

**Build locally:**

```bash
git clone https://github.com/muxover/goripper.git
cd goripper
go build -o goripper ./cmd/goripper/
```

---

## Quick Start

```bash
# Full analysis — human-readable report
goripper analyze ./malware.exe

# Full analysis — JSON output
goripper analyze ./malware.exe --json

# Stream output line-by-line (pipe to jq, grep, etc.)
goripper analyze ./malware.exe --jsonl | jq 'select(.type=="string" and .string_type=="url")'

# Show only user-written functions (no runtime/stdlib noise)
goripper functions ./malware.exe --only-user

# Cap output to 50 functions
goripper functions ./malware.exe --max-functions 50

# Extract URL strings only
goripper strings ./malware.exe --type url

# Suppress headers for scripting
goripper strings ./malware.exe --quiet

# Compare two binaries — see what changed
goripper diff ./v1.exe ./v2.exe

# Print version and build info
goripper version
```

**Example output:**

```
=== GoRipper Analysis Report ===
Binary:     malware.exe
Format:     PE
Arch:       x86_64
Go Version: go1.22.1
Pclntab:    version=go1.20+  magic=0xFFFFFFF1
Size:       8388608 bytes
Obfuscation: 0.12 [none]

=== Summary ===
Total functions:      5729
  User:               312
  Stdlib:             1847
  Runtime:            3570
Suspicious:           61
Concurrent:           24
Strings:              847 total  (12 URLs · 3 IPs · 28 paths · 1 secrets · 41 pkg-paths · 762 plain)
Recovered types:      203
```

---

## Commands

| Command | Description |
|---------|-------------|
| `goripper analyze <binary>` | Full pipeline — functions, strings, call graph, types, behaviors |
| `goripper functions <binary>` | List functions with addresses, sizes, and tags |
| `goripper strings <binary>` | Extract and classify strings from `.rodata` |
| `goripper callgraph <binary>` | Print the call graph as a tree |
| `goripper diff <binary1> <binary2>` | Compare two binaries — added/removed/modified functions and strings |
| `goripper version` | Print version, Go toolchain, OS/arch, commit, and build date |
| `goripper completion <shell>` | Generate shell completion for `bash`, `zsh`, `fish`, or `powershell` |

---

## Flags

### Global (all commands)

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output <file>` | stdout | Write output to a file instead of stdout |
| `-q`, `--quiet` | `false` | Suppress headers and decorative output; emit data rows only |
| `-v`, `--verbose` | `false` | Show pipeline stage timing and debug info |

### `analyze`

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit JSON |
| `--jsonl` | `false` | Emit newline-delimited JSON (streaming; mutually exclusive with `--json`) |
| `--no-runtime` | `false` | Exclude runtime functions from output |
| `--only-user` | `false` | Show only user-written package functions |
| `--max-functions N` | `0` | Cap function list at N entries (0 = unlimited) |
| `--cfg` | `false` | Build CFG and emit pseudocode (slow on large binaries) |
| `--types` | `false` | Run type recovery from runtime `rtype` descriptors |
| `--min-len N` | `0` | Drop strings shorter than N bytes |
| `--no-plain` | `false` | Suppress plain-text strings from output |
| `--min-refs N` | `0` | Drop strings with fewer than N user-code references |
| `--show-refs` | `false` | Show up to 3 referencing function names per string |

### `functions`

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit JSON |
| `--only-user` | `false` | Filter to user packages only |
| `--no-runtime` | `false` | Exclude `runtime.*` functions |
| `--pkg <name>` | `""` | Filter to a specific package name |
| `--max-functions N` | `0` | Cap function list at N entries (0 = unlimited) |
| `--cfg` | `false` | Generate pseudocode |

### `strings`

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit JSON |
| `--type <type>` | `""` | Filter: `url`, `ip`, `path`, `secret`, `pkgpath` |
| `--min-len N` | `0` | Drop strings shorter than N bytes |
| `--no-plain` | `false` | Suppress plain-text strings |
| `--min-refs N` | `0` | Drop strings with fewer than N user-code references |
| `--show-refs` | `false` | Show referencing functions per string |

### `callgraph`

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit JSON |
| `--no-runtime` | `false` | Exclude runtime nodes |
| `--depth N` | `0` | Maximum call depth to display (0 = unlimited) |

### `diff`

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit JSON diff |
| `--no-runtime` | `false` | Exclude runtime functions from diff |
| `--only-user` | `false` | Diff only user-written package functions |
| `-o`, `--output <file>` | stdout | Write diff output to file |

---

## Shell Completion

```bash
# bash
goripper completion bash >> ~/.bashrc

# zsh
goripper completion zsh >> ~/.zshrc

# fish
goripper completion fish > ~/.config/fish/completions/goripper.fish

# powershell
goripper completion powershell >> $PROFILE
```

---

## Project Layout

```
goripper/
├── cmd/goripper/          # CLI entry point (cobra)
├── pkg/analyzer/          # Pipeline orchestrator
└── internal/
    ├── binary/            # PE, ELF, and Mach-O loaders; format + arch detection
    ├── disasm/            # Arch-neutral disassembler (x86_64 + ARM64)
    ├── diff/              # Binary comparison (added/removed/modified)
    ├── gopclntab/         # Go PC-line table parsing (via debug/gosym)
    ├── functions/         # Function extraction + runtime/stdlib/user classification
    ├── strings/           # .rodata scanner + LEA/ADRP cross-reference + classifier
    ├── callgraph/         # CALL disassembly + edge resolution (x86 + ARM64)
    ├── cfg/               # Basic block splitting + pseudocode emission
    ├── types/             # rtype descriptor recovery + struct fields + itab recovery
    ├── concurrency/       # Goroutine/channel pattern detection
    ├── behaviors/         # Behavior tag rules (NETWORK, CRYPTO, EXEC, etc.)
    ├── obfuscation/       # Garble/obfuscation scoring and relabeling
    ├── version/           # Version vars (injected via ldflags at release)
    └── output/            # JSON, JSONL, and text report writers
```

---

## Limitations

- Standard Go toolchain only — AGC/TinyGo binaries are not supported
- CFG pseudocode is slow on binaries with 10,000+ functions
- Static analysis only — no dynamic tracing or runtime instrumentation

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Licensed under the [Apache-2.0](LICENSE) license.

---

## Links

- Repository: https://github.com/muxover/goripper
- Issues: https://github.com/muxover/goripper/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)

---

<p align="center">Made with ❤️ by Jax (@muxover)</p>
