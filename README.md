# GoRipper

<div align="center">

[![CI](https://github.com/muxover/goripper/actions/workflows/ci.yml/badge.svg)](https://github.com/muxover/goripper/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/muxover/goripper.svg)](https://pkg.go.dev/github.com/muxover/goripper)
[![Go Report Card](https://goreportcard.com/badge/github.com/muxover/goripper)](https://goreportcard.com/report/github.com/muxover/goripper)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/muxover/goripper)](https://github.com/muxover/goripper/releases)

**Go binary intelligence framework — extract behavioral insight from compiled Go executables.**

</div>

---

GoRipper analyzes compiled Go binaries (PE `.exe` and ELF) without source code. It parses Go-specific metadata, disassembles code, extracts strings, recovers types, detects concurrency patterns, and tags suspicious behaviors — outputting structured JSON or human-readable reports. Built for security researchers, reverse engineers, and incident responders.

> **Status:** `v0.0.5-pre` — CMOVNE plain-blob splitting, register-aware length inference, post-extraction blob suppression. ELF symbol fallback and full test coverage coming in `v0.0.6-pre` through `v0.1.0`.

---

## Features

- **Function Extraction** — Parses `gopclntab` via Go's standard library (`debug/gosym`) to recover all function names, addresses, and sizes for Go 1.2 through 1.24.
- **Package Classification** — Automatically separates `runtime`, `stdlib`, `user`, and `cgo` packages.
- **Call Graph** — Disassembles `.text` using x86 instruction decoding to map every `CALL` edge across the binary.
- **String Extraction** — Scans `.rodata` and cross-references strings to functions via LEA/MOV RIP-relative instruction analysis.
- **String Classification** — Categorizes strings as URLs, IPs, file paths, secrets, Go package paths, or plain text.
- **Obfuscation Detection** — Scores each binary for garble/obfuscation (0.0–1.0) using entropy, prefix ratio, string density, and build-info signals.
- **Stripped Binary Fallback** — Falls back to `.pdata` exception table when gopclntab is absent, generating synthetic `sub_0x<addr>` names.
- **Type Recovery** — Parses Go runtime `rtype` descriptors to recover struct names, kinds, and field layouts.
- **Concurrency Detection** — Identifies goroutine spawns, channel operations, and mutex usage via call graph patterns.
- **Behavior Tagging** — Tags functions with `NETWORK`, `CRYPTO`, `FILE_WRITE`, `FILE_READ`, `EXEC`, `REGISTRY`, `HTTP`, `DNS`, and more.
- **CFG + Pseudocode** — Builds basic-block control flow graphs and emits simplified pseudocode per function (optional, slow on large binaries).
- **JSON + Text Output** — Machine-readable JSON or analyst-friendly tabular text.

---

## Installation

**From source (requires Go 1.24+):**

```bash
go install github.com/muxover/goripper/cmd/goripper@latest
```

**Build locally:**

```bash
git clone https://github.com/muxover/goripper.git
cd goripper
go build -o goripper ./cmd/goripper/
```

**Pre-built binaries:**

Download from [Releases](https://github.com/muxover/goripper/releases) for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.

---

## Quick Start

```bash
# Full analysis — human-readable report
goripper analyze ./mybinary

# Full analysis — JSON output
goripper analyze ./mybinary --json

# Show only user-written functions (no runtime/stdlib noise)
goripper functions ./mybinary --only-user

# Extract URL strings
goripper strings ./mybinary --type url

# Build call graph, no runtime functions
goripper callgraph ./mybinary --no-runtime
```

**Example output:**

```
=== GoRipper Analysis Report ===
Binary:     mybinary
Format:     PE
Arch:       x86_64
Go Version: go1.22.1
Size:       8388608 bytes

=== Summary ===
Total functions:      5729
  User:               312
  Stdlib:             1847
  Runtime:            3570
Suspicious:           61
Concurrent:           24
Total strings:        847 (12 URLs)
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

---

## Configuration

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit JSON instead of text |
| `--out <dir>` | stdout | Write output to a file in this directory |
| `-v`, `--verbose` | `false` | Show pipeline stage timing and debug info |

### `analyze` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--no-runtime` | `false` | Exclude runtime functions from output |
| `--only-user` | `false` | Show only user-written package functions |
| `--cfg` | `false` | Build CFG and emit pseudocode (slow on large binaries) |
| `--types` | `false` | Run type recovery from runtime `rtype` descriptors |

### `functions` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--only-user` | `false` | Filter to user packages only |
| `--no-runtime` | `false` | Exclude `runtime.*` functions |
| `--pkg <name>` | `""` | Filter to a specific package name |

### `strings` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--type <type>` | `""` | Filter: `url`, `ip`, `path`, `secret`, `pkgpath` |

### `callgraph` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--no-runtime` | `false` | Exclude runtime nodes |
| `--depth <n>` | `3` | Maximum call depth to display |

---

## Project Layout

```
goripper/
├── cmd/goripper/          # CLI entry point (cobra)
├── pkg/analyzer/          # Pipeline orchestrator
└── internal/
    ├── binary/            # PE + ELF binary loaders
    ├── gopclntab/         # Go PC-line table parsing (via debug/gosym)
    ├── functions/         # Function extraction + runtime/stdlib/user classification
    ├── strings/           # .rodata scanner + LEA cross-reference + classifier
    ├── callgraph/         # x86 CALL disassembly + edge resolution
    ├── cfg/               # Basic block splitting + pseudocode emission
    ├── types/             # Go rtype descriptor recovery
    ├── concurrency/       # Goroutine/channel pattern detection
    ├── behaviors/         # Behavior tag rules (NETWORK, CRYPTO, EXEC, etc.)
    ├── obfuscation/       # Garble/obfuscation scoring and relabeling
    └── output/            # JSON + text report writers
```

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
