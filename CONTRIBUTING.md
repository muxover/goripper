# Contributing to GoRipper

Thank you for your interest in contributing!

---

## Table of Contents

- [Getting started](#getting-started)
- [Running tests](#running-tests)
- [Code style](#code-style)
- [Submitting changes](#submitting-changes)
- [Reporting issues](#reporting-issues)

---

## Getting started

**Requirements:**
- Go 1.24 or later
- Git

```bash
git clone https://github.com/muxover/goripper.git
cd goripper
go build ./...
```

Build the CLI binary:

```bash
go build -o goripper ./cmd/goripper/
./goripper --help
```

---

## Running tests

```bash
go test ./...
```

With the race detector:

```bash
go test -race ./...
```

With coverage:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## Code style

- Run `gofmt` before committing. All code must be `gofmt`-clean.
- Run `go vet ./...` — must be clean.
- No dead code, no commented-out blocks, no debug `fmt.Println` in committed code.
- New exported types and functions must have godoc comments.
- Prefer editing existing files over creating new ones.
- Keep functions focused on one responsibility.

---

## Submitting changes

1. **Open an issue first** for any significant change — discuss the approach before writing code.
2. Fork the repository and branch from `main` using the naming convention:
   - `feat/<short-description>` for new features
   - `fix/<short-description>` for bug fixes
   - `chore/<short-description>` for tooling/CI changes
3. Add or update tests for your change.
4. Ensure `go build ./...`, `go test ./...`, and `go vet ./...` all pass.
5. Open a pull request with a clear description of what changed and why.

One logical change per PR.

---

## Reporting issues

Open an issue at https://github.com/muxover/goripper/issues. Include:

- OS and architecture (e.g. `Windows 11 amd64`, `Ubuntu 22.04 amd64`)
- Go version (`go version`)
- GoRipper version (`goripper --version`)
- The binary you were analyzing (or a minimal reproducer)
- Full error message and command you ran
