#!/usr/bin/env bash
# Builds a minimal linux/amd64 ELF fixture used by the Linux integration tests.
# Run from the repo root: bash testdata/build_elf_fixture.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SCRIPT_DIR/fixture_linux_amd64"

GOOS=linux GOARCH=amd64 go build -o "$OUT" "$SCRIPT_DIR/hello/"
echo "Built ELF fixture: $OUT"
