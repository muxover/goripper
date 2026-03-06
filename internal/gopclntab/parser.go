// Package gopclntab parses Go pclntab (PC-line table) data from Go binaries.
// It uses the standard library's debug/gosym package for version-agnostic parsing.
package gopclntab

import (
	"debug/gosym"
	"fmt"
)

// Parse uses Go's standard debug/gosym package to parse pclntab data.
// textSectionVA is the virtual address of the .text section (passed to gosym.NewLineTable).
// This handles all Go versions from 1.2 through 1.22+.
func Parse(data []byte, textSectionVA uint64) (*ParsedPclntab, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("pclntab too short: %d bytes", len(data))
	}

	version, order, err := detectVersion(data)
	if err != nil {
		return nil, err
	}
	_ = order // order is little-endian for x86

	ptrSize := data[7]
	if ptrSize != 4 && ptrSize != 8 {
		return nil, fmt.Errorf("invalid ptrSize: %d", ptrSize)
	}
	minLC := data[6]

	// Use the standard library's gosym package for reliable cross-version parsing
	lt := gosym.NewLineTable(data, textSectionVA)
	table, err := gosym.NewTable(nil, lt)
	if err != nil {
		return nil, fmt.Errorf("gosym.NewTable: %w", err)
	}

	funcs := make([]FuncEntry, 0, len(table.Funcs))
	for _, fn := range table.Funcs {
		if fn.Name == "" || fn.Entry == 0 {
			continue
		}
		funcs = append(funcs, FuncEntry{
			Name:    fn.Name,
			EntryPC: fn.Entry,
		})
	}

	// Compute sizes from consecutive entry PCs
	for i := 0; i < len(funcs)-1; i++ {
		funcs[i].Size = funcs[i+1].EntryPC - funcs[i].EntryPC
	}
	// Set last function's size if End is available
	if len(table.Funcs) > 0 && len(funcs) > 0 {
		last := table.Funcs[len(table.Funcs)-1]
		if last.End > last.Entry {
			funcs[len(funcs)-1].Size = last.End - last.Entry
		}
	}

	return &ParsedPclntab{
		Version:   version,
		GoVersion: version.String(),
		PtrSize:   ptrSize,
		MinLC:     minLC,
		Funcs:     funcs,
		TextStart: textSectionVA,
	}, nil
}
