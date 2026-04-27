package binary

import (
	"encoding/binary"
	"fmt"
	"os"
)

type Binary interface {
	Section(name string) ([]byte, error)
	SectionVA(name string) (uint64, error)
	TextSectionRange() (uint64, uint64, error)
	ImageBase() uint64
	GoVersion() string
	Format() string
	Arch() string
	Size() int64
	Path() string
	// FindGopclntab scans all sections for pclntab magic — needed on PE where gopclntab has no dedicated section.
	FindGopclntab() ([]byte, uint64, error)
	Close() error
}

// src/internal/abi/symtab.go in the Go standard library.
var gopclntabMagics = []uint32{
	0xFFFFFFFB, // Go 1.2–1.15  (Go12PCLnTabMagic)
	0xFFFFFFFA, // Go 1.16–1.17 (Go116PCLnTabMagic)
	0xFFFFFFF0, // Go 1.18–1.19 (Go118PCLnTabMagic)
	0xFFFFFFF1, // Go 1.20+     (Go120PCLnTabMagic)
}

func IsPclntabMagic(v uint32) bool {
	for _, m := range gopclntabMagics {
		if v == m {
			return true
		}
	}
	return false
}

func ScanForPclntab(data []byte) int {
	for i := 0; i+8 <= len(data); i += 4 {
		v := binary.LittleEndian.Uint32(data[i : i+4])
		if IsPclntabMagic(v) && isValidPclntabHeader(data[i:]) && pclntabNfunc(data[i:]) > 10 {
			return i
		}
	}
	return -1
}

func pclntabNfunc(data []byte) uint32 {
	if len(data) < 12 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[8:12])
}

// header layout: [4 magic][2 pad=0][1 minLC][1 ptrSize]
func isValidPclntabHeader(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	if data[4] != 0 || data[5] != 0 {
		return false
	}
	minLC := data[6]
	if minLC != 1 && minLC != 2 && minLC != 4 {
		return false
	}
	ptrSize := data[7]
	return ptrSize == 4 || ptrSize == 8
}

func isMachoMagic(magic []byte) bool {
	// 32-bit little-endian: 0xCEFAEDFE, 64-bit little-endian: 0xCFFAEDFE
	// 32-bit big-endian: 0xFEEDFACE, 64-bit big-endian: 0xFEEDFACF
	// fat binary: 0xBEBAFECA (little) / 0xCAFEBABE (big)
	return (magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA && (magic[3] == 0xCE || magic[3] == 0xCF)) ||
		(magic[0] == 0xCE && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) ||
		(magic[0] == 0xCF && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) ||
		(magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE)
}

func Open(path string) (Binary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		f.Close()
		return nil, fmt.Errorf("read magic: %w", err)
	}
	f.Close()

	if magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return openELF(path)
	}
	if magic[0] == 'M' && magic[1] == 'Z' {
		return openPE(path)
	}
	// Mach-O: 32-bit, 64-bit, and fat (universal) — both endiannesses.
	if isMachoMagic(magic) {
		return openMacho(path)
	}

	return nil, fmt.Errorf("unknown binary format (magic: %x %x %x %x)", magic[0], magic[1], magic[2], magic[3])
}
