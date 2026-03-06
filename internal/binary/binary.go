package binary

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Binary is the platform-agnostic interface over PE and ELF files.
type Binary interface {
	// Section returns raw bytes for the named section.
	Section(name string) ([]byte, error)
	// SectionVA returns the virtual address of a section.
	SectionVA(name string) (uint64, error)
	// TextSectionRange returns (startVA, endVA) for the executable text section.
	TextSectionRange() (uint64, uint64, error)
	// ImageBase returns the preferred load address.
	ImageBase() uint64
	// GoVersion returns the embedded Go version string if detectable.
	GoVersion() string
	// Format returns "PE" or "ELF".
	Format() string
	// Arch returns the architecture string.
	Arch() string
	// Size returns the file size in bytes.
	Size() int64
	// Path returns the file path.
	Path() string
	// FindGopclntab searches all sections for gopclntab magic bytes.
	// Needed for PE binaries where gopclntab may not be in its own section.
	FindGopclntab() ([]byte, uint64, error)
	// Close releases file resources.
	Close() error
}

// gopclntab magic bytes (little-endian uint32).
// Source: src/internal/abi/symtab.go in the Go standard library.
var gopclntabMagics = []uint32{
	0xFFFFFFFB, // Go 1.2–1.15  (Go12PCLnTabMagic)
	0xFFFFFFFA, // Go 1.16–1.17 (Go116PCLnTabMagic)
	0xFFFFFFF0, // Go 1.18–1.19 (Go118PCLnTabMagic)
	0xFFFFFFF1, // Go 1.20+     (Go120PCLnTabMagic)
}

// IsPclntabMagic returns true if the 4-byte value matches any known pclntab magic.
func IsPclntabMagic(v uint32) bool {
	for _, m := range gopclntabMagics {
		if v == m {
			return true
		}
	}
	return false
}

// ScanForPclntab searches data for a gopclntab magic at any 4-byte aligned offset.
// Returns the offset within data, or -1 if not found.
// Validates that the header looks like a real pclntab (pad bytes zero, valid ptrSize).
func ScanForPclntab(data []byte) int {
	for i := 0; i+8 <= len(data); i += 4 {
		v := binary.LittleEndian.Uint32(data[i : i+4])
		if IsPclntabMagic(v) && isValidPclntabHeader(data[i:]) && pclntabNfunc(data[i:]) > 10 {
			return i
		}
	}
	return -1
}

// pclntabNfunc reads the lower 32 bits of the nfunc field from a pclntab header.
// In all pclntab versions the nfunc (or its low 32 bits in 64-bit layouts) lives at
// bytes [8:12], so a simple uint32 read is sufficient as a false-positive guard.
func pclntabNfunc(data []byte) uint32 {
	if len(data) < 12 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[8:12])
}

// isValidPclntabHeader performs sanity checks on the pclntab header bytes.
// layout: [4 magic][2 pad=0][1 minLC][1 ptrSize]
func isValidPclntabHeader(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	// Bytes 4-5 must be zero padding
	if data[4] != 0 || data[5] != 0 {
		return false
	}
	// minLC (byte 6) should be 1 (x86) or 4 (RISC)
	minLC := data[6]
	if minLC != 1 && minLC != 2 && minLC != 4 {
		return false
	}
	// ptrSize (byte 7) must be 4 or 8
	ptrSize := data[7]
	if ptrSize != 4 && ptrSize != 8 {
		return false
	}
	return true
}

// Open detects the binary format and returns the appropriate loader.
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

	// ELF magic: 0x7f 'E' 'L' 'F'
	if magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return openELF(path)
	}

	// PE magic: 'M' 'Z'
	if magic[0] == 'M' && magic[1] == 'Z' {
		return openPE(path)
	}

	return nil, fmt.Errorf("unknown binary format (magic: %x %x %x %x)", magic[0], magic[1], magic[2], magic[3])
}
