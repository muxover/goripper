package types

import (
	"encoding/binary"
	"fmt"
	"strings"

	gobinary "github.com/muxover/goripper/internal/binary"
)

// Recover scans the binary for Go type descriptors embedded in .rodata / .typelinks.
// It returns a best-effort list of recovered types; partial results are acceptable.
func Recover(bin gobinary.Binary) ([]RecoveredType, error) {
	var types []RecoveredType

	rodataData, rodataVA, err := readRodata(bin)
	if err != nil {
		return nil, err
	}

	order := binary.LittleEndian
	ptrSize := uint8(8) // x86_64

	// Strategy 1: Use .typelinks if available (ELF binaries)
	if types, ok := tryTypelinks(bin, rodataData, rodataVA, order, ptrSize); ok {
		return types, nil
	}

	// Strategy 2: Scan .rodata for type name strings prefixed with known patterns
	types = scanForTypeNames(rodataData, rodataVA, order, ptrSize)

	return types, nil
}

func readRodata(bin gobinary.Binary) ([]byte, uint64, error) {
	// Try .rodata (ELF) then .rdata (PE)
	for _, name := range []string{".rodata", ".rdata"} {
		data, err := bin.Section(name)
		if err == nil {
			va, _ := bin.SectionVA(name)
			return data, va, nil
		}
	}
	return nil, 0, fmt.Errorf("no rodata section found")
}

// tryTypelinks uses the ELF .typelinks section (int32 offsets into .rodata).
func tryTypelinks(bin gobinary.Binary, rodataData []byte, rodataVA uint64, order binary.ByteOrder, ptrSize uint8) ([]RecoveredType, bool) {
	// Only ELF binaries have .typelinks as a separate section
	type typelinkBin interface {
		TypeLinks() ([]byte, uint64, error)
	}

	tlBin, ok := bin.(typelinkBin)
	if !ok {
		return nil, false
	}

	tlData, _, err := tlBin.TypeLinks()
	if err != nil {
		return nil, false
	}

	var types []RecoveredType

	// .typelinks contains int32 offsets from the start of .rodata to rtype structs
	for i := 0; i+4 <= len(tlData); i += 4 {
		off := int(order.Uint32(tlData[i : i+4]))
		if off < 0 || off >= len(rodataData) {
			continue
		}

		rt, err := parseRType(rodataData, off, ptrSize, order, rodataVA)
		if err != nil {
			continue
		}
		if rt.Name != "" {
			types = append(types, *rt)
		}
	}

	return types, len(types) > 0
}

// reflect.rtype layout (Go 1.18+, 64-bit):
//   [0:8]   size        uintptr
//   [8:16]  ptrdata     uintptr
//   [16:20] hash        uint32
//   [20]    tflag       uint8
//   [21]    align       uint8
//   [22]    fieldAlign  uint8
//   [23]    kind_       uint8
//   [24:32] equal       uintptr (func pointer)
//   [32:40] gcdata      uintptr (pointer)
//   [40:44] str         int32   (nameOff into .rodata)
//   [44:48] ptrToThis   int32
// Total: 48 bytes
const rtypeSize = 48

func parseRType(data []byte, off int, ptrSize uint8, order binary.ByteOrder, baseVA uint64) (*RecoveredType, error) {
	if off+rtypeSize > len(data) {
		return nil, fmt.Errorf("rtype at %d: insufficient data", off)
	}

	size := order.Uint64(data[off : off+8])
	kind := data[off+23] & kindMask

	// str field at offset 40: int32 offset to name in .rodata
	strOff := int32(order.Uint32(data[off+40 : off+44]))

	name := ""
	if strOff != 0 {
		nameOff := off + int(strOff) // relative to this rtype
		name = readTypeName(data, nameOff)
	}

	if name == "" || !isValidTypeName(name) {
		return nil, fmt.Errorf("no valid name at rtype+%d", off)
	}

	rt := &RecoveredType{
		Name: name,
		Kind: kindFromByte(kind),
		Size: uint32(size),
		Addr: baseVA + uint64(off),
	}

	return rt, nil
}

// readTypeName reads a Go type name from the name section.
// Go type names are stored with a 2-byte length prefix (varint-like).
func readTypeName(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}

	// Type name format: [flags uint8][len uint16 big-endian][name bytes...]
	if off+3 > len(data) {
		return ""
	}

	// flags byte
	_ = data[off]
	// 2-byte length (big-endian)
	nameLen := int(data[off+1])<<8 | int(data[off+2])

	if nameLen <= 0 || nameLen > 512 || off+3+nameLen > len(data) {
		return ""
	}

	return string(data[off+3 : off+3+nameLen])
}

// isValidTypeName returns true if the name looks like a real Go type name.
func isValidTypeName(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	// Must start with a letter or * (pointer) or [ (slice/array)
	c := name[0]
	if c != '*' && c != '[' && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
		return false
	}
	// Must not contain null bytes or control characters
	for _, ch := range name {
		if ch < 32 {
			return false
		}
	}
	return true
}

// scanForTypeNames is a fallback that searches .rodata for type name patterns.
// Go embeds type names as "go:type." prefixed strings in some builds.
func scanForTypeNames(data []byte, baseVA uint64, order binary.ByteOrder, ptrSize uint8) []RecoveredType {
	var types []RecoveredType
	seen := make(map[string]bool)

	// Look for "type:" or "go:type." markers
	patterns := []string{"type.", "*"}
	for _, pat := range patterns {
		_ = pat
	}

	// Simple scan: look for null-terminated strings that look like type names
	// and are followed by rtype-sized alignment
	i := 0
	for i < len(data)-rtypeSize {
		// Try to read a type name at position i
		name := readTypeName(data, i)
		if name != "" && isValidTypeName(name) && !seen[name] {
			// Check if this could be followed by a valid rtype
			nameRecordSize := 3 + len(name)
			rtOff := i - rtypeSize // rtype comes before the name in Go's layout

			// Alternative: try rtype at current position
			if i+rtypeSize <= len(data) {
				kind := data[i+23] & kindMask
				if kind >= 1 && kind <= 26 {
					seen[name] = true
					types = append(types, RecoveredType{
						Name: name,
						Kind: kindFromByte(kind),
						Addr: baseVA + uint64(i),
					})
				}
			}
			_ = rtOff
			_ = nameRecordSize
		}
		i++
	}

	// Deduplicate and filter
	var result []RecoveredType
	seenFinal := make(map[string]bool)
	for _, t := range types {
		if !seenFinal[t.Name] && isInterestingType(t.Name) {
			seenFinal[t.Name] = true
			result = append(result, t)
		}
	}

	return result
}

// isInterestingType filters out boring/internal type names.
func isInterestingType(name string) bool {
	// Skip basic types
	boring := map[string]bool{
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
		"float32": true, "float64": true, "string": true, "bool": true, "byte": true,
		"rune": true, "error": true, "uintptr": true,
	}
	if boring[name] {
		return false
	}
	// Skip runtime internal types
	if strings.HasPrefix(name, "runtime.") || strings.HasPrefix(name, "internal/") {
		return false
	}
	return true
}
