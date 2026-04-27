package types

import (
	"encoding/binary"
	"fmt"
	"strings"

	gobinary "github.com/muxover/goripper/internal/binary"
)

func Recover(bin gobinary.Binary) ([]RecoveredType, error) {
	var types []RecoveredType

	rodataData, rodataVA, err := readRodata(bin)
	if err != nil {
		return []RecoveredType{}, err
	}

	order := binary.LittleEndian
	ptrSize := uint8(8) // x86_64

	if types, ok := tryTypelinks(bin, rodataData, rodataVA, order, ptrSize); ok {
		return types, nil
	}

	types = scanForTypeNames(rodataData, rodataVA, order, ptrSize)
	if types == nil {
		types = []RecoveredType{}
	}

	return types, nil
}

func readRodata(bin gobinary.Binary) ([]byte, uint64, error) {
	for _, name := range []string{".rodata", ".rdata"} {
		data, err := bin.Section(name)
		if err == nil {
			va, _ := bin.SectionVA(name)
			return data, va, nil
		}
	}
	return nil, 0, fmt.Errorf("no rodata section found")
}

func tryTypelinks(bin gobinary.Binary, rodataData []byte, rodataVA uint64, order binary.ByteOrder, ptrSize uint8) ([]RecoveredType, bool) {
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
	strOff := int32(order.Uint32(data[off+40 : off+44]))

	name := ""
	if strOff != 0 {
		nameOff := off + int(strOff) // nameOff is relative to the rtype's own position
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

	if kind == kindStruct {
		rt.Fields = parseStructFields(data, off, order, baseVA)
	}

	return rt, nil
}

// structType layout (64-bit, Go 1.18+):
//
//	[0:48]  rtype
//	[48:52] PkgPath NameOff (int32)
//	[52:56] padding
//	[56:64] Fields.Data *StructField (VA)
//	[64:72] Fields.Len  int
//	[72:80] Fields.Cap  int
//
// StructField (24 bytes):
//
//	[0:4]   Name_       NameOff (int32, relative to rtype position)
//	[4:8]   padding
//	[8:16]  Typ_        *abi.Type (VA)
//	[16:24] OffsetEmbed uintptr  (offset << 1 | embedded)
const structTypeHeaderSize = 80 // rtype(48) + pkgPath(4) + pad(4) + slice(24)
const structFieldSize = 24

func parseStructFields(data []byte, off int, order binary.ByteOrder, baseVA uint64) []FieldDescriptor {
	if off+structTypeHeaderSize > len(data) {
		return nil
	}

	fieldsDataVA := order.Uint64(data[off+56 : off+64])
	fieldsLen := int(order.Uint64(data[off+64 : off+72]))

	if fieldsLen <= 0 || fieldsLen > 128 {
		return nil
	}
	if fieldsDataVA < baseVA {
		return nil
	}
	fieldsOff := int(fieldsDataVA - baseVA)
	if fieldsOff+fieldsLen*structFieldSize > len(data) {
		return nil
	}

	fields := make([]FieldDescriptor, 0, fieldsLen)
	for i := 0; i < fieldsLen; i++ {
		fOff := fieldsOff + i*structFieldSize
		if fOff+structFieldSize > len(data) {
			break
		}

		nameOff := int(int32(order.Uint32(data[fOff : fOff+4])))
		typPtr := order.Uint64(data[fOff+8 : fOff+16])
		offsetEmbed := order.Uint64(data[fOff+16 : fOff+24])
		fieldOffset := uint32(offsetEmbed >> 1)

		// field NameOff is relative to the StructField's own position (mirrors rtype.str behavior)
		fieldName := readTypeName(data, fOff+nameOff)
		if fieldName == "" || !isValidTypeName(fieldName) {
			continue
		}

		typName := ""
		if typPtr >= baseVA {
			typOff := int(typPtr - baseVA)
			if rt, err := parseRType(data, typOff, 8, order, baseVA); err == nil {
				typName = rt.Name
			}
		}

		fields = append(fields, FieldDescriptor{
			Name:   fieldName,
			Type:   typName,
			Offset: fieldOffset,
		})
	}

	return fields
}

func readTypeName(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}

	// layout: [flags uint8][len uint16 big-endian][name bytes...]
	if off+3 > len(data) {
		return ""
	}

	_ = data[off]
	nameLen := int(data[off+1])<<8 | int(data[off+2])

	if nameLen <= 0 || nameLen > 512 || off+3+nameLen > len(data) {
		return ""
	}

	return string(data[off+3 : off+3+nameLen])
}

func isValidTypeName(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	c := name[0]
	if c != '*' && c != '[' && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
		return false
	}
	for _, ch := range name {
		if ch < 32 {
			return false
		}
	}
	return true
}

func scanForTypeNames(data []byte, baseVA uint64, order binary.ByteOrder, ptrSize uint8) []RecoveredType {
	var types []RecoveredType
	seen := make(map[string]bool)

	i := 0
	for i < len(data)-rtypeSize {
		// Try to read a type name at position i
		name := readTypeName(data, i)
		if name != "" && isValidTypeName(name) && !seen[name] {
			nameRecordSize := 3 + len(name)
			rtOff := i - rtypeSize
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

func isInterestingType(name string) bool {
	boring := map[string]bool{
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
		"float32": true, "float64": true, "string": true, "bool": true, "byte": true,
		"rune": true, "error": true, "uintptr": true,
	}
	if boring[name] {
		return false
	}
	if strings.HasPrefix(name, "runtime.") || strings.HasPrefix(name, "internal/") {
		return false
	}
	return true
}
