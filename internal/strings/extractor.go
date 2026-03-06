package strings

import (
	"encoding/binary"

	"github.com/muxover/goripper/internal/functions"
	"golang.org/x/arch/x86/x86asm"
)

const minStringLen = 6

// Extract scans rodataData for Go string header pairs (ptr uint64, len uint64)
// at 8-byte aligned offsets. Only emits strings where ptr points back into
// .rodata, len is in range [minStringLen, 4096], and all bytes are printable ASCII.
func Extract(rodataData []byte, rodataVA uint64) []ExtractedString {
	rodataEnd := rodataVA + uint64(len(rodataData))
	seen := make(map[string]bool)
	var result []ExtractedString

	for i := 0; i+16 <= len(rodataData); i += 8 {
		ptr := binary.LittleEndian.Uint64(rodataData[i:])
		slen := binary.LittleEndian.Uint64(rodataData[i+8:])

		if ptr < rodataVA || ptr >= rodataEnd {
			continue
		}
		if slen < uint64(minStringLen) || slen > 4096 {
			continue
		}
		off := ptr - rodataVA
		if off+slen > uint64(len(rodataData)) {
			continue
		}
		b := rodataData[off : off+slen]
		if !isPrintableASCII(b) {
			continue
		}
		s := string(b)
		if seen[s] {
			continue
		}
		seen[s] = true
		result = append(result, ExtractedString{Value: s, Offset: ptr})
	}
	return result
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

type funcRange struct {
	start, end uint64
	name       string
}

// leaRef records the byte offset of a LEA/MOV RIP-relative instruction in textData
// and the name of the function containing it. Stored per target VA so the second pass
// can look at nearby instructions for a string-length immediate.
type leaRef struct {
	instrPos int
	funcName string
}

func buildFuncRanges(funcs []functions.Function) []funcRange {
	ranges := make([]funcRange, 0, len(funcs))
	for _, f := range funcs {
		if f.Size > 0 {
			ranges = append(ranges, funcRange{f.Addr, f.Addr + f.Size, f.Name})
		}
	}
	return ranges
}

func findContainingFunc(va uint64, franges []funcRange) string {
	for _, fr := range franges {
		if va >= fr.start && va < fr.end {
			return fr.name
		}
	}
	return ""
}

func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

// CrossReference annotates each string with the names of functions whose
// disassembly references the string's virtual address via LEA instructions
// (RIP-relative addressing in x86_64). It also emits new strings for LEA
// targets not found by the header-pair scan (e.g. strings only referenced
// from code and not stored with an adjacent header in .rodata).
func CrossReference(
	strs []ExtractedString,
	funcs []functions.Function,
	textData []byte,
	textVA uint64,
	rodataData []byte,
	rodataVA uint64,
	rodataEnd uint64,
) []ExtractedString {
	if len(funcs) == 0 || len(textData) == 0 {
		return strs
	}

	addrToIdx := make(map[uint64]int, len(strs))
	for i, s := range strs {
		addrToIdx[s.Offset] = i
	}

	franges := buildFuncRanges(funcs)
	refs := make(map[uint64][]leaRef)

	pos := 0
	for pos < len(textData) {
		inst, err := x86asm.Decode(textData[pos:], 64)
		if err != nil {
			pos++
			continue
		}

		instrVA := textVA + uint64(pos)

		if inst.Op == x86asm.LEA || inst.Op == x86asm.MOV {
			for _, arg := range inst.Args {
				if arg == nil {
					continue
				}
				mem, ok := arg.(x86asm.Mem)
				if !ok {
					continue
				}
				if mem.Base == x86asm.RIP {
					var disp int64 = mem.Disp
					targetVA := int64(instrVA) + int64(inst.Len) + disp
					if targetVA >= int64(rodataVA) && targetVA < int64(rodataEnd) {
						funcName := findContainingFunc(instrVA, franges)
						if funcName != "" {
							uva := uint64(targetVA)
							refs[uva] = append(refs[uva], leaRef{instrPos: pos, funcName: funcName})
						}
					}
				}
			}
		}

		pos += inst.Len
	}

	// Annotate strings already found by the header-pair scan.
	for i := range strs {
		if lrefs, ok := refs[strs[i].Offset]; ok {
			for _, lr := range lrefs {
				strs[i].ReferencedBy = appendUniq(strs[i].ReferencedBy, lr.funcName)
			}
		}
	}

	// Emit new strings for LEA targets not found by the header-pair scan.
	// Try to infer the exact length from nearby MOV instructions; fall back to
	// a 512-byte printable run when no length immediate is found.
	seen := make(map[uint64]bool, len(strs))
	for _, s := range strs {
		seen[s.Offset] = true
	}
	for va, lrefs := range refs {
		if seen[va] {
			continue
		}
		if va < rodataVA || va >= rodataEnd {
			continue
		}
		off := va - rodataVA
		if off >= uint64(len(rodataData)) {
			continue
		}

		// Try exact length from a nearby MOV reg, imm instruction.
		length := 0
		for _, lr := range lrefs {
			if l := findLengthNearby(textData, lr.instrPos); l > 0 {
				length = l
				break
			}
		}

		var value string
		if length > 0 {
			end := off + uint64(length)
			if end <= uint64(len(rodataData)) {
				b := rodataData[off:end]
				if isPrintableASCII(b) {
					value = string(b)
				}
			}
		}
		if value == "" {
			// Fallback: 512-byte printable run.
			end := off
			for end < uint64(len(rodataData)) && rodataData[end] >= 0x20 && rodataData[end] <= 0x7e && end-off < 512 {
				end++
			}
			if end-off < uint64(minStringLen) {
				continue
			}
			value = string(rodataData[off:end])
		}

		var funcNames []string
		seenFn := make(map[string]bool)
		for _, lr := range lrefs {
			if lr.funcName != "" && !seenFn[lr.funcName] {
				seenFn[lr.funcName] = true
				funcNames = append(funcNames, lr.funcName)
			}
		}
		strs = append(strs, ExtractedString{
			Value:        value,
			Offset:       va,
			ReferencedBy: funcNames,
		})
	}

	return strs
}

// findLengthNearby scans up to 15 instructions forward from instrPos in textData,
// returning the first MOV immediate in [minStringLen, 4096]. This covers the common
// Go compiler pattern where string length is loaded into a register right after the
// LEA that loads the string pointer. Returns 0 if no such immediate is found.
func findLengthNearby(textData []byte, instrPos int) int {
	if instrPos < 0 || instrPos >= len(textData) {
		return 0
	}
	pos := instrPos
	for i := 0; i < 15 && pos < len(textData); i++ {
		inst, err := x86asm.Decode(textData[pos:], 64)
		if err != nil {
			break
		}
		if inst.Op == x86asm.MOV {
			for _, arg := range inst.Args {
				if arg == nil {
					continue
				}
				if imm, ok := arg.(x86asm.Imm); ok {
					v := int64(imm)
					if v >= int64(minStringLen) && v <= 4096 {
						return int(v)
					}
				}
			}
		}
		pos += inst.Len
	}
	return 0
}

// CrossReferenceSimple uses raw 64-bit address scanning as a fallback for
// non-PIE binaries where addresses appear literally in .text.
func CrossReferenceSimple(
	strs []ExtractedString,
	funcs []functions.Function,
	textData []byte,
	textVA uint64,
) []ExtractedString {
	if len(strs) == 0 {
		return strs
	}

	addrToIdx := make(map[uint64]int, len(strs))
	for i, s := range strs {
		addrToIdx[s.Offset] = i
	}

	franges := buildFuncRanges(funcs)
	refs := make(map[uint64][]string)

	for i := 0; i+8 <= len(textData); i++ {
		val := binary.LittleEndian.Uint64(textData[i : i+8])
		if idx, ok := addrToIdx[val]; ok {
			instrVA := textVA + uint64(i)
			funcName := findContainingFunc(instrVA, franges)
			if funcName != "" {
				refs[strs[idx].Offset] = appendUniq(refs[strs[idx].Offset], funcName)
			}
		}
	}

	for i := range strs {
		if names, ok := refs[strs[i].Offset]; ok {
			existing := strs[i].ReferencedBy
			for _, n := range names {
				existing = appendUniq(existing, n)
			}
			strs[i].ReferencedBy = existing
		}
	}

	return strs
}
