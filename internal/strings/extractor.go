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
// (RIP-relative addressing in x86_64).
func CrossReference(
	strs []ExtractedString,
	funcs []functions.Function,
	textData []byte,
	textVA uint64,
	rodataVA uint64,
	rodataEnd uint64,
) []ExtractedString {
	if len(strs) == 0 || len(funcs) == 0 || len(textData) == 0 {
		return strs
	}

	addrToIdx := make(map[uint64]int, len(strs))
	for i, s := range strs {
		addrToIdx[s.Offset] = i
	}

	franges := buildFuncRanges(funcs)
	refs := make(map[uint64][]string)

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
							refs[uva] = appendUniq(refs[uva], funcName)
						}
					}
				}
			}
		}

		pos += inst.Len
	}

	for i := range strs {
		if names, ok := refs[strs[i].Offset]; ok {
			strs[i].ReferencedBy = names
		}
	}

	return strs
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
