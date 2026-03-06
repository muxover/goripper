package strings

import (
	"encoding/binary"

	"github.com/muxover/goripper/internal/functions"
	"golang.org/x/arch/x86/x86asm"
)

const minStringLen = 4

// Extract scans rodataData for printable strings of length >= minStringLen.
// rodataVA is the virtual address of the .rodata section start.
func Extract(rodataData []byte, rodataVA uint64) []ExtractedString {
	var result []ExtractedString
	i := 0
	for i < len(rodataData) {
		if !isPrintable(rodataData[i]) {
			i++
			continue
		}
		j := i
		for j < len(rodataData) && isPrintable(rodataData[j]) {
			j++
		}
		if j-i >= minStringLen {
			result = append(result, ExtractedString{
				Value:  string(rodataData[i:j]),
				Offset: rodataVA + uint64(i),
			})
		}
		i = j + 1
	}
	return result
}

func isPrintable(b byte) bool {
	return (b >= 32 && b <= 126) || b == '\t' || b == '\n' || b == '\r'
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
					targetVA := instrVA + uint64(inst.Len) + uint64(mem.Disp)
					if targetVA >= rodataVA && targetVA < rodataEnd {
						funcName := findContainingFunc(instrVA, franges)
						if funcName != "" {
							refs[targetVA] = appendUniq(refs[targetVA], funcName)
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
