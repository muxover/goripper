package strings

import (
	"encoding/binary"
	"sort"

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

	// Build function name → PackageKind map for the stdlib-only fallback cap (Fix 4).
	kindMap := make(map[string]functions.PackageKind, len(funcs))
	for _, f := range funcs {
		kindMap[f.Name] = f.PackageKind
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
	// a capped printable run when no length immediate is found.
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
		var isFallback bool
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
			// Fix 4: use 200-byte cap for stdlib/runtime-only refs, 512 otherwise.
			cap := 512
			if allStdlibRefs(lrefs, kindMap) {
				cap = 200
			}
			end := off
			for end < uint64(len(rodataData)) && rodataData[end] >= 0x20 && rodataData[end] <= 0x7e && end-off < uint64(cap) {
				end++
			}
			if end-off < uint64(minStringLen) {
				continue
			}
			value = string(rodataData[off:end])
			isFallback = true
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
			Value:          value,
			Offset:         va,
			ReferencedBy:   funcNames,
			IsFallbackBlob: isFallback,
		})
	}

	return strs
}

// allStdlibRefs returns true when every reference in lrefs belongs to a
// runtime or stdlib function (not user or CGo code).
func allStdlibRefs(lrefs []leaRef, kindMap map[string]functions.PackageKind) bool {
	if len(lrefs) == 0 {
		return false
	}
	for _, lr := range lrefs {
		kind, ok := kindMap[lr.funcName]
		if !ok {
			return false
		}
		if kind == functions.PackageUser || kind == functions.PackageCGo {
			return false
		}
	}
	return true
}

// SuppressBlobs removes fallback blobs whose content is already covered by
// individually-extracted component strings. A blob is suppressed when at least
// 2 other string start-VAs fall strictly inside its byte range — those
// components are already present in the output and the blob adds no information.
func SuppressBlobs(strs []ExtractedString) []ExtractedString {
	// Collect VAs of all non-blob strings for containment checks.
	nonBlobVAs := make([]uint64, 0, len(strs))
	for _, s := range strs {
		if !s.IsFallbackBlob {
			nonBlobVAs = append(nonBlobVAs, s.Offset)
		}
	}
	sort.Slice(nonBlobVAs, func(i, j int) bool { return nonBlobVAs[i] < nonBlobVAs[j] })

	result := make([]ExtractedString, 0, len(strs))
	for _, s := range strs {
		if !s.IsFallbackBlob {
			result = append(result, s)
			continue
		}
		lo := s.Offset + 1
		hi := s.Offset + uint64(len(s.Value))
		// Count non-blob VAs that are strictly inside this blob's range.
		start := sort.Search(len(nonBlobVAs), func(i int) bool { return nonBlobVAs[i] >= lo })
		count := sort.Search(len(nonBlobVAs)-start, func(i int) bool { return nonBlobVAs[start+i] >= hi })
		if count >= 2 {
			continue // suppress: components already individually present
		}
		result = append(result, s)
	}
	return result
}

// findLengthNearby scans up to 8 instructions backward and 30 instructions
// forward from instrPos in textData, returning the first valid MOV immediate
// in [minStringLen, 4096]. MOV to extended registers (R8..R15) are rejected
// to avoid misattributing the second string length in a CMOVNE pair.
// Returns 0 if no suitable immediate is found.
func findLengthNearby(textData []byte, instrPos int) int {
	if instrPos < 0 || instrPos >= len(textData) {
		return 0
	}

	// Backward scan: decode forward from up to 64 bytes before instrPos,
	// collect instruction start positions, then scan the last 8 backward.
	backStart := instrPos - 64
	if backStart < 0 {
		backStart = 0
	}
	var backPositions []int
	pos := backStart
	for pos < instrPos {
		inst, err := x86asm.Decode(textData[pos:], 64)
		if err != nil {
			pos++
			continue
		}
		backPositions = append(backPositions, pos)
		pos += inst.Len
	}
	limit := len(backPositions) - 8
	if limit < 0 {
		limit = 0
	}
	for i := len(backPositions) - 1; i >= limit; i-- {
		inst, err := x86asm.Decode(textData[backPositions[i]:], 64)
		if err != nil {
			continue
		}
		if v := extractMovImm(inst); v > 0 {
			return v
		}
	}

	// Forward scan: up to 30 instructions from instrPos.
	pos = instrPos
	for i := 0; i < 30 && pos < len(textData); i++ {
		inst, err := x86asm.Decode(textData[pos:], 64)
		if err != nil {
			break
		}
		if v := extractMovImm(inst); v > 0 {
			return v
		}
		pos += inst.Len
	}
	return 0
}

// extractMovImm returns a valid string-length immediate from a MOV instruction,
// or 0. MOV to extended registers (R8..R15) are rejected to avoid picking up
// the second length in a CMOVNE pair.
func extractMovImm(inst x86asm.Inst) int {
	if inst.Op != x86asm.MOV {
		return 0
	}
	if len(inst.Args) >= 1 && inst.Args[0] != nil {
		if reg, ok := inst.Args[0].(x86asm.Reg); ok {
			if isExtendedReg(reg) {
				return 0
			}
		}
	}
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
	return 0
}

// isExtendedReg returns true for the R8..R15 register family (all widths).
func isExtendedReg(reg x86asm.Reg) bool {
	switch reg {
	case x86asm.R8, x86asm.R8L, x86asm.R8W, x86asm.R8B,
		x86asm.R9, x86asm.R9L, x86asm.R9W, x86asm.R9B,
		x86asm.R10, x86asm.R10L, x86asm.R10W, x86asm.R10B,
		x86asm.R11, x86asm.R11L, x86asm.R11W, x86asm.R11B,
		x86asm.R12, x86asm.R12L, x86asm.R12W, x86asm.R12B,
		x86asm.R13, x86asm.R13L, x86asm.R13W, x86asm.R13B,
		x86asm.R14, x86asm.R14L, x86asm.R14W, x86asm.R14B,
		x86asm.R15, x86asm.R15L, x86asm.R15W, x86asm.R15B:
		return true
	}
	return false
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
