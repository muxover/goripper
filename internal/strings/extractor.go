package strings

import (
	"encoding/binary"
	"sort"

	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
	"golang.org/x/arch/x86/x86asm"
)

const minStringLen = 6

func Deduplicate(strs []ExtractedString) []ExtractedString {
	type key struct {
		value string
		typ   StringType
	}
	type entry struct {
		s   ExtractedString
		idx int
	}
	seen := make(map[key]*entry, len(strs))
	order := make([]*entry, 0, len(strs))

	for _, s := range strs {
		k := key{s.Value, s.Type}
		if e, ok := seen[k]; ok {
			for _, fn := range s.ReferencedBy {
				e.s.ReferencedBy = appendUniq(e.s.ReferencedBy, fn)
			}
			if s.Offset < e.s.Offset {
				e.s.Offset = s.Offset
			}
		} else {
			cp := s
			e := &entry{s: cp, idx: len(order)}
			seen[k] = e
			order = append(order, e)
		}
	}

	result := make([]ExtractedString, len(order))
	for i, e := range order {
		result[i] = e.s
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Offset < result[j].Offset })
	return result
}

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

func CrossReference(
	strs []ExtractedString,
	funcs []functions.Function,
	textData []byte,
	textVA uint64,
	rodataData []byte,
	rodataVA uint64,
	rodataEnd uint64,
	d disasm.Disassembler,
) []ExtractedString {
	if len(funcs) == 0 || len(textData) == 0 {
		return strs
	}

	addrToIdx := make(map[uint64]int, len(strs))
	for i, s := range strs {
		addrToIdx[s.Offset] = i
	}

	kindMap := make(map[string]functions.PackageKind, len(funcs))
	for _, f := range funcs {
		kindMap[f.Name] = f.PackageKind
	}

	franges := buildFuncRanges(funcs)
	refs := make(map[uint64][]leaRef)

	pos := 0
	for pos < len(textData) {
		instr, err := d.Decode(textData[pos:], textVA+uint64(pos))
		if err != nil {
			pos++
			continue
		}
		if instr.Op == disasm.OpAddrLoad && instr.AddrRef >= rodataVA && instr.AddrRef < rodataEnd {
			funcName := findContainingFunc(instr.VA, franges)
			if funcName != "" {
				refs[instr.AddrRef] = append(refs[instr.AddrRef], leaRef{instrPos: pos, funcName: funcName})
			}
		}
		pos += instr.Len
	}

	for i := range strs {
		if lrefs, ok := refs[strs[i].Offset]; ok {
			for _, lr := range lrefs {
				strs[i].ReferencedBy = appendUniq(strs[i].ReferencedBy, lr.funcName)
			}
		}
	}

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

		length := 0
		if d.Arch() == "x86_64" {
			for _, lr := range lrefs {
				if l := findLengthNearby(textData, lr.instrPos); l > 0 {
					length = l
					break
				}
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
			// stdlib-only refs get a tighter cap: they rarely have user-readable strings.
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

func SuppressBlobs(strs []ExtractedString) []ExtractedString {
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
			continue
		}
		result = append(result, s)
	}
	return result
}

func findLengthNearby(textData []byte, instrPos int) int {
	if instrPos < 0 || instrPos >= len(textData) {
		return 0
	}

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

// extractMovImm rejects R8..R15 destinations to avoid grabbing the second length in a CMOVNE pair.
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

// CrossReferenceSimple is a fallback for non-PIE binaries where addresses appear literally in .text.
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
