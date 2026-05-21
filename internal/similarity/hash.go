package similarity

import (
	"fmt"
	"hash/fnv"

	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
)

// Targets, immediates, and address references are stripped — only opcode and indirect
// flag are hashed. Two functions differing only in constants produce the same hash.
func HashFunction(textData []byte, textVA uint64, fn functions.Function, d disasm.Disassembler) string {
	if fn.Size == 0 || fn.Addr < textVA {
		return ""
	}
	off := fn.Addr - textVA
	if off >= uint64(len(textData)) {
		return ""
	}
	end := off + uint64(fn.Size)
	if end > uint64(len(textData)) {
		end = uint64(len(textData))
	}
	data := textData[off:end]

	h := fnv.New64a()
	buf := [2]byte{}
	pos := 0
	for pos < len(data) {
		instr, err := d.Decode(data[pos:], fn.Addr+uint64(pos))
		if err != nil {
			pos++
			continue
		}
		buf[0] = byte(instr.Op)
		if instr.Indirect {
			buf[1] = 1
		} else {
			buf[1] = 0
		}
		h.Write(buf[:])
		pos += instr.Len
	}
	return fmt.Sprintf("%016x", h.Sum64())
}
