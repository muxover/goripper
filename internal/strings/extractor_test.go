package strings_test

import (
	"encoding/binary"
	"testing"

	gstrings "github.com/muxover/goripper/internal/strings"
)

func makeRodata(rodataVA uint64, strings map[uint64]string) []byte {
	// Find the maximum offset needed
	maxOff := uint64(256) // minimum size for headers
	for va, s := range strings {
		off := va - rodataVA
		if off+uint64(len(s)) > maxOff {
			maxOff = off + uint64(len(s)) + 16
		}
	}
	data := make([]byte, maxOff)
	for va, s := range strings {
		off := va - rodataVA
		copy(data[off:], s)
	}
	return data
}

func TestExtract_Empty(t *testing.T) {
	strs := gstrings.Extract([]byte{}, 0x1000)
	if len(strs) != 0 {
		t.Errorf("expected 0 strings from empty input, got %d", len(strs))
	}
}

func TestExtract_FindsHeaderPairs(t *testing.T) {
	const rodataVA = uint64(0x1000)
	data := make([]byte, 256)

	// Place string "hello world" (len=11) at offset 0x20 (VA 0x1020)
	const strOffset = uint64(0x20)
	const strVal = "hello world"
	copy(data[strOffset:], strVal)

	// Write header at offset 0: ptr=0x1020, len=11
	binary.LittleEndian.PutUint64(data[0:8], rodataVA+strOffset)
	binary.LittleEndian.PutUint64(data[8:16], uint64(len(strVal)))

	strs := gstrings.Extract(data, rodataVA)
	if len(strs) != 1 {
		t.Fatalf("expected 1 string, got %d", len(strs))
	}
	if strs[0].Value != strVal {
		t.Errorf("expected %q, got %q", strVal, strs[0].Value)
	}
	if strs[0].Offset != rodataVA+strOffset {
		t.Errorf("expected offset 0x%x, got 0x%x", rodataVA+strOffset, strs[0].Offset)
	}
}

func TestExtract_MinLengthFiltered(t *testing.T) {
	const rodataVA = uint64(0x1000)
	data := make([]byte, 256)

	// String of length 5 — below minStringLen=6, must be filtered
	copy(data[0x20:], "hello")
	binary.LittleEndian.PutUint64(data[0:8], rodataVA+0x20)
	binary.LittleEndian.PutUint64(data[8:16], 5)

	strs := gstrings.Extract(data, rodataVA)
	for _, s := range strs {
		if s.Value == "hello" {
			t.Errorf("string with len<minStringLen should not appear: got %q", s.Value)
		}
	}
}

func TestExtract_NonPrintableFiltered(t *testing.T) {
	const rodataVA = uint64(0x1000)
	data := make([]byte, 256)

	// String with a non-printable byte (0x01) — must be rejected
	copy(data[0x20:], "hello\x01world")
	binary.LittleEndian.PutUint64(data[0:8], rodataVA+0x20)
	binary.LittleEndian.PutUint64(data[8:16], 11)

	strs := gstrings.Extract(data, rodataVA)
	for _, s := range strs {
		if s.Value == "hello\x01world" {
			t.Error("string with non-printable byte must be filtered")
		}
	}
}

func TestExtract_Deduplicated(t *testing.T) {
	const rodataVA = uint64(0x1000)
	data := make([]byte, 256)

	// Two headers both pointing to the same string
	copy(data[0x20:], "duplicate!")
	binary.LittleEndian.PutUint64(data[0:8], rodataVA+0x20)
	binary.LittleEndian.PutUint64(data[8:16], 10)
	binary.LittleEndian.PutUint64(data[16:24], rodataVA+0x20)
	binary.LittleEndian.PutUint64(data[24:32], 10)

	strs := gstrings.Extract(data, rodataVA)
	count := 0
	for _, s := range strs {
		if s.Value == "duplicate!" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduplicated string, got %d", count)
	}
}

func TestExtract_PtrOutsideRodata(t *testing.T) {
	const rodataVA = uint64(0x1000)
	data := make([]byte, 256)

	// Ptr points outside .rodata — must be rejected
	binary.LittleEndian.PutUint64(data[0:8], 0xDEADBEEF) // invalid ptr
	binary.LittleEndian.PutUint64(data[8:16], 10)

	strs := gstrings.Extract(data, rodataVA)
	if len(strs) != 0 {
		t.Errorf("expected 0 strings for out-of-range ptr, got %d", len(strs))
	}
}
