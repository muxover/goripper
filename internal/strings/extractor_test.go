package strings_test

import (
	"encoding/binary"
	"testing"

	gstrings "github.com/muxover/goripper/internal/strings"
)

// TestSuppressBlobs_RemovesCoveredBlob verifies that a fallback blob is removed
// when 2+ non-blob strings start inside its byte range.
func TestSuppressBlobs_RemovesCoveredBlob(t *testing.T) {
	blob := gstrings.ExtractedString{Value: "hello world foo bar baz", Offset: 0x1000, IsFallbackBlob: true}
	comp1 := gstrings.ExtractedString{Value: "world", Offset: 0x1006}  // inside blob
	comp2 := gstrings.ExtractedString{Value: "foo", Offset: 0x100C}    // inside blob
	input := []gstrings.ExtractedString{blob, comp1, comp2}
	result := gstrings.SuppressBlobs(input)
	for _, s := range result {
		if s.IsFallbackBlob {
			t.Error("blob should have been suppressed")
		}
	}
	if len(result) != 2 {
		t.Errorf("expected 2 component strings, got %d", len(result))
	}
}

// TestSuppressBlobs_KeepsUniqueBlob verifies that a fallback blob is kept when
// fewer than 2 component strings are inside its range.
func TestSuppressBlobs_KeepsUniqueBlob(t *testing.T) {
	blob := gstrings.ExtractedString{Value: "hello world", Offset: 0x2000, IsFallbackBlob: true}
	comp := gstrings.ExtractedString{Value: "world", Offset: 0x2006} // only 1 inside
	input := []gstrings.ExtractedString{blob, comp}
	result := gstrings.SuppressBlobs(input)
	found := false
	for _, s := range result {
		if s.IsFallbackBlob {
			found = true
		}
	}
	if !found {
		t.Error("unique blob should be preserved")
	}
}

// TestSuppressBlobs_EmptyInput handles the empty case without panic.
func TestSuppressBlobs_EmptyInput(t *testing.T) {
	result := gstrings.SuppressBlobs(nil)
	if result == nil {
		t.Error("SuppressBlobs(nil) should return non-nil slice")
	}
}

// TestSuppressBlobs_NoBlobsPassThrough verifies non-blob strings are unchanged.
func TestSuppressBlobs_NoBlobsPassThrough(t *testing.T) {
	strs := []gstrings.ExtractedString{
		{Value: "alpha", Offset: 0x100},
		{Value: "beta", Offset: 0x200},
	}
	result := gstrings.SuppressBlobs(strs)
	if len(result) != 2 {
		t.Errorf("expected 2 strings, got %d", len(result))
	}
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

func TestDeduplicate_MergesReferencedBy(t *testing.T) {
	strs := []gstrings.ExtractedString{
		{Value: "hello world", Type: "plain", Offset: 0x1000, ReferencedBy: []string{"main.foo"}},
		{Value: "hello world", Type: "plain", Offset: 0x1100, ReferencedBy: []string{"main.bar"}},
		{Value: "unique", Type: "plain", Offset: 0x2000},
	}
	result := gstrings.Deduplicate(strs)
	if len(result) != 2 {
		t.Fatalf("expected 2 strings after dedup, got %d", len(result))
	}
	var deduped *gstrings.ExtractedString
	for i := range result {
		if result[i].Value == "hello world" {
			deduped = &result[i]
		}
	}
	if deduped == nil {
		t.Fatal("deduped string not found")
	}
	if len(deduped.ReferencedBy) != 2 {
		t.Errorf("expected merged ReferencedBy of 2, got %d: %v", len(deduped.ReferencedBy), deduped.ReferencedBy)
	}
	// Lower offset should win
	if deduped.Offset != 0x1000 {
		t.Errorf("expected lower offset 0x1000, got 0x%x", deduped.Offset)
	}
}

func TestDeduplicate_PreservesOrder(t *testing.T) {
	strs := []gstrings.ExtractedString{
		{Value: "beta", Type: "plain", Offset: 0x2000},
		{Value: "alpha", Type: "plain", Offset: 0x1000},
	}
	result := gstrings.Deduplicate(strs)
	if len(result) != 2 {
		t.Fatalf("expected 2 strings, got %d", len(result))
	}
	if result[0].Offset >= result[1].Offset {
		t.Error("result should be sorted by offset ascending")
	}
}

func TestDeduplicate_DifferentTypeSameValue(t *testing.T) {
	strs := []gstrings.ExtractedString{
		{Value: "same", Type: "plain", Offset: 0x1000},
		{Value: "same", Type: "url", Offset: 0x2000},
	}
	result := gstrings.Deduplicate(strs)
	if len(result) != 2 {
		t.Errorf("different types with same value should NOT be merged: got %d", len(result))
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
