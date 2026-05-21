package similarity

import (
	"testing"

	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
	"github.com/muxover/goripper/internal/output"
)

func TestHashFunction_SameSequence(t *testing.T) {
	d := disasm.New("x86_64")

	// Two identical byte slices must produce the same hash.
	body := []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0x5d, // pop rbp
		0xc3, // ret
	}

	fn := functions.Function{
		Addr: 0x1000,
		Size: uint64(len(body)),
	}

	textData := make([]byte, 0x1000+len(body))
	copy(textData[0x1000:], body)

	h1 := HashFunction(textData, 0, fn, d)
	h2 := HashFunction(textData, 0, fn, d)

	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}
	if h1 != h2 {
		t.Fatalf("same input produced different hashes: %s vs %s", h1, h2)
	}
}

func TestHashFunction_EmptyFunction(t *testing.T) {
	d := disasm.New("x86_64")

	fn := functions.Function{Addr: 0x1000, Size: 0}
	textData := make([]byte, 0x2000)

	h := HashFunction(textData, 0, fn, d)
	if h != "" {
		t.Fatalf("expected empty hash for zero-size function, got %q", h)
	}
}

func TestHashFunction_AddrBelowTextVA(t *testing.T) {
	d := disasm.New("x86_64")

	fn := functions.Function{Addr: 0x500, Size: 10}
	textData := make([]byte, 0x2000)

	// fn.Addr < textVA (0x1000) — should return empty.
	h := HashFunction(textData, 0x1000, fn, d)
	if h != "" {
		t.Fatalf("expected empty hash when addr < textVA, got %q", h)
	}
}

func TestHashFunction_DifferentConstants_SameOpcodes(t *testing.T) {
	d := disasm.New("x86_64")

	// mov eax, 1  (B8 01 00 00 00)
	bodyA := []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}
	// mov eax, 2  (B8 02 00 00 00)
	bodyB := []byte{0xB8, 0x02, 0x00, 0x00, 0x00, 0xC3}

	base := uint64(0x1000)
	fn := functions.Function{Addr: base, Size: uint64(len(bodyA))}

	textA := make([]byte, 0x2000)
	copy(textA[base:], bodyA)
	textB := make([]byte, 0x2000)
	copy(textB[base:], bodyB)

	hA := HashFunction(textA, 0, fn, d)
	hB := HashFunction(textB, 0, fn, d)

	// opcodes are identical (only immediate differs) — hashes must match.
	if hA == "" || hB == "" {
		t.Fatal("expected non-empty hashes")
	}
	if hA != hB {
		t.Fatalf("expected same hash for same opcode sequence, got %s vs %s", hA, hB)
	}
}

func makeResult(path string, hashes []string, pkgs []string) *output.AnalysisResult {
	funcs := make([]output.FunctionOutput, len(hashes))
	for i, h := range hashes {
		pkg := "main"
		if i < len(pkgs) {
			pkg = pkgs[i]
		}
		funcs[i] = output.FunctionOutput{
			Name:           "fn" + string(rune('A'+i)),
			SimilarityHash: h,
			Package:        pkg,
		}
	}
	return &output.AnalysisResult{
		BinaryInfo: output.BinaryInfo{Path: path},
		Functions:  funcs,
	}
}

func TestCompare_AllShared(t *testing.T) {
	hashes := []string{"aabbccdd00000001", "aabbccdd00000002"}
	a := makeResult("/bin/a", hashes, nil)
	b := makeResult("/bin/b", hashes, nil)

	cr := Compare(a, b)
	if cr.SharedFunctions != 2 {
		t.Fatalf("expected 2 shared, got %d", cr.SharedFunctions)
	}
	if cr.SimilarityScore != 1.0 {
		t.Fatalf("expected score 1.0, got %f", cr.SimilarityScore)
	}
	if cr.UniqueToA != 0 || cr.UniqueToB != 0 {
		t.Fatalf("expected 0 unique on each side")
	}
}

func TestCompare_NoShared(t *testing.T) {
	a := makeResult("/bin/a", []string{"aaaa000000000001", "aaaa000000000002"}, nil)
	b := makeResult("/bin/b", []string{"bbbb000000000001", "bbbb000000000002"}, nil)

	cr := Compare(a, b)
	if cr.SharedFunctions != 0 {
		t.Fatalf("expected 0 shared, got %d", cr.SharedFunctions)
	}
	if cr.SimilarityScore != 0 {
		t.Fatalf("expected score 0, got %f", cr.SimilarityScore)
	}
}

func TestCompare_PartialOverlap(t *testing.T) {
	a := makeResult("/bin/a", []string{"shared0000000001", "onlya00000000001"}, nil)
	b := makeResult("/bin/b", []string{"shared0000000001", "onlyb00000000001"}, nil)

	cr := Compare(a, b)
	if cr.SharedFunctions != 1 {
		t.Fatalf("expected 1 shared, got %d", cr.SharedFunctions)
	}
	if cr.UniqueToA != 1 || cr.UniqueToB != 1 {
		t.Fatalf("expected 1 unique each, got a=%d b=%d", cr.UniqueToA, cr.UniqueToB)
	}
}
