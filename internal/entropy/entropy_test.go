package entropy

import (
	"math"
	"testing"
)

func TestCalculate_Empty(t *testing.T) {
	if e := Calculate(nil); e != 0 {
		t.Fatalf("expected 0, got %f", e)
	}
}

func TestCalculate_Uniform(t *testing.T) {
	// Single repeated byte has entropy 0.
	data := make([]byte, 1024)
	if e := Calculate(data); e != 0 {
		t.Fatalf("uniform data: expected 0, got %f", e)
	}
}

func TestCalculate_MaxEntropy(t *testing.T) {
	// 256 unique bytes — maximum entropy ≈ 8.0.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := Calculate(data)
	if math.Abs(e-8.0) > 0.01 {
		t.Fatalf("expected ~8.0, got %f", e)
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		e    float64
		want string
	}{
		{0.5, "packed"},
		{5.0, "normal"},
		{6.8, "compressed"},
		{7.5, "encrypted"},
	}
	for _, c := range cases {
		if got := Verdict(c.e); got != c.want {
			t.Errorf("Verdict(%.1f) = %q, want %q", c.e, got, c.want)
		}
	}
}

func TestDetectPacker(t *testing.T) {
	if p := DetectPacker([]string{".text", "UPX0", "UPX1"}); p != "UPX" {
		t.Errorf("expected UPX, got %q", p)
	}
	if p := DetectPacker([]string{"MPRESS1", ".rdata"}); p != "MPRESS" {
		t.Errorf("expected MPRESS, got %q", p)
	}
	if p := DetectPacker([]string{".text", ".rdata", ".data"}); p != "" {
		t.Errorf("expected empty, got %q", p)
	}
}
