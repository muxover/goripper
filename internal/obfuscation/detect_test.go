package obfuscation

import (
	"testing"

	"github.com/muxover/goripper/internal/functions"
	gstrings "github.com/muxover/goripper/internal/strings"
)

// makeFunc is a test helper that builds a minimal Function.
func makeFunc(name string, size uint64) functions.Function {
	return functions.Function{
		Name:   name,
		Addr:   0x401000,
		Size:   size,
		Source: functions.SourcePclntab,
	}
}

func TestShannonEntropy_KnownValues(t *testing.T) {
	tests := []struct {
		input   string
		wantMin float64
		wantMax float64
	}{
		{"aaaaaaa", 0.0, 0.01},           // all same char → 0
		{"ab", 1.0, 1.01},                // two equal-frequency chars → 1
		{"aBcDeF1234567890", 3.5, 4.5},   // mixed → moderate entropy
		{"xK9mP2qR7wL", 3.2, 4.0},        // garble-like short hash
	}
	for _, tt := range tests {
		h := shannonEntropy(tt.input)
		if h < tt.wantMin || h > tt.wantMax {
			t.Errorf("shannonEntropy(%q) = %.4f, want [%.2f, %.2f]",
				tt.input, h, tt.wantMin, tt.wantMax)
		}
	}
}

func TestDetect_CleanBinary_LowScore(t *testing.T) {
	funcs := []functions.Function{
		makeFunc("main.main", 100),
		makeFunc("main.server", 200),
		makeFunc("net/http.Get", 50),
		makeFunc("runtime.mallocgc", 80),
		makeFunc("fmt.Println", 40),
	}
	strs := []gstrings.ExtractedString{
		{Value: "hello world"},
		{Value: "https://example.com"},
	}
	r := Detect(funcs, strs, true /* hasBuildInfo */)
	if r.Score > 0.20 {
		t.Errorf("clean binary score = %.3f, want <= 0.20 (indicators: %v)", r.Score, r.Indicators)
	}
	if r.Level != "none" && r.Level != "low" {
		t.Errorf("clean binary level = %q, want none or low", r.Level)
	}
}

func TestDetect_GarbledBinary_HighScore(t *testing.T) {
	// Garbled function names: short random-looking hex identifiers, no dots.
	garbledNames := []string{
		"aB3xK9mP", "rQ7wL2nE", "vT5jH8dC", "fU6yI1oN",
		"zA4sG0pM", "bX9tF3eR", "cW2uD7lV", "dY1vB5kS",
	}
	funcs := make([]functions.Function, len(garbledNames))
	for i, name := range garbledNames {
		funcs[i] = makeFunc(name, 60)
	}
	// Very few strings (garble encrypts them).
	strs := []gstrings.ExtractedString{}

	r := Detect(funcs, strs, false /* no build info */)
	if r.Score < 0.35 {
		t.Errorf("garbled binary score = %.3f, want >= 0.35 (indicators: %v)", r.Score, r.Indicators)
	}
	if r.Level == "none" {
		t.Errorf("garbled binary level = %q, want low/medium/high", r.Level)
	}
}

func TestDetect_EmptyFuncs_ReturnsZero(t *testing.T) {
	r := Detect(nil, nil, true)
	if r.Score != 0 {
		t.Errorf("empty input score = %.3f, want 0", r.Score)
	}
}

func TestDetect_NoBuildInfo_RaisesScore(t *testing.T) {
	funcs := []functions.Function{
		makeFunc("main.main", 100),
		makeFunc("main.run", 200),
	}
	withBuild := Detect(funcs, nil, true)
	withoutBuild := Detect(funcs, nil, false)
	if withoutBuild.Score <= withBuild.Score {
		t.Errorf("missing build info should raise score: with=%.3f without=%.3f",
			withBuild.Score, withoutBuild.Score)
	}
}

func TestScoreLevel_Boundaries(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0.0, "none"},
		{0.14, "none"},
		{0.15, "low"},
		{0.34, "low"},
		{0.35, "medium"},
		{0.59, "medium"},
		{0.60, "high"},
		{1.0, "high"},
	}
	for _, tt := range tests {
		got := scoreLevel(tt.score)
		if got != tt.want {
			t.Errorf("scoreLevel(%.2f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestIsGarbledName_Table(t *testing.T) {
	// These cases are unambiguous regardless of exact entropy threshold.
	falseTests := []string{
		"",                // empty
		"a",               // too short
		"main.main",       // normal Go name, low entropy
		"runtime.mallocgc",// normal Go name, low entropy
		"verylongidentifierthatismorethantwentyfourcharacterslong", // too long last segment
	}
	for _, name := range falseTests {
		if isGarbledName(name) {
			t.Errorf("isGarbledName(%q) = true, want false", name)
		}
	}

	// Garble names: high entropy AND contain digits.
	trueTests := []string{
		"xK9mP2qRwL",  // 10 unique chars, has digits
		"t3R7mK2nPq",  // 10 unique chars, has digits
		"aB3xK9mPqR",  // 10 unique chars, has digits
	}
	for _, name := range trueTests {
		if !isGarbledName(name) {
			t.Errorf("isGarbledName(%q) = false, want true (entropy=%.3f)",
				name, shannonEntropy(name))
		}
	}
}

func TestRelabel_AppliesLabels_WhenScoreHigh(t *testing.T) {
	// Use a name with 10 unique chars → entropy ≈ 3.32 > 3.1 → isGarbledName=true.
	fn := functions.Function{
		Name:  "xK9mP2qRwL",
		Addr:  0x401000,
		Size:  50,
		Calls: []string{"net.Dial"},
	}
	result := Relabel([]functions.Function{fn}, 0.8)
	found := false
	for _, tag := range result[0].Tags {
		if tag == "[suspected:network_connect]" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected [suspected:network_connect] tag, got tags: %v", result[0].Tags)
	}
}

func TestRelabel_NoLabels_WhenScoreLow(t *testing.T) {
	fn := functions.Function{
		Name:  "xK9mP2qRwL",
		Calls: []string{"net.Dial"},
	}
	result := Relabel([]functions.Function{fn}, 0.3)
	for _, tag := range result[0].Tags {
		if tag == "[suspected:network_connect]" {
			t.Errorf("should not relabel when score < 0.5, got tag: %q", tag)
		}
	}
}

func TestRelabel_SkipsKnownFunctions(t *testing.T) {
	fn := functions.Function{
		Name:  "main.handleRequest",
		Calls: []string{"net.Dial"},
	}
	result := Relabel([]functions.Function{fn}, 0.9)
	for _, tag := range result[0].Tags {
		if tag == "[suspected:network_connect]" {
			t.Errorf("should not relabel non-garbled function %q", fn.Name)
		}
	}
}
