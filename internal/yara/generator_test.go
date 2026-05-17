package yara

import (
	"strings"
	"testing"

	"github.com/muxover/goripper/internal/output"
)

func makeResult(format string, strs []output.StringOutput) *output.AnalysisResult {
	return &output.AnalysisResult{
		BinaryInfo: output.BinaryInfo{
			Path:   "/tmp/sample.exe",
			Format: format,
		},
		Strings: strs,
	}
}

func TestGenerate_ContainsRuleName(t *testing.T) {
	result := makeResult("pe", nil)
	rule := Generate(result)
	if !strings.Contains(rule, "rule sample ") && !strings.Contains(rule, "rule sample{") {
		t.Errorf("expected rule name derived from filename, got:\n%s", rule)
	}
}

func TestGenerate_PECondition(t *testing.T) {
	result := makeResult("pe", nil)
	rule := Generate(result)
	if !strings.Contains(rule, "0x5A4D") {
		t.Errorf("expected PE magic in condition, got:\n%s", rule)
	}
}

func TestGenerate_ELFCondition(t *testing.T) {
	result := makeResult("elf", nil)
	rule := Generate(result)
	if !strings.Contains(rule, "0x464C457F") {
		t.Errorf("expected ELF magic in condition, got:\n%s", rule)
	}
}

func TestGenerate_IncludesURLStrings(t *testing.T) {
	result := makeResult("pe", []output.StringOutput{
		{Value: "https://c2.example.com/upload", Type: "url"},
	})
	rule := Generate(result)
	if !strings.Contains(rule, "c2.example.com") {
		t.Errorf("expected URL string in rule, got:\n%s", rule)
	}
}

func TestGenerate_SkipsShortStrings(t *testing.T) {
	result := makeResult("pe", []output.StringOutput{
		{Value: "short", Type: "url"},
		{Value: "https://c2.example.com/upload", Type: "url"},
	})
	rule := Generate(result)
	if strings.Contains(rule, `"short"`) {
		t.Errorf("expected short string to be skipped, got:\n%s", rule)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/tmp/malware.exe", "malware"},
		{"C:\\samples\\rat.bin", "rat"},
		{"123start.exe", "rule_123start"},
		{"my-binary.elf", "my_binary"},
	}
	for _, c := range cases {
		got := sanitizeName(c.input)
		if got != c.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}
