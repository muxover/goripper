package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/muxover/goripper/internal/output"
)

func makeResult() *output.AnalysisResult {
	return &output.AnalysisResult{
		BinaryInfo: output.BinaryInfo{
			Path:      "/tmp/test.exe",
			Format:    "PE",
			Arch:      "x86_64",
			GoVersion: "go1.24",
			SizeBytes: 1024,
		},
		Functions: []output.FunctionOutput{
			{Name: "main.main", Addr: "0x401000", Package: "main", PackageKind: "user", Size: 100},
			{Name: "fmt.Println", Addr: "0x402000", Package: "fmt", PackageKind: "stdlib", Size: 50},
		},
		Strings: []output.StringOutput{
			{Value: "hello world", Type: "generic"},
			{Value: "https://example.com", Type: "url"},
		},
		Summary: output.SummaryOutput{
			TotalFunctions: 2,
			UserFunctions:  1,
			TotalStrings:   2,
			URLStrings:     1,
		},
	}
}

func TestTextWriter_ProducesExpectedSections(t *testing.T) {
	result := makeResult()
	var buf bytes.Buffer
	output.WriteText(result, &buf, output.TextOptions{})
	out := buf.String()

	checks := []string{
		"=== GoRipper Analysis Report ===",
		"=== Functions",
		"=== Strings",
		"/tmp/test.exe",
		"PE",
		"x86_64",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestJSONWriter_ValidJSON(t *testing.T) {
	result := makeResult()
	var buf bytes.Buffer
	if err := output.WriteJSON(result, &buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded output.AnalysisResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Summary.TotalFunctions == 0 {
		t.Error("decoded TotalFunctions is 0")
	}
	if decoded.BinaryInfo.Format == "" {
		t.Error("decoded Format is empty")
	}
}

func TestTextWriter_Warnings(t *testing.T) {
	result := makeResult()
	result.Warnings = []string{"stage parse panicked: index out of range"}
	var buf bytes.Buffer
	output.WriteText(result, &buf, output.TextOptions{})
	out := buf.String()
	if !strings.Contains(out, "WARNING:") {
		t.Error("expected WARNING: prefix in output")
	}
	if !strings.Contains(out, "index out of range") {
		t.Error("expected warning message in output")
	}
}

func TestTextWriter_CallGraph(t *testing.T) {
	result := makeResult()
	result.CallGraph = map[string][]string{
		"main.main": {"fmt.Println", "os.Exit"},
	}
	var buf bytes.Buffer
	output.WriteText(result, &buf, output.TextOptions{ShowCallGraph: true})
	out := buf.String()
	if !strings.Contains(out, "=== Call Graph ===") {
		t.Error("expected call graph section in output")
	}
	if !strings.Contains(out, "main.main") {
		t.Error("expected caller in call graph")
	}
}

func TestTextWriter_Types(t *testing.T) {
	result := makeResult()
	result.Types = []output.TypeOutput{
		{
			Name: "main.Config",
			Kind: "struct",
			Fields: []output.FieldOutput{
				{Name: "Host", Type: "string", Offset: 0},
				{Name: "Port", Type: "int", Offset: 16},
			},
		},
	}
	var buf bytes.Buffer
	output.WriteText(result, &buf, output.TextOptions{ShowTypes: true})
	out := buf.String()
	if !strings.Contains(out, "=== Recovered Types") {
		t.Error("expected types section")
	}
	if !strings.Contains(out, "main.Config") {
		t.Error("expected type name in output")
	}
}

func TestTextWriter_StringFilter(t *testing.T) {
	result := makeResult()
	var buf bytes.Buffer
	output.WriteText(result, &buf, output.TextOptions{StringFilter: "url"})
	out := buf.String()
	if !strings.Contains(out, "https://example.com") {
		t.Error("expected URL string in filtered output")
	}
	if strings.Contains(out, "hello world") {
		t.Error("generic string should not appear with url filter")
	}
}

func TestTextWriter_NoRuntime(t *testing.T) {
	result := makeResult()
	result.Functions = append(result.Functions, output.FunctionOutput{
		Name: "runtime.mallocgc", Package: "runtime", PackageKind: "runtime", IsRuntime: true,
	})
	var buf bytes.Buffer
	output.WriteText(result, &buf, output.TextOptions{NoRuntime: true})
	out := buf.String()
	if strings.Contains(out, "runtime.mallocgc") {
		t.Error("runtime function should be filtered with NoRuntime=true")
	}
}

func TestJSONWriter_RoundTrip(t *testing.T) {
	result := makeResult()
	var buf bytes.Buffer
	if err := output.WriteJSON(result, &buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded output.AnalysisResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.Summary.TotalFunctions != result.Summary.TotalFunctions {
		t.Errorf("TotalFunctions: got %d, want %d", decoded.Summary.TotalFunctions, result.Summary.TotalFunctions)
	}
	if decoded.Summary.TotalStrings != result.Summary.TotalStrings {
		t.Errorf("TotalStrings: got %d, want %d", decoded.Summary.TotalStrings, result.Summary.TotalStrings)
	}
	if len(decoded.Functions) != len(result.Functions) {
		t.Errorf("Functions len: got %d, want %d", len(decoded.Functions), len(result.Functions))
	}
}
