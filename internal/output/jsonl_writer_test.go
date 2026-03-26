package output_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/muxover/goripper/internal/output"
)

func TestWriteJSONL_EachLineIsValidJSON(t *testing.T) {
	result := makeResult()
	var buf bytes.Buffer
	if err := output.WriteJSONL(&buf, result); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}

	scanner := bufio.NewScanner(&buf)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d is not valid JSON: %q — %v", lineNum, line, err)
		}
	}
	if lineNum == 0 {
		t.Fatal("WriteJSONL produced no output")
	}
}

func TestWriteJSONL_SummaryIsLast(t *testing.T) {
	result := makeResult()
	var buf bytes.Buffer
	if err := output.WriteJSONL(&buf, result); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	last := lines[len(lines)-1]

	var obj map[string]any
	if err := json.Unmarshal([]byte(last), &obj); err != nil {
		t.Fatalf("last line is not valid JSON: %v", err)
	}
	if obj["type"] != "summary" {
		t.Errorf("last line type = %q, want \"summary\"", obj["type"])
	}
}

func TestWriteJSONL_TypesPresent(t *testing.T) {
	result := makeResult()
	result.Functions = append(result.Functions, output.FunctionOutput{
		Name: "main.connect", Tags: []string{"NETWORK"},
	})
	var buf bytes.Buffer
	if err := output.WriteJSONL(&buf, result); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}

	out := buf.String()
	for _, want := range []string{`"binary_info"`, `"function"`, `"string"`, `"behavior"`, `"summary"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing type %s", want)
		}
	}
}

func TestWriteJSONL_BinaryInfoFirst(t *testing.T) {
	result := makeResult()
	var buf bytes.Buffer
	if err := output.WriteJSONL(&buf, result); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}

	first := strings.SplitN(buf.String(), "\n", 2)[0]
	var obj map[string]any
	if err := json.Unmarshal([]byte(first), &obj); err != nil {
		t.Fatalf("first line not valid JSON: %v", err)
	}
	if obj["type"] != "binary_info" {
		t.Errorf("first line type = %q, want \"binary_info\"", obj["type"])
	}
}
