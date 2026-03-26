package diff_test

import (
	"testing"

	"github.com/muxover/goripper/internal/diff"
	"github.com/muxover/goripper/internal/output"
)

func makeResult(funcs []output.FunctionOutput, strs []output.StringOutput) *output.AnalysisResult {
	return &output.AnalysisResult{
		Functions: funcs,
		Strings:   strs,
	}
}

func fn(name string, size uint64, tags ...string) output.FunctionOutput {
	return output.FunctionOutput{Name: name, Size: size, Tags: tags}
}

func str(value, typ string) output.StringOutput {
	return output.StringOutput{Value: value, Type: typ}
}

func TestCompare_AddedFunctions(t *testing.T) {
	a := makeResult([]output.FunctionOutput{fn("main.old", 100)}, nil)
	b := makeResult([]output.FunctionOutput{fn("main.old", 100), fn("main.new", 200)}, nil)

	r := diff.Compare(a, b)

	if len(r.Added) != 1 || r.Added[0].Name != "main.new" {
		t.Fatalf("Added = %v, want [main.new]", r.Added)
	}
	if len(r.Removed) != 0 {
		t.Fatalf("Removed = %v, want []", r.Removed)
	}
}

func TestCompare_RemovedFunctions(t *testing.T) {
	a := makeResult([]output.FunctionOutput{fn("main.old", 100), fn("main.gone", 50)}, nil)
	b := makeResult([]output.FunctionOutput{fn("main.old", 100)}, nil)

	r := diff.Compare(a, b)

	if len(r.Removed) != 1 || r.Removed[0].Name != "main.gone" {
		t.Fatalf("Removed = %v, want [main.gone]", r.Removed)
	}
	if len(r.Added) != 0 {
		t.Fatalf("Added = %v, want []", r.Added)
	}
}

func TestCompare_ModifiedFunctions(t *testing.T) {
	a := makeResult([]output.FunctionOutput{fn("main.process", 1000)}, nil)
	b := makeResult([]output.FunctionOutput{fn("main.process", 2000)}, nil)

	r := diff.Compare(a, b)

	if len(r.Modified) != 1 {
		t.Fatalf("Modified = %v, want 1 entry", r.Modified)
	}
	m := r.Modified[0]
	if m.Name != "main.process" || m.SizeBefore != 1000 || m.SizeAfter != 2000 {
		t.Fatalf("Modified[0] = %+v, want {main.process 1000 2000}", m)
	}
}

func TestCompare_NewStrings(t *testing.T) {
	a := makeResult(nil, []output.StringOutput{str("https://old.example.com", "url")})
	b := makeResult(nil, []output.StringOutput{
		str("https://old.example.com", "url"),
		str("https://new-c2.example.com", "url"),
	})

	r := diff.Compare(a, b)

	if len(r.NewStrings) != 1 || r.NewStrings[0].Value != "https://new-c2.example.com" {
		t.Fatalf("NewStrings = %v, want [https://new-c2.example.com]", r.NewStrings)
	}
}

func TestCompare_NewBehaviors(t *testing.T) {
	a := makeResult([]output.FunctionOutput{fn("main.dial", 100, "NETWORK")}, nil)
	b := makeResult([]output.FunctionOutput{fn("main.dial", 100, "NETWORK"), fn("main.exec", 200, "EXECUTION")}, nil)

	r := diff.Compare(a, b)

	if len(r.NewBehaviors) != 1 || r.NewBehaviors[0] != "EXECUTION" {
		t.Fatalf("NewBehaviors = %v, want [EXECUTION]", r.NewBehaviors)
	}
}

func TestCompare_Identical(t *testing.T) {
	a := makeResult([]output.FunctionOutput{fn("main.main", 500)}, []output.StringOutput{str("hello", "plain")})
	b := makeResult([]output.FunctionOutput{fn("main.main", 500)}, []output.StringOutput{str("hello", "plain")})

	r := diff.Compare(a, b)

	if len(r.Added) != 0 || len(r.Removed) != 0 || len(r.Modified) != 0 || len(r.NewStrings) != 0 || len(r.NewBehaviors) != 0 {
		t.Fatalf("expected empty diff for identical results, got %+v", r)
	}
}
