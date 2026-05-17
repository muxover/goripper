package taint

import "testing"

func TestAnalyze_DirectFlow(t *testing.T) {
	// fn reads os.Args and calls os/exec.Command directly → high confidence
	calls := map[string][]string{
		"main.run": {"os.Args", "os/exec.Command"},
	}
	calledBy := map[string][]string{
		"os.Args":         {"main.run"},
		"os/exec.Command": {"main.run"},
	}

	flows := Analyze(calls, calledBy)
	if len(flows) == 0 {
		t.Fatal("expected at least one taint flow")
	}

	f := flows[0]
	if f.Source != "os.Args" {
		t.Errorf("source = %q, want os.Args", f.Source)
	}
	if f.Sink != "os/exec.Command" {
		t.Errorf("sink = %q, want os/exec.Command", f.Sink)
	}
	if f.Confidence != "high" {
		t.Errorf("confidence = %q, want high", f.Confidence)
	}
}

func TestAnalyze_MultiHopFlow(t *testing.T) {
	// parseArgs reads os.Args → buildCmd uses result → runCmd calls exec
	calls := map[string][]string{
		"main.parseArgs": {"os.Args"},
		"main.buildCmd":  {"main.parseArgs"},
		"main.runCmd":    {"main.buildCmd", "os/exec.Command"},
		"main.main":      {"main.parseArgs", "main.runCmd"},
	}
	calledBy := map[string][]string{
		"os.Args":         {"main.parseArgs"},
		"main.parseArgs":  {"main.buildCmd", "main.main"},
		"main.buildCmd":   {"main.runCmd"},
		"os/exec.Command": {"main.runCmd"},
	}

	flows := Analyze(calls, calledBy)
	if len(flows) == 0 {
		t.Fatal("expected taint flow through multi-hop path")
	}
}

func TestAnalyze_NoSink(t *testing.T) {
	calls := map[string][]string{
		"main.read": {"os.Args"},
	}
	calledBy := map[string][]string{
		"os.Args": {"main.read"},
	}

	flows := Analyze(calls, calledBy)
	if len(flows) != 0 {
		t.Errorf("expected no flows when no sink present, got %d", len(flows))
	}
}

func TestAnalyze_NoSource(t *testing.T) {
	calls := map[string][]string{
		"main.run": {"os/exec.Command"},
	}
	calledBy := map[string][]string{
		"os/exec.Command": {"main.run"},
	}

	flows := Analyze(calls, calledBy)
	if len(flows) != 0 {
		t.Errorf("expected no flows when no source present, got %d", len(flows))
	}
}

func TestConfidence(t *testing.T) {
	cases := []struct {
		pathLen int
		want    string
	}{
		{1, "high"},
		{2, "high"},
		{3, "medium"},
		{4, "medium"},
		{5, "low"},
		{8, "low"},
	}
	for _, c := range cases {
		got := confidence(c.pathLen)
		if got != c.want {
			t.Errorf("confidence(%d) = %q, want %q", c.pathLen, got, c.want)
		}
	}
}
