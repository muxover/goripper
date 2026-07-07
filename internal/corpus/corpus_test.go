package corpus

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/muxover/goripper/internal/decompile"
	"github.com/muxover/goripper/internal/pipeline"
)

// manifest is the ground truth for one corpus program: the user functions and
// call targets we expect to see recovered in the decompiled output.
type manifest struct {
	program string
	funcs   []string
	calls   []string
}

var manifests = []manifest{
	{"controlflow", []string{"classify", "sumTo", "grade"}, []string{"classify", "sumTo", "grade"}},
	{"structs", []string{"abs", "manhattan", "makePoint"}, []string{"abs", "makePoint"}},
	{"slicesmaps", []string{"sumSlice", "countWords"}, []string{"sumSlice", "countWords"}},
	{"goroutines", []string{"parallelSum"}, []string{"parallelSum"}},
	{"interfaces", []string{"area", "totalArea", "safeDiv"}, []string{"totalArea", "safeDiv"}},
	{"deferpanic", []string{"mustPositive"}, []string{"mustPositive"}},
}

type score struct {
	program        string
	funcsExpected  int
	funcsFound     int
	callsExpected  int
	callsFound     int
	rawGotos       int
	commentedLogic int
	structured     int
	richTypes      bool
}

var richTypeRe = regexp.MustCompile(`\b(string|float64|float32|\[\]\w|map\[|chan |struct\b|\*[A-Za-z])`)

// TestCorpusScores compiles every corpus program, decompiles it through the shared
// pipeline, and scores the output against its manifest. It records a baseline rather
// than asserting targets — threshold gates are added as the v0.9 layers land.
func TestCorpusScores(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	root := repoRoot(t)
	progDir := filepath.Join(root, "testdata", "corpus", "programs")

	var scores []score
	for _, m := range manifests {
		scores = append(scores, scoreProgram(t, progDir, m))
	}

	table := renderScores(scores)
	t.Log("\n" + table)

	if os.Getenv("CORPUS_UPDATE") != "" {
		out := filepath.Join(root, "testdata", "corpus", "SCORES.md")
		if err := os.WriteFile(out, []byte(scoresDoc(table)), 0o644); err != nil {
			t.Fatalf("write SCORES.md: %v", err)
		}
		t.Logf("wrote %s", out)
	}
}

func scoreProgram(t *testing.T, progDir string, m manifest) score {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, m.program+".exe")

	build := exec.Command("go", "build", "-o", bin, filepath.Join(progDir, m.program+".go"))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", m.program, err, out)
	}

	funcs, err := pipeline.LiftBinary(bin, 0)
	if err != nil {
		t.Fatalf("lift %s: %v", m.program, err)
	}
	outDir := filepath.Join(tmp, "out")
	if err := decompile.EmitGo(funcs, decompile.Options{OutDir: outDir, Lang: "go"}); err != nil {
		t.Fatalf("emit %s: %v", m.program, err)
	}
	code := readAllGo(t, outDir)

	s := score{program: m.program, funcsExpected: len(m.funcs), callsExpected: len(m.calls)}
	s.richTypes = richTypeRe.MatchString(code)
	for _, fn := range m.funcs {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(fn) + `\b`).MatchString(code) {
			s.funcsFound++
		}
	}
	for _, c := range m.calls {
		if hasCall(code, c) {
			s.callsFound++
		}
	}
	for _, line := range strings.Split(code, "\n") {
		tr := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(tr, "goto "):
			s.rawGotos++
		case isCommentedLogic(tr):
			s.commentedLogic++
		case strings.HasPrefix(tr, "if ") || strings.HasPrefix(tr, "for ") || strings.HasPrefix(tr, "switch "):
			s.structured++
		}
	}
	return s
}

// hasCall reports whether name appears at a call site — a line that is neither a
// function declaration nor a comment and contains name immediately before a paren.
func hasCall(code, name string) bool {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
	for _, line := range strings.Split(code, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "func ") || strings.HasPrefix(t, "//") {
			continue
		}
		if re.MatchString(t) {
			return true
		}
	}
	return false
}

func isCommentedLogic(trimmed string) bool {
	for _, p := range []string{"// load ", "// arith ", "// store ", "// assign ", "// unary "} {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

func readAllGo(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			b.Write(data)
			b.WriteByte('\n')
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read output %s: %v", dir, err)
	}
	return b.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above test dir")
		}
		dir = parent
	}
}

func renderScores(scores []score) string {
	var b strings.Builder
	b.WriteString("| Program | Funcs | Calls | Raw gotos | Elided logic | Structured | Rich types |\n")
	b.WriteString("|---------|-------|-------|-----------|--------------|------------|------------|\n")
	var fE, fF, cE, cF, gotos, elided, structured int
	rich := 0
	for _, s := range scores {
		b.WriteString(fmt.Sprintf("| %s | %d/%d | %d/%d | %d | %d | %d | %v |\n",
			s.program, s.funcsFound, s.funcsExpected, s.callsFound, s.callsExpected,
			s.rawGotos, s.commentedLogic, s.structured, s.richTypes))
		fE += s.funcsExpected
		fF += s.funcsFound
		cE += s.callsExpected
		cF += s.callsFound
		gotos += s.rawGotos
		elided += s.commentedLogic
		structured += s.structured
		if s.richTypes {
			rich++
		}
	}
	b.WriteString(fmt.Sprintf("| **total** | **%d/%d** | **%d/%d** | **%d** | **%d** | **%d** | **%d/%d** |\n",
		fF, fE, cF, cE, gotos, elided, structured, rich, len(scores)))
	return b.String()
}

func scoresDoc(table string) string {
	return fmt.Sprintf(`# Decompiler Corpus Scores

Recorded %s. Higher is better for funcs/calls/structured/rich types; **lower** is better
for raw gotos and elided logic. These are the acceptance ruler for v0.9.0 — regenerate
with `+"`CORPUS_UPDATE=1 go test ./internal/corpus`"+`.

Proxies (Task 1): funcs/calls = manifest names recovered; raw gotos = unstructured jumps;
elided logic = real logic emitted as comments; structured = real if/for/switch; rich types
= any non-int64 type recovered. Human-readability scoring is added with the readable emitter.

%s
`, time.Now().Format("2006-01-02"), table)
}
