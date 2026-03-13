package behaviors_test

import (
	"testing"

	"github.com/muxover/goripper/internal/behaviors"
	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/functions"
	gstrings "github.com/muxover/goripper/internal/strings"
)

// makeGraph builds a CallGraph with a single edge: caller -> callee.
func makeGraph(caller, callee string) *callgraph.CallGraph {
	g := callgraph.NewCallGraph()
	g.AddEdge(callgraph.CallEdge{
		Caller:   caller,
		Callee:   callee,
		Resolved: true,
	})
	return g
}

func tagsFor(t *testing.T, callee string) []string {
	t.Helper()
	fn := functions.Function{Name: "myFunc", Package: "main"}
	graph := makeGraph("myFunc", callee)
	result := behaviors.Tag([]functions.Function{fn}, graph, nil)
	return result[0].Tags
}

func assertTag(t *testing.T, tags []string, want behaviors.BehaviorTag) {
	t.Helper()
	for _, tag := range tags {
		if tag == string(want) {
			return
		}
	}
	t.Errorf("tag %q not found in %v", want, tags)
}

func assertNoTags(t *testing.T, tags []string) {
	t.Helper()
	if len(tags) != 0 {
		t.Errorf("expected no tags, got %v", tags)
	}
}

func TestTag_NetworkCalls(t *testing.T) {
	tags := tagsFor(t, "net.Dial")
	assertTag(t, tags, behaviors.TagNetwork)
}

func TestTag_CryptoCalls(t *testing.T) {
	tags := tagsFor(t, "crypto/tls.(*Conn).Handshake")
	assertTag(t, tags, behaviors.TagCrypto)
}

func TestTag_ExecCalls(t *testing.T) {
	tags := tagsFor(t, "os/exec.(*Cmd).Start")
	assertTag(t, tags, behaviors.TagExecution)
}

func TestTag_FileCalls(t *testing.T) {
	writeTags := tagsFor(t, "os.Create")
	assertTag(t, writeTags, behaviors.TagFileWrite)

	readTags := tagsFor(t, "os.Open")
	assertTag(t, readTags, behaviors.TagFileRead)
}

func TestTag_NoFalsePositives(t *testing.T) {
	fn := functions.Function{Name: "myFunc", Package: "main"}
	graph := makeGraph("myFunc", "fmt.Println")
	result := behaviors.Tag([]functions.Function{fn}, graph, []gstrings.ExtractedString{})
	assertNoTags(t, result[0].Tags)
}
