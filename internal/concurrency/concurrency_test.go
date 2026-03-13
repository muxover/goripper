package concurrency_test

import (
	"testing"

	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/concurrency"
	"github.com/muxover/goripper/internal/functions"
)

func makeGraph(caller, callee string) *callgraph.CallGraph {
	g := callgraph.NewCallGraph()
	g.AddEdge(callgraph.CallEdge{
		Caller:   caller,
		Callee:   callee,
		Resolved: true,
	})
	return g
}

func TestDetect_GoroutineSpawn(t *testing.T) {
	fn := functions.Function{Name: "myFunc", Package: "main"}
	graph := makeGraph("myFunc", "runtime.newproc")

	_, updated := concurrency.Detect(graph, []functions.Function{fn})
	if !updated[0].IsConcurrent {
		t.Error("expected IsConcurrent=true for function calling runtime.newproc")
	}
}

func TestDetect_ChannelOp(t *testing.T) {
	fn := functions.Function{Name: "myFunc", Package: "main"}
	graph := makeGraph("myFunc", "runtime.chansend1")

	_, updated := concurrency.Detect(graph, []functions.Function{fn})
	if !updated[0].IsConcurrent {
		t.Error("expected IsConcurrent=true for function calling runtime.chansend1")
	}
}

func TestDetect_NoConcurrency(t *testing.T) {
	fn := functions.Function{Name: "myFunc", Package: "main"}
	graph := makeGraph("myFunc", "fmt.Println")

	_, updated := concurrency.Detect(graph, []functions.Function{fn})
	if updated[0].IsConcurrent {
		t.Error("expected IsConcurrent=false for function calling only fmt.Println")
	}
}
