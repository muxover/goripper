package concurrency

import (
	"strings"

	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/functions"
)

var concurrencyTargets = []struct {
	prefix  string
	exact   bool
	pattern PatternKind
}{
	{"runtime.newproc", true, PatternGoroutineSpawn},
	{"runtime.newproc1", true, PatternGoroutineSpawn},
	{"runtime.chansend1", true, PatternChanSend},
	{"runtime.chansend", true, PatternChanSend},
	{"runtime.chanrecv1", true, PatternChanRecv},
	{"runtime.chanrecv2", true, PatternChanRecv},
	{"runtime.chanrecv", true, PatternChanRecv},
	{"runtime.makechan", false, PatternChanMake},
	{"runtime.selectgo", true, PatternSelect},
	{"sync.(*Mutex).", false, PatternSyncMutex},
	{"sync.(*RWMutex).", false, PatternSyncMutex},
	{"sync.(*WaitGroup).", false, PatternWaitGroup},
	{"sync.(*Once).", false, PatternSyncOnce},
	{"sync/atomic.", false, PatternAtomicOp},
	{"runtime/internal/atomic.", false, PatternAtomicOp},
}

func Detect(graph *callgraph.CallGraph, funcs []functions.Function) ([]ConcurrencyPattern, []functions.Function) {
	var patterns []ConcurrencyPattern
	concurrentFuncs := make(map[string]bool)

	for _, edge := range graph.Edges {
		if !edge.Resolved {
			continue
		}
		kind, ok := matchTarget(edge.Callee)
		if !ok {
			continue
		}

		patterns = append(patterns, ConcurrencyPattern{
			Kind:     kind,
			FuncName: edge.Caller,
			CallSite: edge.CallSite,
		})
		concurrentFuncs[edge.Caller] = true
	}

	result := make([]functions.Function, len(funcs))
	for i, f := range funcs {
		f.IsConcurrent = concurrentFuncs[f.Name]
		result[i] = f
	}

	return patterns, result
}

func matchTarget(callee string) (PatternKind, bool) {
	for _, t := range concurrencyTargets {
		if t.exact {
			if callee == t.prefix {
				return t.pattern, true
			}
		} else {
			if strings.HasPrefix(callee, t.prefix) {
				return t.pattern, true
			}
		}
	}
	return "", false
}
