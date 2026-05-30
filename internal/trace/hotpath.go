package trace

import (
	"fmt"
	"io"
	"sort"

	"github.com/muxover/goripper/internal/output"
)

// The root represents total execution (100%).
func PrintHotPath(w io.Writer, events []Event, funcs []output.FunctionOutput) {
	callCounts := make(map[string]int)
	for _, ev := range events {
		if ev.Type == EventCall && ev.Func != "" {
			callCounts[ev.Func]++
		}
	}
	if len(callCounts) == 0 {
		fmt.Fprintln(w, "(no call events recorded)")
		return
	}

	// We maintain a call stack per goroutine; since we don't have goroutine IDs
	// in all backends, we use a single shared stack as an approximation.
	type edge struct {
		caller string
		callee string
	}
	edgeCounts := make(map[edge]int)
	var stack []string
	for _, ev := range events {
		switch ev.Type {
		case EventCall:
			if len(stack) > 0 {
				e := edge{caller: stack[len(stack)-1], callee: ev.Func}
				edgeCounts[e]++
			}
			stack = append(stack, ev.Func)
		case EventReturn:
			if len(stack) > 0 && stack[len(stack)-1] == ev.Func {
				stack = stack[:len(stack)-1]
			}
		}
	}

	calleeSet := make(map[string]bool)
	for e := range edgeCounts {
		calleeSet[e.callee] = true
	}
	roots := make([]string, 0)
	for name := range callCounts {
		if !calleeSet[name] {
			roots = append(roots, name)
		}
	}
	// If we can't determine roots from edges, fall back to highest call counts.
	if len(roots) == 0 {
		type kv struct {
			name  string
			count int
		}
		var kvs []kv
		for name, c := range callCounts {
			kvs = append(kvs, kv{name, c})
		}
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].count > kvs[j].count })
		if len(kvs) > 0 {
			roots = []string{kvs[0].name}
		}
	}
	sort.Strings(roots)

	totalCalls := 0
	for _, c := range callCounts {
		totalCalls += c
	}

	type child struct {
		name  string
		count int
	}
	childrenOf := make(map[string][]child)
	for e, c := range edgeCounts {
		childrenOf[e.caller] = append(childrenOf[e.caller], child{e.callee, c})
	}
	for name := range childrenOf {
		sort.Slice(childrenOf[name], func(i, j int) bool {
			return childrenOf[name][i].count > childrenOf[name][j].count
		})
	}

	var printNode func(name string, count int, total int, prefix string, isLast bool, depth int)
	printNode = func(name string, count int, total int, prefix string, isLast bool, depth int) {
		if depth > 10 {
			return
		}
		pct := 0.0
		if total > 0 {
			pct = float64(count) * 100.0 / float64(total)
		}
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		if depth == 0 {
			fmt.Fprintf(w, "%s (%.0f%%)\n", name, pct)
		} else {
			fmt.Fprintf(w, "%s%s%s (%.0f%%)\n", prefix, connector, name, pct)
		}

		children := childrenOf[name]
		childPrefix := prefix
		if depth > 0 {
			if isLast {
				childPrefix += "      "
			} else {
				childPrefix += "│     "
			}
		}
		for i, c := range children {
			last := i == len(children)-1
			printNode(c.name, c.count, total, childPrefix, last, depth+1)
		}
	}

	for i, root := range roots {
		last := i == len(roots)-1
		printNode(root, callCounts[root], totalCalls, "", last, 0)
	}
}
