package taint

import "strings"

var sources = []source{
	{"os.Args", "os.Args"},
	{"os.Stdin", "os.Stdin"},
	{"os.Getenv", "os.Getenv"},
	{"os.LookupEnv", "os.LookupEnv"},
	{"os.ReadFile", "os.ReadFile"},
	{"os.Open", "os.Open"},
	{"net/http.Request.Body", "net/http.(*Request)."},
	{"net.Conn.Read", "net.(*TCPConn).Read"},
	{"bufio.Scanner", "bufio.(*Scanner)."},
}

var sinks = []sink{
	{"os/exec.Command", "os/exec.Command"},
	{"syscall.Exec", "syscall.Exec"},
	{"database/sql.Query", "database/sql.(*DB).Query"},
	{"database/sql.Exec", "database/sql.(*DB).Exec"},
	{"os.WriteFile", "os.WriteFile"},
	{"os.Create", "os.Create"},
	{"net.Conn.Write", "net.(*TCPConn).Write"},
	{"http.ResponseWriter.Write", "net/http.(*response).Write"},
	{"encoding/json.Unmarshal", "encoding/json.Unmarshal"},
	{"encoding/gob.Decode", "encoding/gob.(*Decoder).Decode"},
	{"html/template.Execute", "html/template.(*Template).Execute"},
}

// Analyze performs inter-procedural taint analysis using the call graph.
func Analyze(calls map[string][]string, calledBy map[string][]string) []TaintFlow {
	sourceCallers := findCallers(calls, sources)
	sinkCallers := findSinkCallers(calls)
	if len(sourceCallers) == 0 || len(sinkCallers) == 0 {
		return nil
	}

	var flows []TaintFlow
	seen := make(map[string]bool) // deduplicate (sourceName+sinkName+sinkFunc)

	for srcFunc, srcName := range sourceCallers {
		paths := bfsToSinks(srcFunc, sinkCallers, calledBy)
		for _, p := range paths {
			sinkFunc := p[len(p)-1]
			sinkName := sinkCallers[sinkFunc]
			key := srcName + "\x00" + sinkName + "\x00" + sinkFunc
			if seen[key] {
				continue
			}
			seen[key] = true
			flows = append(flows, TaintFlow{
				Source:     srcName,
				SourceFunc: srcFunc,
				Sink:       sinkName,
				SinkFunc:   sinkFunc,
				Path:       p,
				Confidence: confidence(len(p)),
			})
		}
	}

	return flows
}

func findCallers(calls map[string][]string, srcs []source) map[string]string {
	result := make(map[string]string)
	for caller, callees := range calls {
		for _, callee := range callees {
			for _, s := range srcs {
				if strings.HasPrefix(callee, s.pattern) || callee == s.pattern {
					if _, exists := result[caller]; !exists {
						result[caller] = s.name
					}
				}
			}
		}
	}
	return result
}

func findSinkCallers(calls map[string][]string) map[string]string {
	result := make(map[string]string)
	for caller, callees := range calls {
		for _, callee := range callees {
			for _, s := range sinks {
				if strings.HasPrefix(callee, s.pattern) || callee == s.pattern {
					if _, exists := result[caller]; !exists {
						result[caller] = s.name
					}
				}
			}
		}
	}
	return result
}

// bfsToSinks finds paths from a source function to sink callers.
// Tainted data flows upward: callers of a tainted function may receive tainted
// return values, so we propagate through calledBy edges. We also check if the
// source function itself calls a sink directly.
func bfsToSinks(start string, sinkCallers map[string]string, calledBy map[string][]string) [][]string {
	type state struct {
		node string
		path []string
	}

	visited := map[string]bool{start: true}
	queue := []state{{start, []string{start}}}
	var results [][]string
	foundSinks := map[string]bool{}

	// source function itself may also call a sink directly
	if _, isSink := sinkCallers[start]; isSink {
		foundSinks[start] = true
		results = append(results, []string{start})
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if _, isSink := sinkCallers[cur.node]; isSink && cur.node != start {
			if !foundSinks[cur.node] {
				foundSinks[cur.node] = true
				cp := make([]string, len(cur.path))
				copy(cp, cur.path)
				results = append(results, cp)
			}
			continue
		}

		// cap BFS depth at 8 hops to avoid combinatorial explosion
		if len(cur.path) >= 8 {
			continue
		}

		// propagate upward: callers of cur.node may receive tainted data
		for _, caller := range calledBy[cur.node] {
			if !visited[caller] {
				visited[caller] = true
				newPath := make([]string, len(cur.path)+1)
				copy(newPath, cur.path)
				newPath[len(cur.path)] = caller
				queue = append(queue, state{caller, newPath})
			}
		}
	}

	return results
}

func confidence(pathLen int) string {
	switch {
	case pathLen <= 2:
		return "high"
	case pathLen <= 4:
		return "medium"
	default:
		return "low"
	}
}
