package callgraph

// CallEdge represents a single CALL instruction from caller to callee.
type CallEdge struct {
	Caller   string
	Callee   string
	CallSite uint64 // VA of the CALL instruction
	Resolved bool   // false if target address could not be mapped to a name
}

// CallGraph holds all call edges and adjacency maps for fast traversal.
type CallGraph struct {
	Edges    []CallEdge
	Calls    map[string][]string // caller -> []callee (direct calls only)
	CalledBy map[string][]string // callee -> []caller
}

// NewCallGraph creates an empty call graph.
func NewCallGraph() *CallGraph {
	return &CallGraph{
		Calls:    make(map[string][]string),
		CalledBy: make(map[string][]string),
	}
}

// AddEdge adds a resolved call edge to the graph.
func (g *CallGraph) AddEdge(edge CallEdge) {
	g.Edges = append(g.Edges, edge)
	if !edge.Resolved {
		return
	}
	g.Calls[edge.Caller] = appendUniq(g.Calls[edge.Caller], edge.Callee)
	g.CalledBy[edge.Callee] = appendUniq(g.CalledBy[edge.Callee], edge.Caller)
}

func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
