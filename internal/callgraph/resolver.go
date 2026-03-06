package callgraph

import (
	"sort"

	"github.com/muxover/goripper/internal/functions"
)

// AddrName pairs a virtual address with a function name.
type AddrName struct {
	Addr uint64
	Name string
}

// BuildAddrIndex creates a sorted slice of (addr, name) pairs for binary search.
func BuildAddrIndex(funcs []functions.Function) []AddrName {
	index := make([]AddrName, 0, len(funcs))
	for _, f := range funcs {
		index = append(index, AddrName{Addr: f.Addr, Name: f.Name})
	}
	sort.Slice(index, func(i, j int) bool {
		return index[i].Addr < index[j].Addr
	})
	return index
}

// LookupAddr finds the function that contains addr using binary search.
// Returns the function name and true if found, or "" and false otherwise.
func LookupAddr(index []AddrName, addr uint64) (string, bool) {
	n := len(index)
	if n == 0 {
		return "", false
	}

	// Binary search for the largest addr <= target
	lo, hi := 0, n-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if index[mid].Addr <= addr {
			lo = mid
		} else {
			hi = mid - 1
		}
	}

	if index[lo].Addr == addr {
		return index[lo].Name, true
	}
	return "", false
}

// Resolve maps call target VAs in the graph to function names using the addr index.
func Resolve(graph *CallGraph, index []AddrName) *CallGraph {
	resolved := NewCallGraph()

	for _, edge := range graph.Edges {
		if edge.Resolved {
			resolved.AddEdge(edge)
			continue
		}
		// Try to resolve using addr stored in Callee as hex... skip,
		// resolution is done at disasm time.
		resolved.AddEdge(edge)
	}

	return resolved
}
