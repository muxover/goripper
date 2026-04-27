package callgraph

import (
	"sort"

	"github.com/muxover/goripper/internal/functions"
)

type AddrName struct {
	Addr uint64
	Name string
}

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

func LookupAddr(index []AddrName, addr uint64) (string, bool) {
	n := len(index)
	if n == 0 {
		return "", false
	}

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

func Resolve(graph *CallGraph, index []AddrName) *CallGraph {
	resolved := NewCallGraph()
	for _, edge := range graph.Edges {
		resolved.AddEdge(edge)
	}
	return resolved
}
