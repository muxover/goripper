package callgraph

import (
	"fmt"

	"github.com/muxover/goripper/internal/disasm"
	"github.com/muxover/goripper/internal/functions"
)

func Build(funcs []functions.Function, textData []byte, textVA uint64, d disasm.Disassembler) (*CallGraph, error) {
	if len(textData) == 0 {
		return NewCallGraph(), nil
	}

	addrIndex := BuildAddrIndex(funcs)
	graph := NewCallGraph()

	for _, fn := range funcs {
		if fn.Addr < textVA || fn.Size == 0 {
			continue
		}
		offset := fn.Addr - textVA
		if offset >= uint64(len(textData)) {
			continue
		}
		size := fn.Size
		if offset+size > uint64(len(textData)) {
			size = uint64(len(textData)) - offset
		}
		buildFuncEdges(graph, fn.Name, fn.Addr, textData[offset:offset+size], d, addrIndex)
	}

	return graph, nil
}

func buildFuncEdges(graph *CallGraph, funcName string, funcVA uint64, data []byte, d disasm.Disassembler, addrIndex []AddrName) {
	pos := 0
	for pos < len(data) {
		instr, err := d.Decode(data[pos:], funcVA+uint64(pos))
		if err != nil {
			pos++
			continue
		}
		if instr.Op == disasm.OpCall {
			edge := CallEdge{
				Caller:   funcName,
				CallSite: instr.VA,
				Resolved: false,
			}
			if instr.Indirect {
				edge.Callee = "<indirect>"
			} else if instr.Target != 0 {
				if name, found := LookupAddr(addrIndex, instr.Target); found {
					edge.Callee = name
					edge.Resolved = true
				} else {
					edge.Callee = fmt.Sprintf("0x%x", instr.Target)
				}
			} else {
				edge.Callee = "<indirect>"
			}
			graph.AddEdge(edge)
		}
		pos += instr.Len
	}
}
