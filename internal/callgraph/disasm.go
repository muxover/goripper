package callgraph

import (
	"fmt"

	"github.com/muxover/goripper/internal/functions"
	"golang.org/x/arch/x86/x86asm"
)

// Build disassembles the text section and extracts all CALL edges for each function.
func Build(funcs []functions.Function, textData []byte, textVA uint64) (*CallGraph, error) {
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

		funcData := textData[offset : offset+size]
		edges, err := disasmFunc(fn.Name, fn.Addr, funcData, addrIndex)
		if err != nil {
			// Non-fatal: skip functions that can't be disassembled
			continue
		}

		for _, edge := range edges {
			graph.AddEdge(edge)
		}
	}

	return graph, nil
}

// disasmFunc disassembles a single function's bytes and returns its call edges.
func disasmFunc(funcName string, funcVA uint64, data []byte, addrIndex []AddrName) ([]CallEdge, error) {
	var edges []CallEdge
	pos := 0

	for pos < len(data) {
		inst, err := x86asm.Decode(data[pos:], 64)
		if err != nil {
			// Skip one byte on decode error (data mixed with code, or truncated)
			pos++
			continue
		}

		instrVA := funcVA + uint64(pos)

		if inst.Op == x86asm.CALL {
			edge := resolveCall(funcName, instrVA, inst, addrIndex)
			edges = append(edges, edge)
		}

		pos += inst.Len
	}

	return edges, nil
}

// resolveCall resolves a CALL instruction to a named target if possible.
func resolveCall(caller string, callVA uint64, inst x86asm.Inst, addrIndex []AddrName) CallEdge {
	edge := CallEdge{
		Caller:   caller,
		CallSite: callVA,
		Resolved: false,
	}

	if len(inst.Args) == 0 || inst.Args[0] == nil {
		edge.Callee = "<indirect>"
		return edge
	}

	switch arg := inst.Args[0].(type) {
	case x86asm.Rel:
		// Direct CALL: E8 rel32
		// Target VA = callVA + instrLen + rel
		targetVA := callVA + uint64(inst.Len) + uint64(arg)
		name, found := LookupAddr(addrIndex, targetVA)
		if found {
			edge.Callee = name
			edge.Resolved = true
		} else {
			edge.Callee = fmt.Sprintf("0x%x", targetVA)
		}

	case x86asm.Mem:
		// Indirect CALL via memory: CALL [rip+disp], CALL [reg+off], etc.
		if arg.Base == x86asm.RIP {
			// RIP-relative: could be PLT stub or vtable dispatch
			edge.Callee = fmt.Sprintf("[rip+0x%x]", arg.Disp)
		} else {
			edge.Callee = "<indirect:mem>"
		}

	case x86asm.Reg:
		// CALL reg — fully indirect, can't resolve statically
		edge.Callee = fmt.Sprintf("<indirect:reg:%s>", arg)

	default:
		edge.Callee = "<indirect>"
	}

	return edge
}
