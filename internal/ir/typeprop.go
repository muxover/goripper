package ir

import "strings"

var goRuntimeSigs = map[string][2][]string{
	// name → ([param types], [return types])
	"runtime.newobject":    {{"*_type"}, {"void*"}},
	"runtime.makeslice":   {{"*_type", "int64_t", "int64_t"}, {"void*"}},
	"runtime.makemap":     {{"*_type", "int64_t", "void*"}, {"void*"}},
	"runtime.convT64":     {{"uint64_t"}, {"void*"}},
	"runtime.convTstring": {{"GoString"}, {"void*"}},
	"runtime.gopanic":     {{"GoIface"}, {}},
	"runtime.gorecover":   {{}, {"GoIface"}},
	"runtime.newproc":     {{"int32_t", "void*"}, {}},
	"runtime.deferreturn": {{"void*"}, {}},
	"runtime.chansend1":   {{"void*", "void*"}, {}},
	"runtime.chanrecv1":   {{"void*", "void*"}, {}},
	"fmt.Println":         {{"...GoIface"}, {"int64_t", "error"}},
	"fmt.Printf":          {{"GoString", "...GoIface"}, {"int64_t", "error"}},
	"fmt.Sprintf":         {{"GoString", "...GoIface"}, {"GoString"}},
}

func PropTypes(f *IRFunc, typeHints map[string]string) {
	if f.Vars == nil {
		f.Vars = make(map[string]string)
	}

	for k, v := range typeHints {
		if f.Vars[k] == "" {
			f.Vars[k] = v
		}
	}

	for _, blk := range f.Blocks {
		for _, instr := range blk.Instrs {
			switch instr.Op {
			case OpCall:
				propagateCallTypes(f, instr)
			case OpLoad:
				// Loaded values are pointers; type unknown without rtype context.
				if instr.Dst != "" && f.Vars[instr.Dst] == "" {
					f.Vars[instr.Dst] = "void*"
				}
			case OpAssign:
				if len(instr.Src) > 0 && instr.Dst != "" && f.Vars[instr.Dst] == "" {
					if t := f.Vars[instr.Src[0]]; t != "" {
						f.Vars[instr.Dst] = t
					}
				}
			case OpArith:
				if instr.Dst != "" && f.Vars[instr.Dst] == "" {
					f.Vars[instr.Dst] = "int64_t"
				}
			}
		}
	}

	for name := range f.Vars {
		if f.Vars[name] == "" {
			f.Vars[name] = "int64_t"
		}
	}
}

func propagateCallTypes(f *IRFunc, instr IRInstr) {
	sig, known := goRuntimeSigs[instr.Target]
	if !known {
		// Heuristic: calls to runtime.new* return pointers.
		if strings.HasPrefix(instr.Target, "runtime.new") || strings.HasPrefix(instr.Target, "runtime.make") {
			if instr.Dst != "" {
				f.Vars[instr.Dst] = "void*"
			}
		}
		return
	}

	paramTypes := sig[0]
	for i, src := range instr.Src {
		if i < len(paramTypes) && f.Vars[src] == "" {
			f.Vars[src] = paramTypes[i]
		}
	}

	retTypes := sig[1]
	if instr.Dst != "" && len(retTypes) > 0 && f.Vars[instr.Dst] == "" {
		f.Vars[instr.Dst] = retTypes[0]
	}
}
