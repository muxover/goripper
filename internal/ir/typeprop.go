package ir

import "strings"

// goRuntimeSigs maps a callee to its ([param types], [return types]) using the C
// type names the emitters understand (GoString -> string, GoSlice -> []byte, etc.).
// Constructors that reveal a Go aggregate type are the main source of non-int64
// types recovered from a stripped binary.
var goRuntimeSigs = map[string][2][]string{
	"runtime.newobject":         {{"*_type"}, {"void*"}},
	"runtime.makeslice":         {{"*_type", "int64_t", "int64_t"}, {"GoSlice"}},
	"runtime.makeslicecopy":     {{"*_type", "int64_t", "int64_t", "void*"}, {"GoSlice"}},
	"runtime.growslice":         {{"void*", "int64_t", "int64_t", "int64_t", "*_type"}, {"GoSlice"}},
	"runtime.makemap":           {{"*_type", "int64_t", "void*"}, {"void*"}},
	"runtime.makemap_small":     {{}, {"void*"}},
	"runtime.makechan":          {{"*_type", "int64_t"}, {"void*"}},
	"runtime.concatstring2":     {{"void*", "GoString", "GoString"}, {"GoString"}},
	"runtime.concatstring3":     {{"void*", "GoString", "GoString", "GoString"}, {"GoString"}},
	"runtime.concatstring4":     {{"void*", "GoString", "GoString", "GoString", "GoString"}, {"GoString"}},
	"runtime.concatstrings":     {{"void*", "GoSlice"}, {"GoString"}},
	"runtime.slicebytetostring": {{"void*", "void*", "int64_t"}, {"GoString"}},
	"runtime.stringtoslicebyte": {{"void*", "GoString"}, {"GoSlice"}},
	"runtime.intstring":         {{"void*", "int64_t"}, {"GoString"}},
	"runtime.convT64":           {{"uint64_t"}, {"void*"}},
	"runtime.convTstring":       {{"GoString"}, {"GoIface"}},
	"runtime.convTslice":        {{"GoSlice"}, {"GoIface"}},
	"runtime.gopanic":           {{"GoIface"}, {}},
	"runtime.gorecover":         {{}, {"GoIface"}},
	"runtime.newproc":           {{"int32_t", "void*"}, {}},
	"runtime.deferreturn":       {{"void*"}, {}},
	"runtime.chansend1":         {{"void*", "void*"}, {}},
	"runtime.chanrecv1":         {{"void*", "void*"}, {}},
	"errors.New":                {{"GoString"}, {"error"}},
	"fmt.Errorf":                {{"GoString", "...GoIface"}, {"error"}},
	"fmt.Println":               {{"...GoIface"}, {"int64_t", "error"}},
	"fmt.Printf":                {{"GoString", "...GoIface"}, {"int64_t", "error"}},
	"fmt.Sprintf":               {{"GoString", "...GoIface"}, {"GoString"}},
	"fmt.Sprint":                {{"...GoIface"}, {"GoString"}},
}

// PropTypes infers a C type for every variable by iterating call-signature,
// assignment, phi, and arithmetic constraints to a fixpoint, then defaults anything
// still unknown to int64_t. typeHints seeds types recovered elsewhere (e.g. rtype
// analysis) keyed by variable name.
func PropTypes(f *IRFunc, typeHints map[string]string) {
	if f.Vars == nil {
		f.Vars = make(map[string]string)
	}

	set := func(name, typ string) bool {
		if typ == "" || !isPlainIdent(name) || f.Vars[name] != "" {
			return false
		}
		f.Vars[name] = typ
		return true
	}

	for k, v := range typeHints {
		set(k, v)
	}

	for changed := true; changed; {
		changed = false
		for _, blk := range f.Blocks {
			for _, instr := range blk.Instrs {
				switch instr.Op {
				case OpCall:
					changed = propagateCallTypes(f, instr, set) || changed
				case OpLoad:
					changed = set(instr.Dst, "void*") || changed
				case OpAssign:
					if len(instr.Src) > 0 {
						if t := f.Vars[instr.Src[0]]; t != "" {
							changed = set(instr.Dst, t) || changed
						}
					}
				case OpPhi:
					for _, s := range instr.Src {
						if t := f.Vars[s]; t != "" {
							changed = set(instr.Dst, t) || changed
							break
						}
					}
				case OpArith:
					changed = set(instr.Dst, "int64_t") || changed
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

func propagateCallTypes(f *IRFunc, instr IRInstr, set func(string, string) bool) bool {
	changed := false
	sig, known := goRuntimeSigs[instr.Target]
	if !known {
		if strings.HasPrefix(instr.Target, "runtime.new") {
			changed = set(instr.Dst, "void*") || changed
		}
		return changed
	}

	paramTypes := sig[0]
	for i, src := range instr.Src {
		if i < len(paramTypes) {
			changed = set(src, strings.TrimPrefix(paramTypes[i], "...")) || changed
		}
	}
	if ret := sig[1]; len(ret) > 0 {
		changed = set(instr.Dst, ret[0]) || changed
	}
	return changed
}

// isPlainIdent reports whether s is a bare variable name (not a literal, address, or
// composite expression) so type facts are only attached to real variables.
func isPlainIdent(s string) bool {
	if s == "" {
		return false
	}
	if c := s[0]; !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}
