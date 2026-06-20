package ir

import "fmt"

// Within each basic block, every write to a register variable (_rXX) creates
// a new versioned name (_rXX_vN). Reads see the most recently written version.
// At block boundaries, versions flow from the single predecessor; join points
// get phi-like assignments at the top of the block (one assignment per live reg).
func RenameVars(f *IRFunc) {
	if len(f.Blocks) == 0 {
		return
	}

	// exitState[blockID] = map of reg → version at block exit.
	exitState := make([]map[string]string, len(f.Blocks))

	counter := make(map[string]int)

	// Seed entry state with v0 for each known parameter register so that
	// any use of the raw register name in the entry block (e.g. AND RAX, mask)
	// resolves to the initial versioned name rather than staying unversioned.
	entryState := make(map[string]string)
	for _, p := range f.Params {
		if isRegVar(p) {
			v0 := freshVersion(p, counter)
			entryState[p] = v0
			f.Vars[v0] = ""
		}
	}

	// Process blocks in ID order (not necessarily dominance order, but good
	// enough for linear code and simple loops since we propagate from preds).
	processed := make([]bool, len(f.Blocks))

	idToIdx := make(map[int]int, len(f.Blocks))
	for i, b := range f.Blocks {
		idToIdx[b.ID] = i
	}

	var processBlock func(idx int, incoming map[string]string)
	processBlock = func(idx int, incoming map[string]string) {
		if processed[idx] {
			return
		}
		processed[idx] = true

		blk := f.Blocks[idx]
		cur := make(map[string]string, len(incoming))
		for k, v := range incoming {
			cur[k] = v
		}

		var newInstrs []IRInstr

		// Emit phi-like assignments at block entry for versions inherited from preds.
		// (Only emit if there are multiple predecessors and version diverges.)
		if len(blk.Preds) > 1 {
			for reg, ver := range cur {
				phiDst := freshVersion(reg, counter)
				newInstrs = append(newInstrs, IRInstr{
					Op:  OpPhi,
					Dst: phiDst,
					Src: []string{ver},
				})
				cur[reg] = phiDst
			}
		}

		for _, instr := range blk.Instrs {
			renamed := instr

			renamed.Src = renameSrcs(instr.Src, cur)
			if instr.Meta != "" && instr.Op == OpIf {
				// The condition string may reference register vars; rename them.
				renamed.Meta = renameExpr(instr.Meta, cur)
			}

			if instr.Dst != "" && isRegVar(instr.Dst) {
				newVer := freshVersion(instr.Dst, counter)
				renamed.Dst = newVer
				cur[instr.Dst] = newVer
			}

			newInstrs = append(newInstrs, renamed)
		}

		blk.Instrs = newInstrs
		exitState[idx] = copyMap(cur)

		for _, succID := range blk.Succs {
			if si, ok := idToIdx[succID]; ok {
				if !processed[si] {
					// Build incoming state: use this block's exit if no prior state,
					// or intersect with existing state from another predecessor.
					succIncoming := exitState[si]
					if succIncoming == nil {
						processBlock(si, cur)
					}
				}
			}
		}
	}

	processBlock(0, entryState)

	// Process any blocks not yet reached (e.g. multiple entry points, dead code).
	for i := range f.Blocks {
		if !processed[i] {
			processBlock(i, make(map[string]string))
		}
	}

	for _, blk := range f.Blocks {
		for _, instr := range blk.Instrs {
			if instr.Dst != "" {
				f.Vars[instr.Dst] = "" // type filled by type propagation
			}
		}
	}
}

func freshVersion(base string, counter map[string]int) string {
	n := counter[base]
	counter[base]++
	return fmt.Sprintf("%s_v%d", base, n)
}

func renameSrcs(srcs []string, cur map[string]string) []string {
	if len(srcs) == 0 {
		return srcs
	}
	out := make([]string, len(srcs))
	for i, s := range srcs {
		out[i] = renameExpr(s, cur)
	}
	return out
}

// renameExpr rewrites register variable references inside an expression string.
// Only exact token matches are replaced to avoid partial name collisions.
func renameExpr(expr string, cur map[string]string) string {
	result := expr
	for old, newV := range cur {
		if newV == "" || old == newV {
			continue
		}
		result = replaceWord(result, old, newV)
	}
	return result
}

// replaceWord replaces whole-word occurrences of old with newV.
// "word" here means surrounded by non-alphanumeric/non-underscore characters.
func replaceWord(s, old, newV string) string {
	out := make([]byte, 0, len(s))
	i := 0
	for i < len(s) {
		j := indexOf(s, old, i)
		if j < 0 {
			out = append(out, s[i:]...)
			break
		}
		// Check word boundaries.
		leftOK := j == 0 || !isWordChar(s[j-1])
		rightOK := j+len(old) >= len(s) || !isWordChar(s[j+len(old)])
		if leftOK && rightOK {
			out = append(out, s[i:j]...)
			out = append(out, newV...)
			i = j + len(old)
		} else {
			out = append(out, s[i:j+1]...)
			i = j + 1
		}
	}
	return string(out)
}

func indexOf(s, sub string, start int) int {
	if len(sub) == 0 || start+len(sub) > len(s) {
		return -1
	}
	for i := start; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
