package ir

import (
	"fmt"
	"sort"
)

// RenameVars converts the lifted IR into SSA form. Every write to a register
// variable (_rXX) becomes a fresh version (_rXX_vN); phi nodes are placed at the
// iterated dominance frontier of each definition and their operands are filled from
// the version live at the end of each predecessor; reads are rewritten to the
// version live at that point. Register tokens embedded in source, store-address,
// and condition expressions are renamed in place. The _rXX_vN naming is relied on by
// RecoverVars.
func RenameVars(f *IRFunc) {
	if len(f.Blocks) == 0 {
		return
	}

	dom := BuildDomTree(f)
	blockByID := make(map[int]*IRBlock, len(f.Blocks))
	for _, b := range f.Blocks {
		blockByID[b.ID] = b
	}
	entry := f.Blocks[0].ID

	placePhis(f, dom, entry, blockByID)

	counter := make(map[string]int)
	stacks := make(map[string][]string)

	// Parameters are defined at entry and dominate the whole function.
	for _, p := range f.Params {
		if isRegVar(p) {
			v := freshVersion(p, counter)
			stacks[p] = append(stacks[p], v)
			f.Vars[v] = ""
		}
	}

	visited := make(map[int]bool, len(f.Blocks))
	renameBlock(f, dom, blockByID, entry, counter, stacks, visited)

	// Unreachable blocks never get dom-tree renaming; version their defs locally so
	// nothing is left referencing a bare register.
	for _, b := range f.Blocks {
		if !visited[b.ID] {
			renameUnreachable(f, b, counter)
		}
	}

	compactPhis(f)
}

// placePhis inserts phi placeholders (Dst empty, Meta = base register, Src sized to
// the predecessor count) at the iterated dominance frontier of every definition.
func placePhis(f *IRFunc, dom *DomTree, entry int, blockByID map[int]*IRBlock) {
	df := dominanceFrontiers(f, dom)

	defsites := make(map[string]map[int]bool)
	addDef := func(base string, bid int) {
		if defsites[base] == nil {
			defsites[base] = make(map[int]bool)
		}
		defsites[base][bid] = true
	}
	for _, p := range f.Params {
		if isRegVar(p) {
			addDef(p, entry)
		}
	}
	for _, b := range f.Blocks {
		for _, ins := range b.Instrs {
			if ins.Dst != "" && isRegVar(ins.Dst) {
				addDef(ins.Dst, b.ID)
			}
		}
	}

	bases := make([]string, 0, len(defsites))
	for base := range defsites {
		bases = append(bases, base)
	}
	sort.Strings(bases)

	hasPhi := make(map[int]map[string]bool)
	for _, base := range bases {
		var work []int
		for bid := range defsites[base] {
			work = append(work, bid)
		}
		for len(work) > 0 {
			b := work[len(work)-1]
			work = work[:len(work)-1]
			for _, d := range df[b] {
				if hasPhi[d] == nil {
					hasPhi[d] = make(map[string]bool)
				}
				if hasPhi[d][base] {
					continue
				}
				hasPhi[d][base] = true
				blk := blockByID[d]
				phi := IRInstr{Op: OpPhi, Meta: base, Src: make([]string, len(blk.Preds))}
				blk.Instrs = append([]IRInstr{phi}, blk.Instrs...)
				if !defsites[base][d] {
					defsites[base][d] = true
					work = append(work, d)
				}
			}
		}
	}
}

func renameBlock(f *IRFunc, dom *DomTree, blockByID map[int]*IRBlock, bid int, counter map[string]int, stacks map[string][]string, visited map[int]bool) {
	visited[bid] = true
	blk := blockByID[bid]
	var pushed []string

	for i := range blk.Instrs {
		ins := &blk.Instrs[i]
		if ins.Op == OpPhi && ins.Dst == "" {
			base := ins.Meta
			v := freshVersion(base, counter)
			ins.Dst = v
			f.Vars[v] = ""
			stacks[base] = append(stacks[base], v)
			pushed = append(pushed, base)
		}
	}

	for i := range blk.Instrs {
		ins := &blk.Instrs[i]
		if ins.Op == OpPhi {
			continue
		}
		cur := topMap(stacks)
		ins.Src = renameSrcs(ins.Src, cur)
		if ins.Op == OpIf && ins.Meta != "" {
			ins.Meta = renameExpr(ins.Meta, cur)
		}
		if ins.Dst == "" {
			continue
		}
		if isRegVar(ins.Dst) {
			base := ins.Dst
			v := freshVersion(base, counter)
			ins.Dst = v
			f.Vars[v] = ""
			stacks[base] = append(stacks[base], v)
			pushed = append(pushed, base)
		} else {
			// Store/arith into a memory expression: the register tokens are reads.
			ins.Dst = renameExpr(ins.Dst, cur)
		}
	}

	for _, sid := range blk.Succs {
		sblk := blockByID[sid]
		if sblk == nil {
			continue
		}
		idx := predIndex(sblk.Preds, bid)
		if idx < 0 {
			continue
		}
		for i := range sblk.Instrs {
			ph := &sblk.Instrs[i]
			if ph.Op != OpPhi || idx >= len(ph.Src) {
				continue
			}
			if top := topOf(stacks, ph.Meta); top != "" {
				ph.Src[idx] = top
			}
		}
	}

	for _, c := range dom.Children(bid) {
		renameBlock(f, dom, blockByID, c, counter, stacks, visited)
	}

	for _, base := range pushed {
		stacks[base] = stacks[base][:len(stacks[base])-1]
	}
}

func renameUnreachable(f *IRFunc, blk *IRBlock, counter map[string]int) {
	local := make(map[string][]string)
	for i := range blk.Instrs {
		ins := &blk.Instrs[i]
		if ins.Op == OpPhi && ins.Dst == "" {
			v := freshVersion(ins.Meta, counter)
			ins.Dst = v
			f.Vars[v] = ""
			local[ins.Meta] = []string{v}
		}
	}
	for i := range blk.Instrs {
		ins := &blk.Instrs[i]
		if ins.Op == OpPhi {
			continue
		}
		cur := topMap(local)
		ins.Src = renameSrcs(ins.Src, cur)
		if ins.Op == OpIf && ins.Meta != "" {
			ins.Meta = renameExpr(ins.Meta, cur)
		}
		if ins.Dst == "" {
			continue
		}
		if isRegVar(ins.Dst) {
			v := freshVersion(ins.Dst, counter)
			local[ins.Dst] = []string{v}
			ins.Dst = v
			f.Vars[v] = ""
		} else {
			ins.Dst = renameExpr(ins.Dst, cur)
		}
	}
}

// compactPhis drops empty and duplicate operands left by unreachable predecessors
// and clears the base marker stashed in Meta during placement.
func compactPhis(f *IRFunc) {
	for _, b := range f.Blocks {
		for i := range b.Instrs {
			ins := &b.Instrs[i]
			if ins.Op != OpPhi {
				continue
			}
			var ops []string
			seen := make(map[string]bool)
			for _, s := range ins.Src {
				if s == "" || s == ins.Dst || seen[s] {
					continue
				}
				seen[s] = true
				ops = append(ops, s)
			}
			if len(ops) == 0 {
				ops = []string{ins.Meta}
			}
			ins.Src = ops
			ins.Meta = ""
		}
	}
}

// dominanceFrontiers computes DF(b) for every block via the Cooper-Harvey-Kennedy
// runner walk: for each join block, walk each predecessor up the dom tree until the
// join's immediate dominator, adding the join to every block passed.
func dominanceFrontiers(f *IRFunc, dom *DomTree) map[int][]int {
	frontier := make(map[int]map[int]bool)
	for _, b := range f.Blocks {
		if len(b.Preds) < 2 {
			continue
		}
		idomB := dom.Idom(b.ID)
		for _, p := range b.Preds {
			for runner := p; runner != -1 && runner != idomB; runner = dom.Idom(runner) {
				if frontier[runner] == nil {
					frontier[runner] = make(map[int]bool)
				}
				frontier[runner][b.ID] = true
			}
		}
	}
	out := make(map[int][]int, len(frontier))
	for k, set := range frontier {
		ids := make([]int, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		out[k] = ids
	}
	return out
}

func predIndex(preds []int, id int) int {
	for i, p := range preds {
		if p == id {
			return i
		}
	}
	return -1
}

func topOf(stacks map[string][]string, base string) string {
	s := stacks[base]
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func topMap(stacks map[string][]string) map[string]string {
	cur := make(map[string]string, len(stacks))
	for base, s := range stacks {
		if len(s) > 0 {
			cur[base] = s[len(s)-1]
		}
	}
	return cur
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

// renameExpr rewrites whole-word register references inside an expression using the
// current version map.
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

func replaceWord(s, old, newV string) string {
	out := make([]byte, 0, len(s))
	i := 0
	for i < len(s) {
		j := indexOf(s, old, i)
		if j < 0 {
			out = append(out, s[i:]...)
			break
		}
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
