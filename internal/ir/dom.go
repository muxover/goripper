package ir

// DomTree holds immediate-dominator relationships over an IRFunc's blocks, keyed
// by block ID. It is the shared basis for SSA phi placement and control-flow
// structuring. Built with the Cooper-Harvey-Kennedy iterative algorithm.
type DomTree struct {
	idom     map[int]int
	children map[int][]int
	rpo      []int
}

// BuildDomTree computes the dominator tree for f, treating the first block as the
// entry. Unreachable blocks are omitted.
func BuildDomTree(f *IRFunc) *DomTree {
	d := &DomTree{idom: map[int]int{}, children: map[int][]int{}}
	if len(f.Blocks) == 0 {
		return d
	}

	blocks := make(map[int]*IRBlock, len(f.Blocks))
	for _, b := range f.Blocks {
		blocks[b.ID] = b
	}
	entry := f.Blocks[0].ID

	d.rpo = reversePostorder(blocks, entry)
	rpoIndex := make(map[int]int, len(d.rpo))
	for i, id := range d.rpo {
		rpoIndex[id] = i
	}

	// Undefined is -1; entry is its own idom during the fixpoint so intersect
	// terminates, then reset to -1 for callers.
	idom := make(map[int]int, len(d.rpo))
	for _, id := range d.rpo {
		idom[id] = -1
	}
	idom[entry] = entry

	for changed := true; changed; {
		changed = false
		for _, b := range d.rpo {
			if b == entry {
				continue
			}
			newIdom := -1
			for _, p := range blocks[b].Preds {
				if _, ok := rpoIndex[p]; !ok || idom[p] == -1 {
					continue
				}
				if newIdom == -1 {
					newIdom = p
				} else {
					newIdom = intersect(idom, rpoIndex, p, newIdom)
				}
			}
			if newIdom != -1 && idom[b] != newIdom {
				idom[b] = newIdom
				changed = true
			}
		}
	}
	idom[entry] = -1

	for _, id := range d.rpo {
		if dom := idom[id]; dom != -1 {
			d.children[dom] = append(d.children[dom], id)
		}
	}
	d.idom = idom
	return d
}

func intersect(idom, rpoIndex map[int]int, a, b int) int {
	for a != b {
		for rpoIndex[a] > rpoIndex[b] {
			a = idom[a]
		}
		for rpoIndex[b] > rpoIndex[a] {
			b = idom[b]
		}
	}
	return a
}

func reversePostorder(blocks map[int]*IRBlock, entry int) []int {
	visited := make(map[int]bool, len(blocks))
	var post []int
	var dfs func(int)
	dfs = func(id int) {
		visited[id] = true
		if b, ok := blocks[id]; ok {
			for _, s := range b.Succs {
				if _, exists := blocks[s]; exists && !visited[s] {
					dfs(s)
				}
			}
		}
		post = append(post, id)
	}
	dfs(entry)

	for i, j := 0, len(post)-1; i < j; i, j = i+1, j-1 {
		post[i], post[j] = post[j], post[i]
	}
	return post
}

// Idom returns the immediate dominator of a block, or -1 for the entry or an
// unreachable block.
func (d *DomTree) Idom(id int) int {
	if v, ok := d.idom[id]; ok {
		return v
	}
	return -1
}

// Dominates reports whether block a dominates block b.
func (d *DomTree) Dominates(a, b int) bool {
	for x := b; x != -1; x = d.Idom(x) {
		if x == a {
			return true
		}
	}
	return false
}

// Children returns the blocks immediately dominated by id.
func (d *DomTree) Children(id int) []int {
	return d.children[id]
}

// RPO returns block IDs in reverse postorder from the entry.
func (d *DomTree) RPO() []int {
	return d.rpo
}
