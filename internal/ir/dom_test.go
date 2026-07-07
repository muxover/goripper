package ir_test

import (
	"testing"

	"github.com/muxover/goripper/internal/ir"
)

func TestDomTree_Diamond(t *testing.T) {
	// 0 -> {1,2}; 1 -> 3; 2 -> 3
	f := &ir.IRFunc{Blocks: []*ir.IRBlock{
		{ID: 0, Succs: []int{1, 2}},
		{ID: 1, Succs: []int{3}, Preds: []int{0}},
		{ID: 2, Succs: []int{3}, Preds: []int{0}},
		{ID: 3, Preds: []int{1, 2}},
	}}
	d := ir.BuildDomTree(f)

	for id, want := range map[int]int{0: -1, 1: 0, 2: 0, 3: 0} {
		if got := d.Idom(id); got != want {
			t.Errorf("idom(%d) = %d, want %d", id, got, want)
		}
	}
	if !d.Dominates(0, 3) {
		t.Error("0 should dominate 3")
	}
	if d.Dominates(1, 3) {
		t.Error("1 should not dominate the merge block 3")
	}
}

func TestDomTree_Loop(t *testing.T) {
	// 0 -> 1; 1 -> {2,4}; 2 -> 3; 3 -> 1 (back edge); 4 exit
	f := &ir.IRFunc{Blocks: []*ir.IRBlock{
		{ID: 0, Succs: []int{1}},
		{ID: 1, Succs: []int{2, 4}, Preds: []int{0, 3}},
		{ID: 2, Succs: []int{3}, Preds: []int{1}},
		{ID: 3, Succs: []int{1}, Preds: []int{2}},
		{ID: 4, Preds: []int{1}},
	}}
	d := ir.BuildDomTree(f)

	for id, want := range map[int]int{0: -1, 1: 0, 2: 1, 3: 2, 4: 1} {
		if got := d.Idom(id); got != want {
			t.Errorf("idom(%d) = %d, want %d", id, got, want)
		}
	}
	if !d.Dominates(1, 4) {
		t.Error("loop header 1 should dominate exit 4")
	}
	if d.Dominates(2, 4) {
		t.Error("loop body 2 should not dominate exit 4")
	}
}
