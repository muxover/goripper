package cluster

import (
	"testing"

	"github.com/muxover/goripper/internal/output"
)

func makeResult(path string, hashes []string) *output.AnalysisResult {
	funcs := make([]output.FunctionOutput, len(hashes))
	for i, h := range hashes {
		funcs[i] = output.FunctionOutput{
			Name:           "fn",
			SimilarityHash: h,
			Package:        "main",
		}
	}
	return &output.AnalysisResult{
		BinaryInfo: output.BinaryInfo{Path: path},
		Functions:  funcs,
	}
}

func TestCluster_Empty(t *testing.T) {
	groups := Cluster(nil, 0.6)
	if len(groups) != 0 {
		t.Fatalf("expected no groups for empty input, got %d", len(groups))
	}
}

func TestCluster_IdenticalBinaries(t *testing.T) {
	hashes := []string{
		"aabbccdd00000001",
		"aabbccdd00000002",
		"aabbccdd00000003",
	}
	a := makeResult("/bin/a", hashes)
	b := makeResult("/bin/b", hashes)

	groups := Cluster([]*output.AnalysisResult{a, b}, 0.6)
	if len(groups) != 1 {
		t.Fatalf("expected 1 cluster for identical binaries, got %d", len(groups))
	}
	if len(groups[0].Members) != 2 {
		t.Fatalf("expected 2 members in cluster, got %d", len(groups[0].Members))
	}
	if groups[0].Similarity < 0.6 {
		t.Fatalf("expected similarity >= 0.6, got %f", groups[0].Similarity)
	}
}

func TestCluster_UnrelatedBinaries(t *testing.T) {
	a := makeResult("/bin/a", []string{"aaaa000000000001", "aaaa000000000002"})
	b := makeResult("/bin/b", []string{"bbbb000000000001", "bbbb000000000002"})

	groups := Cluster([]*output.AnalysisResult{a, b}, 0.6)
	if len(groups) != 0 {
		t.Fatalf("expected no clusters for unrelated binaries, got %d", len(groups))
	}
}

func TestCluster_ThreeWithTwoSimilar(t *testing.T) {
	shared := []string{"shared000000001", "shared000000002", "shared000000003"}
	a := makeResult("/bin/a", shared)
	b := makeResult("/bin/b", shared)
	c := makeResult("/bin/c", []string{"unique000000001", "unique000000002"})

	groups := Cluster([]*output.AnalysisResult{a, b, c}, 0.6)
	if len(groups) != 1 {
		t.Fatalf("expected 1 cluster (a and b), got %d", len(groups))
	}
	if len(groups[0].Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(groups[0].Members))
	}
}
