package cluster

import (
	"sort"

	"github.com/muxover/goripper/internal/output"
	"github.com/muxover/goripper/internal/similarity"
)

type Group struct {
	Members        []string `json:"members"`
	Similarity     float64  `json:"similarity"`
	SharedPackages []string `json:"shared_packages"`
}

// Pairs with score >= threshold are merged into the same cluster (single-linkage).
func Cluster(results []*output.AnalysisResult, threshold float64) []Group {
	n := len(results)
	if n == 0 {
		return nil
	}

	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(x, y int) { parent[find(x)] = find(y) }

	type pair struct {
		i, j  int
		score float64
	}
	var pairs []pair
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			cr := similarity.Compare(results[i], results[j])
			if cr.SimilarityScore >= threshold {
				pairs = append(pairs, pair{i, j, cr.SimilarityScore})
			}
		}
	}
	sort.Slice(pairs, func(a, b int) bool { return pairs[a].score > pairs[b].score })
	for _, p := range pairs {
		union(p.i, p.j)
	}

	groupMap := make(map[int][]int)
	for i := range results {
		root := find(i)
		groupMap[root] = append(groupMap[root], i)
	}

	var groups []Group
	for _, members := range groupMap {
		if len(members) < 2 {
			continue
		}
		minSim := 1.0
		pkgSet := make(map[string]bool)
		for mi := 0; mi < len(members); mi++ {
			for mj := mi + 1; mj < len(members); mj++ {
				cr := similarity.Compare(results[members[mi]], results[members[mj]])
				if cr.SimilarityScore < minSim {
					minSim = cr.SimilarityScore
				}
				for _, p := range cr.SharedPackages {
					pkgSet[p] = true
				}
			}
		}
		paths := make([]string, len(members))
		for i, m := range members {
			paths[i] = results[m].BinaryInfo.Path
		}
		sort.Strings(paths)
		pkgs := make([]string, 0, len(pkgSet))
		for p := range pkgSet {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		groups = append(groups, Group{
			Members:        paths,
			Similarity:     minSim,
			SharedPackages: pkgs,
		})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Similarity > groups[j].Similarity })
	return groups
}
