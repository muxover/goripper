package similarity

import (
	"sort"

	"github.com/muxover/goripper/internal/output"
)

type CompareResult struct {
	BinaryA         string   `json:"binary_a"`
	BinaryB         string   `json:"binary_b"`
	SharedFunctions int      `json:"shared_functions"`
	SharedPackages  []string `json:"shared_packages"`
	UniqueToA       int      `json:"unique_to_a"`
	UniqueToB       int      `json:"unique_to_b"`
	SimilarityScore float64  `json:"similarity_score"`
}

// SimilarityScore = shared / max(totalA, totalB); score > 0.7 suggests shared codebase.
func Compare(a, b *output.AnalysisResult) CompareResult {
	aMap := buildHashMap(a.Functions)
	bMap := buildHashMap(b.Functions)

	shared := 0
	pkgSet := make(map[string]bool)
	for hash, fn := range aMap {
		if _, ok := bMap[hash]; ok {
			shared++
			pkgSet[fn.Package] = true
		}
	}

	totalA, totalB := len(aMap), len(bMap)
	maxTotal := totalA
	if totalB > maxTotal {
		maxTotal = totalB
	}
	score := 0.0
	if maxTotal > 0 {
		score = float64(shared) / float64(maxTotal)
	}

	pkgs := make([]string, 0, len(pkgSet))
	for p := range pkgSet {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)

	return CompareResult{
		BinaryA:         a.BinaryInfo.Path,
		BinaryB:         b.BinaryInfo.Path,
		SharedFunctions: shared,
		SharedPackages:  pkgs,
		UniqueToA:       totalA - shared,
		UniqueToB:       totalB - shared,
		SimilarityScore: score,
	}
}

func buildHashMap(funcs []output.FunctionOutput) map[string]output.FunctionOutput {
	m := make(map[string]output.FunctionOutput, len(funcs))
	for _, f := range funcs {
		if f.SimilarityHash != "" {
			m[f.SimilarityHash] = f
		}
	}
	return m
}
