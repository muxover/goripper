package diff

import (
	"sort"

	"github.com/muxover/goripper/internal/output"
)

// FunctionDiff describes a function whose size changed between two binaries.
type FunctionDiff struct {
	Name       string `json:"name"`
	SizeBefore uint64 `json:"size_before"`
	SizeAfter  uint64 `json:"size_after"`
}

type Result struct {
	Added        []output.FunctionOutput `json:"added"`
	Removed      []output.FunctionOutput `json:"removed"`
	Modified     []FunctionDiff          `json:"modified"`
	NewStrings   []output.StringOutput   `json:"new_strings"`
	NewBehaviors []string                `json:"new_behaviors"`
}

// a is the baseline (binary1), b is the candidate (binary2).
func Compare(a, b *output.AnalysisResult) *Result {
	aFuncs := make(map[string]output.FunctionOutput, len(a.Functions))
	for _, f := range a.Functions {
		aFuncs[f.Name] = f
	}
	bFuncs := make(map[string]output.FunctionOutput, len(b.Functions))
	for _, f := range b.Functions {
		bFuncs[f.Name] = f
	}

	var added, removed []output.FunctionOutput
	var modified []FunctionDiff

	for name, bf := range bFuncs {
		if af, ok := aFuncs[name]; !ok {
			added = append(added, bf)
		} else if af.Size != bf.Size {
			modified = append(modified, FunctionDiff{
				Name:       name,
				SizeBefore: af.Size,
				SizeAfter:  bf.Size,
			})
		}
	}
	for name, af := range aFuncs {
		if _, ok := bFuncs[name]; !ok {
			removed = append(removed, af)
		}
	}

	// Strings: values present in b but not a.
	aStrings := make(map[string]bool, len(a.Strings))
	for _, s := range a.Strings {
		aStrings[s.Value] = true
	}
	var newStrings []output.StringOutput
	for _, s := range b.Strings {
		if !aStrings[s.Value] {
			newStrings = append(newStrings, s)
		}
	}

	// Behavior tags: tags present in b functions but not in any a function.
	aTags := make(map[string]bool)
	for _, f := range a.Functions {
		for _, tag := range f.Tags {
			aTags[tag] = true
		}
	}
	bTags := make(map[string]bool)
	for _, f := range b.Functions {
		for _, tag := range f.Tags {
			bTags[tag] = true
		}
	}
	var newBehaviors []string
	for tag := range bTags {
		if !aTags[tag] {
			newBehaviors = append(newBehaviors, tag)
		}
	}

	// Sort all slices for deterministic output.
	sort.Slice(added, func(i, j int) bool { return added[i].Name < added[j].Name })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Name < removed[j].Name })
	sort.Slice(modified, func(i, j int) bool { return modified[i].Name < modified[j].Name })
	sort.Strings(newBehaviors)

	return &Result{
		Added:        added,
		Removed:      removed,
		Modified:     modified,
		NewStrings:   newStrings,
		NewBehaviors: newBehaviors,
	}
}
