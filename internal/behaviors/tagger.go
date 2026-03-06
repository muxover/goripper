package behaviors

import (
	"strings"

	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/functions"
	gstrings "github.com/muxover/goripper/internal/strings"
)

// Tag annotates each function with behavior tags based on call edges and string references.
func Tag(
	funcs []functions.Function,
	graph *callgraph.CallGraph,
	strs []gstrings.ExtractedString,
) []functions.Function {
	// Build func name -> string values map for quick lookup
	funcStrings := buildFuncStringMap(funcs, strs)

	result := make([]functions.Function, len(funcs))
	for i, fn := range funcs {
		callees := graph.Calls[fn.Name]
		strVals := funcStrings[fn.Name]
		tags := applyRules(callees, strVals)
		fn.Tags = tags
		result[i] = fn
	}

	return result
}

func applyRules(callees []string, strVals []string) []string {
	tagSet := make(map[BehaviorTag]bool)

	for _, rule := range tagRules {
		// Check call targets
		for _, callee := range callees {
			for _, target := range rule.CallTargets {
				if strings.HasPrefix(callee, target) || callee == target {
					tagSet[rule.Tag] = true
					goto nextRule
				}
			}
		}

		// Check string patterns
		if rule.StringPat != nil {
			for _, s := range strVals {
				if rule.StringPat.MatchString(s) {
					tagSet[rule.Tag] = true
					goto nextRule
				}
			}
		}

	nextRule:
	}

	// HTTP implies NETWORK
	if tagSet[TagHTTP] {
		tagSet[TagNetwork] = true
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, string(tag))
	}
	return tags
}

// buildFuncStringMap builds a map from function name to the string values it references.
func buildFuncStringMap(funcs []functions.Function, strs []gstrings.ExtractedString) map[string][]string {
	result := make(map[string][]string)

	for _, s := range strs {
		for _, fn := range s.ReferencedBy {
			result[fn] = appendUniq(result[fn], s.Value)
		}
	}

	// Also include strings already attached to functions (from other analysis stages)
	for _, fn := range funcs {
		for _, s := range fn.Strings {
			result[fn.Name] = appendUniq(result[fn.Name], s)
		}
	}

	return result
}

func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
