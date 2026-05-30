package trace

import (
	"sort"

	"github.com/muxover/goripper/internal/output"
)

// Functions that were never called get CallCount == 0, which is deliberately
// useful: code that exists but never executed is often the most interesting.
func Merge(result *output.AnalysisResult, events []Event) {
	callCounts := make(map[string]int, len(result.Functions))
	totalTime := make(map[string]int64, len(result.Functions))

	callTs := make(map[string]int64)

	netSet := make(map[string]bool)
	fileSet := make(map[string]bool)
	syscallSet := make(map[string]bool)

	for _, ev := range events {
		switch ev.Type {
		case EventCall:
			if ev.Func != "" {
				callCounts[ev.Func]++
				callTs[ev.Func] = ev.TsNs
			}
		case EventReturn:
			if ev.Func != "" && ev.DurationNs > 0 {
				totalTime[ev.Func] += ev.DurationNs
			} else if ev.Func != "" {
				if start, ok := callTs[ev.Func]; ok && ev.TsNs > start {
					totalTime[ev.Func] += ev.TsNs - start
				}
			}
		case EventNet:
			if ev.NetAddr != "" {
				netSet[ev.NetAddr] = true
			}
		case EventFile:
			if ev.Path != "" {
				fileSet[ev.Path] = true
			}
		case EventSyscall:
			if ev.Name != "" {
				syscallSet[ev.Name] = true
			}
		}
	}

	// Determine hot threshold: top 10% by call count.
	counts := make([]int, 0, len(callCounts))
	for _, c := range callCounts {
		counts = append(counts, c)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(counts)))
	hotThreshold := 1
	if len(counts) > 0 {
		topN := len(counts) / 10
		if topN == 0 {
			topN = 1
		}
		hotThreshold = counts[topN-1]
	}

	for i, fn := range result.Functions {
		c := callCounts[fn.Name]
		result.Functions[i].CallCount = c
		result.Functions[i].TotalTimeNs = totalTime[fn.Name]
		if c > 0 && c >= hotThreshold {
			result.Functions[i].IsHot = true
		}
	}

	result.ObservedNetworkAddrs = sortedKeys(netSet)
	result.ObservedFilePaths = sortedKeys(fileSet)
	result.ObservedSyscalls = sortedKeys(syscallSet)
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
