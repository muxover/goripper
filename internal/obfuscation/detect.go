package obfuscation

import (
	"fmt"
	"math"
	"strings"

	"github.com/muxover/goripper/internal/callgraph"
	"github.com/muxover/goripper/internal/functions"
	gstrings "github.com/muxover/goripper/internal/strings"
)

var knownPkgPrefixes = []string{
	"main.", "runtime.", "runtime/", "internal/", "reflect.",
	"sync.", "fmt.", "os.", "net.", "crypto/", "encoding/",
	"io.", "strings.", "bytes.", "errors.", "log.", "time.",
	"context.", "path/", "sort.", "strconv.", "unicode/",
}

func Detect(
	funcs []functions.Function,
	strs []gstrings.ExtractedString,
	hasBuildInfo bool,
) Result {
	if len(funcs) == 0 {
		return Result{Score: 0, Level: "none"}
	}

	var score float64
	var indicators []string

	// non-obfuscated Go averages 3.2–4.0 bits/char; garble names average 4.8+
	entAvg := avgNameEntropy(funcs)
	if entAvg >= 4.8 {
		weight := math.Min((entAvg-4.8)/0.8, 1.0) * 0.35
		score += weight
		indicators = append(indicators, fmt.Sprintf("high name entropy (%.2f bits/char)", entAvg))
	}

	recognised := 0
	for _, fn := range funcs {
		if hasKnownPrefix(fn.Name) {
			recognised++
		}
	}
	recognisedRatio := float64(recognised) / float64(len(funcs))
	if recognisedRatio < 0.10 {
		weight := (0.10 - recognisedRatio) / 0.10 * 0.30
		score += weight
		indicators = append(indicators, fmt.Sprintf("low known-prefix ratio (%.0f%%)", recognisedRatio*100))
	}

	// normal Go has ~0.3–1.5 strings/func; garbled binaries are near-zero
	density := float64(len(strs)) / float64(len(funcs))
	if density < 0.05 {
		weight := (0.05 - density) / 0.05 * 0.20
		score += weight
		indicators = append(indicators, fmt.Sprintf("very low string density (%.3f strings/func)", density))
	}

	if !hasBuildInfo {
		score += 0.15
		indicators = append(indicators, "no build info (stripped or garbled)")
	}

	if score > 1.0 {
		score = 1.0
	}

	return Result{
		Score:      score,
		Level:      scoreLevel(score),
		Indicators: indicators,
	}
}

func FindDecryptorStubs(funcs []functions.Function, graph *callgraph.CallGraph) []StubMatch {
	if graph == nil {
		return nil
	}

	callerCount := make(map[string]int, len(funcs))
	for _, fn := range funcs {
		if len(fn.CalledBy) > 0 {
			callerCount[fn.Name] = len(fn.CalledBy)
		}
	}

	var stubs []StubMatch
	for _, fn := range funcs {
		// Only user-defined functions can be garble decryptor stubs; runtime and
		// stdlib functions are inherently high-fan-in and must never be flagged.
		if fn.PackageKind != functions.PackageUser {
			continue
		}
		count := callerCount[fn.Name]
		if count < 50 {
			continue
		}
		if fn.Size > 100 || fn.Size == 0 {
			continue
		}
		stubs = append(stubs, StubMatch{
			FuncName:    fn.Name,
			FuncAddr:    fn.Addr,
			CallerCount: count,
		})
	}
	return stubs
}

func TryDecodeXOR(fn functions.Function, textData []byte, textVA uint64) (byte, bool) {
	if fn.Addr < textVA || fn.Size == 0 || fn.Size > 100 {
		return 0, false
	}
	start := fn.Addr - textVA
	end := start + fn.Size
	if end > uint64(len(textData)) {
		return 0, false
	}
	body := textData[start:end]

	for i := 0; i+1 < len(body); i++ {
		b := body[i]
		switch b {
		case 0x34:
			if key := body[i+1]; key != 0 {
				return key, true
			}
		case 0x80, 0x83:
			if i+2 < len(body) && (body[i+1]>>3)&0x7 == 6 {
				if key := body[i+2]; key != 0 {
					return key, true
				}
			}
		}
	}
	return 0, false
}

func avgNameEntropy(funcs []functions.Function) float64 {
	total := 0.0
	count := 0
	for _, fn := range funcs {
		name := fn.Name
		if name == "" || len(name) < 4 {
			continue
		}
		if strings.HasPrefix(name, "runtime.") || strings.HasPrefix(name, "internal/") {
			continue
		}
		total += shannonEntropy(name)
		count++
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

func hasKnownPrefix(name string) bool {
	for _, prefix := range knownPkgPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func scoreLevel(score float64) string {
	switch {
	case score < 0.15:
		return "none"
	case score < 0.35:
		return "low"
	case score < 0.60:
		return "medium"
	default:
		return "high"
	}
}
