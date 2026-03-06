package obfuscation

import (
	"fmt"
	"strings"

	"github.com/muxover/goripper/internal/functions"
)

// heuristicRule maps a set of call-target prefixes to an advisory label.
type heuristicRule struct {
	label       string
	callTargets []string
	minSize     uint64 // 0 means no size constraint
}

var heuristicRules = []heuristicRule{
	{
		label:       "[suspected:network_connect]",
		callTargets: []string{"net.Dial", "net.(*Dialer)", "syscall.Connect"},
	},
	{
		label:       "[suspected:file_write]",
		callTargets: []string{"os.Create", "os.(*File).Write", "os.WriteFile", "io/ioutil.WriteFile"},
	},
	{
		label:       "[suspected:exec]",
		callTargets: []string{"os/exec.(*Cmd).Run", "os/exec.(*Cmd).Start", "syscall.Exec"},
	},
	{
		label:       "[suspected:encryption]",
		callTargets: []string{"crypto/aes.", "crypto/rc4.", "crypto/des.", "golang.org/x/crypto/"},
	},
	{
		label:       "[suspected:goroutine_spawn]",
		callTargets: []string{"runtime.newproc"},
	},
	{
		label:       "[suspected:http_client]",
		callTargets: []string{"net/http.(*Client).Do", "net/http.Get", "net/http.Post"},
	},
	{
		label:       "[suspected:registry_access]",
		callTargets: []string{"golang.org/x/sys/windows/registry.", "syscall.RegOpenKeyEx"},
	},
}

// Relabel applies advisory heuristic labels to garbled/anonymous functions when
// the obfuscation score exceeds threshold (0.5). Labels are appended to fn.Tags.
// Returns the updated function slice.
func Relabel(funcs []functions.Function, score float64) []functions.Function {
	if score < 0.5 {
		return funcs
	}

	result := make([]functions.Function, len(funcs))
	copy(result, funcs)

	for i, fn := range result {
		if !isGarbledName(fn.Name) {
			continue
		}

		for _, rule := range heuristicRules {
			if rule.minSize > 0 && fn.Size < rule.minSize {
				continue
			}
			if matchesAnyCall(fn.Calls, rule.callTargets) {
				if !hasTag(fn.Tags, rule.label) {
					result[i].Tags = append(result[i].Tags, rule.label)
				}
			}
		}

		// Large function with no recognisable calls.
		if fn.Size > 4096 && len(fn.Calls) == 0 {
			label := "[suspected:large_unknown]"
			if !hasTag(fn.Tags, label) {
				result[i].Tags = append(result[i].Tags, label)
			}
		}
	}

	return result
}

// TagDecryptorStubs marks stub functions and their callers in the function list.
func TagDecryptorStubs(funcs []functions.Function, stubs []StubMatch, xorKeys map[string]byte) []functions.Function {
	if len(stubs) == 0 {
		return funcs
	}

	stubNames := make(map[string]StubMatch, len(stubs))
	for _, s := range stubs {
		stubNames[s.FuncName] = s
	}

	result := make([]functions.Function, len(funcs))
	copy(result, funcs)

	for i, fn := range result {
		if stub, ok := stubNames[fn.Name]; ok {
			label := fmt.Sprintf("[STRING_DECRYPTOR_STUB callers=%d]", stub.CallerCount)
			if key, hasKey := xorKeys[fn.Name]; hasKey {
				label = fmt.Sprintf("[STRING_DECRYPTOR_STUB callers=%d xor=0x%02x]", stub.CallerCount, key)
			}
			if !hasTag(fn.Tags, "[STRING_DECRYPTOR_STUB") {
				result[i].Tags = append(result[i].Tags, label)
			}
		}
	}
	return result
}

// isGarbledName returns true when the function name looks like a garble-generated
// identifier: short, no dot separator (no package path), and high character entropy.
func isGarbledName(name string) bool {
	if name == "" {
		return false
	}
	// Garbled names have no '.' (no package.FuncName pattern) or only a hash-like
	// segment after the last dot.
	parts := strings.Split(name, ".")
	last := parts[len(parts)-1]
	if len(last) < 4 || len(last) > 24 {
		return false
	}
	// Garble identifiers have: high entropy AND embedded digits.
	// Real camelCase Go names (handleRequest) have high entropy but no digits.
	// Require both signals to reduce false positives.
	if !containsDigit(last) {
		return false
	}
	// Normal Go identifiers score ~2.0–3.0 bits/char; garble base-62 ~3.1+.
	return shannonEntropy(last) > 3.1
}

func matchesAnyCall(calls []string, targets []string) bool {
	for _, call := range calls {
		for _, target := range targets {
			if strings.HasPrefix(call, target) || call == target {
				return true
			}
		}
	}
	return false
}

func hasTag(tags []string, label string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, label) {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}
