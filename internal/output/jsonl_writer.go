package output

import (
	"encoding/json"
	"io"
	"sort"
)

// Each line is a self-contained JSON object with a "type" discriminator.
// Emission order: binary_info → functions → strings → behaviors → summary (always last).
func WriteJSONL(w io.Writer, result *AnalysisResult) error {
	enc := json.NewEncoder(w)

	// 1. binary_info
	if err := enc.Encode(map[string]any{
		"type":              "binary_info",
		"path":              result.BinaryInfo.Path,
		"format":            result.BinaryInfo.Format,
		"arch":              result.BinaryInfo.Arch,
		"go_version":        result.BinaryInfo.GoVersion,
		"size_bytes":        result.BinaryInfo.SizeBytes,
		"obfuscation_score": result.BinaryInfo.ObfuscationScore,
		"obfuscation_level": result.BinaryInfo.ObfuscationLevel,
	}); err != nil {
		return err
	}

	// 2. functions
	for _, f := range result.Functions {
		if err := enc.Encode(map[string]any{
			"type":         "function",
			"name":         f.Name,
			"addr":         f.Addr,
			"package":      f.Package,
			"package_kind": f.PackageKind,
			"size":         f.Size,
			"is_runtime":   f.IsRuntime,
			"tags":         f.Tags,
		}); err != nil {
			return err
		}
	}

	// 3. strings
	for _, s := range result.Strings {
		if err := enc.Encode(map[string]any{
			"type":        "string",
			"value":       s.Value,
			"string_type": s.Type,
		}); err != nil {
			return err
		}
	}

	// 4. behaviors — unique tags with up to 10 evidence function names
	tagEvidence := make(map[string][]string)
	for _, f := range result.Functions {
		for _, tag := range f.Tags {
			tagEvidence[tag] = append(tagEvidence[tag], f.Name)
		}
	}
	tags := make([]string, 0, len(tagEvidence))
	for tag := range tagEvidence {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		evidence := tagEvidence[tag]
		if len(evidence) > 10 {
			evidence = evidence[:10]
		}
		if err := enc.Encode(map[string]any{
			"type":     "behavior",
			"tag":      tag,
			"evidence": evidence,
		}); err != nil {
			return err
		}
	}

	// 5. summary — always last
	return enc.Encode(map[string]any{
		"type":              "summary",
		"total_functions":   result.Summary.TotalFunctions,
		"user_functions":    result.Summary.UserFunctions,
		"stdlib_functions":  result.Summary.StdlibFunctions,
		"runtime_functions": result.Summary.RuntimeFunctions,
		"total_strings":     result.Summary.TotalStrings,
		"url_strings":       result.Summary.URLStrings,
		"ip_strings":        result.Summary.IPStrings,
		"path_strings":      result.Summary.PathStrings,
		"secret_strings":    result.Summary.SecretStrings,
	})
}
