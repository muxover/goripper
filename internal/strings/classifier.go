package strings

import (
	"regexp"
	gostrings "strings"
)

var (
	reURLScheme = regexp.MustCompile(`https?://`)

	reURL = regexp.MustCompile(
		`(?i)^[a-z][a-z0-9+\-.]*://[^\s]{3,}$`,
	)
	reIP = regexp.MustCompile(
		`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$`,
	)
	reUnixPath = regexp.MustCompile(
		`^(/[a-zA-Z0-9._\-]+){2,}/?$`,
	)
	reWinPath = regexp.MustCompile(
		`(?i)^[A-Za-z]:\\[^\x00-\x1f]+$`,
	)
	reSecret = regexp.MustCompile(
		`(?i)(password|passwd|secret|token|api[_-]?key|auth[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)`,
	)
	// Partial URL patterns for strings that look like endpoints but without scheme
	reEndpoint = regexp.MustCompile(
		`(?i)^/[a-zA-Z0-9/_\-]{3,}(\?[^\s]*)?$`,
	)
	// Go module/import paths: e.g. golang.org/x/crypto, github.com/user/repo
	rePkgPath = regexp.MustCompile(
		`^[a-z0-9]([a-z0-9\-]*\.)+[a-z]{2,}/[a-zA-Z0-9/_.\-]+$`,
	)
)

// Classify assigns a StringType to each extracted string based on content patterns.
func Classify(strs []ExtractedString) []ExtractedString {
	result := make([]ExtractedString, len(strs))
	for i, s := range strs {
		s.Type = classifyOne(s.Value)
		result[i] = s
	}
	return result
}

func classifyOne(v string) StringType {
	trimmed := gostrings.TrimSpace(v)
	if trimmed == "" {
		return StringTypePlain
	}

	if reURL.MatchString(trimmed) {
		return StringTypeURL
	}

	if reIP.MatchString(trimmed) {
		return StringTypeIP
	}

	if reSecret.MatchString(trimmed) {
		return StringTypeSecret
	}

	if reUnixPath.MatchString(trimmed) || reWinPath.MatchString(trimmed) {
		return StringTypePath
	}

	// API endpoint-like paths
	if reEndpoint.MatchString(trimmed) {
		return StringTypePath
	}

	if rePkgPath.MatchString(trimmed) {
		return StringTypePkgPath
	}

	return StringTypePlain
}

// SplitConcatenatedURLs breaks apart any URL-typed string that contains multiple
// embedded URL starts (e.g. "https://a.com/...https://b.com/..."). This handles the
// CMOVNE compiler pattern where adjacent .rodata strings have no separator and our
// length inference falls back to a 512-byte printable run.
//
// Only strings that start with "https?://" and contain at least one additional
// "https?://" are split. Non-URL strings and strings with a single URL are returned
// unchanged. The original blob is replaced by its individual components.
func SplitConcatenatedURLs(strs []ExtractedString) []ExtractedString {
	seen := make(map[string]bool, len(strs))
	for _, s := range strs {
		seen[s.Value] = true
	}

	result := make([]ExtractedString, 0, len(strs))
	for _, s := range strs {
		if s.Type != StringTypeURL {
			result = append(result, s)
			continue
		}
		locs := reURLScheme.FindAllStringIndex(s.Value, -1)
		// Only split if the string itself starts with a URL scheme and has more than one.
		if len(locs) <= 1 || locs[0][0] != 0 {
			result = append(result, s)
			continue
		}
		for i, loc := range locs {
			end := len(s.Value)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			part := s.Value[loc[0]:end]
			if len(part) < minStringLen {
				continue
			}
			if seen[part] {
				continue
			}
			seen[part] = true
			result = append(result, ExtractedString{
				Value:        part,
				Type:         StringTypeURL,
				Offset:       s.Offset + uint64(loc[0]),
				ReferencedBy: s.ReferencedBy,
			})
		}
	}
	return result
}
