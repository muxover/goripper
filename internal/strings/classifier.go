package strings

import (
	"regexp"
	gostrings "strings"
)

var (
	reURL = regexp.MustCompile(
		`(?i)^(https?|ftp|ws|wss)://[^\s]{3,}$`,
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

	if reURL.MatchString(trimmed) || gostrings.Contains(trimmed, "://") {
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
