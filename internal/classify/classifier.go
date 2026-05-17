package classify

import "strings"

type Class string

const (
	ClassRAT         Class = "RAT"
	ClassDownloader  Class = "DOWNLOADER"
	ClassRansomware  Class = "RANSOMWARE"
	ClassC2Agent     Class = "C2_AGENT"
	ClassKeylogger   Class = "KEYLOGGER"
	ClassCryptominer Class = "CRYPTOMINER"
	ClassTool        Class = "TOOL"
	ClassUnknown     Class = "UNKNOWN"
)

type Result struct {
	Class      Class
	Confidence string // "high" | "medium" | "low"
	Indicators []string
}

type Input struct {
	BehaviorTags   []string // union of all behavior tags across all functions
	StringValues   []string // all extracted string values
	URLCount       int
	HasConcurrency bool
	HasCrypto      bool
	HasNetwork     bool
	HasFileWrite   bool
	HasFileRead    bool
	HasExecution   bool
	HasRegistry    bool
	HasDNS         bool
	HasHTTP        bool
	HasMemory      bool
	ObfScore       float64
}

// Classify applies rule-based threat classification with no external dependencies.
func Classify(in Input) Result {
	tagSet := make(map[string]bool, len(in.BehaviorTags))
	for _, t := range in.BehaviorTags {
		tagSet[t] = true
	}

	var indicators []string
	addIf := func(cond bool, label string) {
		if cond {
			indicators = append(indicators, label)
		}
	}

	addIf(tagSet["NETWORK"], "NETWORK")
	addIf(tagSet["CRYPTO"], "CRYPTO")
	addIf(tagSet["FILE_WRITE"], "FILE_WRITE")
	addIf(tagSet["FILE_READ"], "FILE_READ")
	addIf(tagSet["EXECUTION"], "EXECUTION")
	addIf(tagSet["REGISTRY"], "REGISTRY")
	addIf(tagSet["DNS"], "DNS")
	addIf(tagSet["HTTP"], "HTTP")
	addIf(tagSet["MEMORY"], "MEMORY")
	addIf(in.HasConcurrency, "CONCURRENCY")
	if in.URLCount > 0 {
		indicators = append(indicators, "url_count="+itoa(in.URLCount))
	}

	hasMiningURL := containsAny(in.StringValues, []string{
		"pool.minergate.com", "stratum+tcp", "xmrpool", "moneroocean", "hashvault",
	})

	hasKeylogPat := containsAny(in.StringValues, []string{
		"keylog", "keystroke", "GetAsyncKeyState", "SetWindowsHookEx",
	})

	hasFileEnum := containsAny(in.StringValues, []string{
		".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".png",
		"filepath.Walk", "os.ReadDir",
	})

	switch {
	case tagSet["NETWORK"] && tagSet["EXECUTION"] && (tagSet["FILE_READ"] || tagSet["FILE_WRITE"]) && in.HasConcurrency:
		return Result{ClassRAT, confidence(3, len(indicators)), indicators}

	case tagSet["NETWORK"] && tagSet["FILE_WRITE"] && in.URLCount >= 1 && !tagSet["EXECUTION"]:
		return Result{ClassDownloader, confidence(2, len(indicators)), indicators}

	case tagSet["CRYPTO"] && tagSet["FILE_WRITE"] && hasFileEnum:
		return Result{ClassRansomware, confidence(3, len(indicators)), indicators}

	case tagSet["NETWORK"] && tagSet["DNS"] && tagSet["CRYPTO"] && in.HasConcurrency:
		return Result{ClassC2Agent, confidence(2, len(indicators)), indicators}

	case tagSet["FILE_WRITE"] && hasKeylogPat:
		return Result{ClassKeylogger, confidence(2, len(indicators)), indicators}

	case tagSet["NETWORK"] && hasMiningURL:
		return Result{ClassCryptominer, confidence(2, len(indicators)), indicators}

	case !tagSet["NETWORK"] && !tagSet["EXECUTION"] && !tagSet["MEMORY"]:
		return Result{ClassTool, "low", indicators}

	default:
		return Result{ClassUnknown, "low", indicators}
	}
}

func containsAny(strs []string, patterns []string) bool {
	for _, s := range strs {
		sl := strings.ToLower(s)
		for _, p := range patterns {
			if strings.Contains(sl, strings.ToLower(p)) {
				return true
			}
		}
	}
	return false
}

func confidence(matchedSignals, indicatorCount int) string {
	switch {
	case matchedSignals >= 3 || indicatorCount >= 5:
		return "high"
	case matchedSignals >= 2 || indicatorCount >= 3:
		return "medium"
	default:
		return "low"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
