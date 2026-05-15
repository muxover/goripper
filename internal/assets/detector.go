package assets

import (
	"path/filepath"
	"strings"

	gstrings "github.com/muxover/goripper/internal/strings"
)

type EmbeddedAsset struct {
	Path     string `json:"path"`
	SizeHint int    `json:"size_hint"`
}

func Detect(strs []gstrings.ExtractedString, callGraph map[string][]string) []EmbeddedAsset {
	embedUsers := findEmbedUsers(callGraph)
	if len(embedUsers) == 0 {
		return nil
	}

	var assets []EmbeddedAsset
	seen := make(map[string]bool)
	for _, s := range strs {
		if seen[s.Value] || !looksLikeEmbedPath(s.Value) {
			continue
		}
		for _, fn := range s.ReferencedBy {
			if embedUsers[fn] {
				seen[s.Value] = true
				assets = append(assets, EmbeddedAsset{Path: s.Value})
				break
			}
		}
	}
	return assets
}

func findEmbedUsers(callGraph map[string][]string) map[string]bool {
	users := make(map[string]bool)
	for caller, callees := range callGraph {
		for _, callee := range callees {
			if strings.HasPrefix(callee, "embed.") || strings.HasPrefix(callee, "io/fs.") {
				users[caller] = true
				break
			}
		}
	}
	return users
}

func looksLikeEmbedPath(s string) bool {
	if len(s) < 4 || len(s) > 256 {
		return false
	}
	// embed paths are always forward-slash, never absolute, no shell-special chars
	if strings.ContainsAny(s, "\\:*?\"<>|\x00") {
		return false
	}
	if s[0] == '/' {
		return false
	}
	return filepath.Ext(s) != ""
}
