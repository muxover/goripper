package assets

import (
	"testing"

	gstrings "github.com/muxover/goripper/internal/strings"
)

func TestDetect_NoEmbedCallers(t *testing.T) {
	strs := []gstrings.ExtractedString{
		{Value: "static/index.html", ReferencedBy: []string{"main.serve"}},
	}
	graph := map[string][]string{
		"main.serve": {"fmt.Println"},
	}
	if got := Detect(strs, graph); len(got) != 0 {
		t.Errorf("expected no assets without embed callers, got %d", len(got))
	}
}

func TestDetect_WithEmbedCallers(t *testing.T) {
	strs := []gstrings.ExtractedString{
		{Value: "static/index.html", ReferencedBy: []string{"main.serve"}},
		{Value: "certs/ca.pem", ReferencedBy: []string{"main.serve"}},
		{Value: "not-a-path", ReferencedBy: []string{"main.serve"}},
	}
	graph := map[string][]string{
		"main.serve": {"embed.FS.Open", "fmt.Println"},
	}
	got := Detect(strs, graph)
	if len(got) != 2 {
		t.Fatalf("expected 2 assets, got %d: %v", len(got), got)
	}
}

func TestLooksLikeEmbedPath(t *testing.T) {
	valid := []string{"static/index.html", "certs/ca.pem", "assets/logo.png"}
	invalid := []string{"/absolute/path.html", "no-extension", "has\\backslash.html", "C:\\win.exe"}

	for _, s := range valid {
		if !looksLikeEmbedPath(s) {
			t.Errorf("expected %q to be a valid embed path", s)
		}
	}
	for _, s := range invalid {
		if looksLikeEmbedPath(s) {
			t.Errorf("expected %q to NOT be a valid embed path", s)
		}
	}
}
