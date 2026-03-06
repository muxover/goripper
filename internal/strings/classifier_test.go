package strings_test

import (
	"testing"

	gstrings "github.com/muxover/goripper/internal/strings"
)

func classifyOne(t *testing.T, value string) gstrings.StringType {
	t.Helper()
	strs := gstrings.Classify([]gstrings.ExtractedString{{Value: value}})
	if len(strs) == 0 {
		t.Fatalf("Classify returned empty slice for %q", value)
	}
	return strs[0].Type
}

func TestClassify_URL(t *testing.T) {
	cases := []string{
		"https://example.com/api",
		"http://go.dev/issue/1",
		"ftp://files.example.com/path",
		"https://discord.com/api/webhooks/123/token",
		"ws://websocket.example.com/path",
		"mongodb://user:pass@host/db",
	}
	for _, c := range cases {
		got := classifyOne(t, c)
		if got != gstrings.StringTypeURL {
			t.Errorf("Classify(%q) = %q, want %q", c, got, gstrings.StringTypeURL)
		}
	}
}

// Strings that merely contain "://" somewhere in the middle must NOT be classified
// as URL — they are error messages or format strings that happen to embed a URL.
func TestClassify_EmbeddedURLNotClassifiedAsURL(t *testing.T) {
	cases := []string{
		"crypto/rsa: key too small (see https://go.dev/issue/1)",
		"invalid padding bits in BIT STRINGcrypto/rsa: public modulus is even",
		`{"embeds":[{"description":"**[@%s](https://instagram.com/%s)**"}]}`,
		"see https://example.com for details",
	}
	for _, c := range cases {
		got := classifyOne(t, c)
		if got == gstrings.StringTypeURL {
			t.Errorf("Classify(%q) = URL, want non-URL (contains embedded URL but does not start with scheme)", c)
		}
	}
}

func TestClassify_IP(t *testing.T) {
	cases := []string{
		"192.168.1.1",
		"10.0.0.1",
		"255.255.255.255",
	}
	for _, c := range cases {
		got := classifyOne(t, c)
		if got != gstrings.StringTypeIP {
			t.Errorf("Classify(%q) = %q, want %q", c, got, gstrings.StringTypeIP)
		}
	}
}

func TestClassify_Path(t *testing.T) {
	cases := []string{
		"/usr/local/bin/go",
		"/var/log/syslog",
	}
	for _, c := range cases {
		got := classifyOne(t, c)
		if got != gstrings.StringTypePath {
			t.Errorf("Classify(%q) = %q, want %q", c, got, gstrings.StringTypePath)
		}
	}
}

func TestClassify_Secret(t *testing.T) {
	cases := []string{
		"SECRET_KEY",
		"api_key=abc123",
		"password123",
		"auth_token",
	}
	for _, c := range cases {
		got := classifyOne(t, c)
		if got != gstrings.StringTypeSecret {
			t.Errorf("Classify(%q) = %q, want %q", c, got, gstrings.StringTypeSecret)
		}
	}
}

func TestClassify_PkgPath(t *testing.T) {
	cases := []string{
		"golang.org/x/crypto",
		"github.com/user/repo",
		"github.com/spf13/cobra",
	}
	for _, c := range cases {
		got := classifyOne(t, c)
		if got != gstrings.StringTypePkgPath {
			t.Errorf("Classify(%q) = %q, want %q", c, got, gstrings.StringTypePkgPath)
		}
	}
}

func TestClassify_Plain(t *testing.T) {
	cases := []string{
		"hello world",
		"ordinary text here",
		"just a string",
	}
	for _, c := range cases {
		got := classifyOne(t, c)
		if got != gstrings.StringTypePlain {
			t.Errorf("Classify(%q) = %q, want %q", c, got, gstrings.StringTypePlain)
		}
	}
}

func TestClassify_BatchPreservesOrder(t *testing.T) {
	input := []gstrings.ExtractedString{
		{Value: "hello world"},
		{Value: "https://example.com"},
		{Value: "192.168.1.1"},
	}
	out := gstrings.Classify(input)
	if len(out) != len(input) {
		t.Fatalf("expected %d results, got %d", len(input), len(out))
	}
	if out[0].Type != gstrings.StringTypePlain {
		t.Errorf("out[0].Type = %q, want plain", out[0].Type)
	}
	if out[1].Type != gstrings.StringTypeURL {
		t.Errorf("out[1].Type = %q, want url", out[1].Type)
	}
	if out[2].Type != gstrings.StringTypeIP {
		t.Errorf("out[2].Type = %q, want ip", out[2].Type)
	}
}

func TestSplitConcatenatedURLs(t *testing.T) {
	blob := "https://discord.com/api/webhooks/111/aaa" +
		"https://discord.com/api/webhooks/222/bbb" +
		"https://discord.com/api/webhooks/333/ccc"

	input := gstrings.Classify([]gstrings.ExtractedString{
		{Value: blob, Offset: 0x1000},
	})
	// Blob starts with https:// so reURL matches the whole thing as a single URL.
	if len(input) != 1 || input[0].Type != gstrings.StringTypeURL {
		t.Fatalf("precondition: blob must be classified as URL, got %v", input)
	}

	out := gstrings.SplitConcatenatedURLs(input)
	if len(out) != 3 {
		t.Fatalf("expected 3 split URLs, got %d: %v", len(out), func() []string {
			s := make([]string, len(out))
			for i, v := range out {
				s[i] = v.Value
			}
			return s
		}())
	}
	for _, s := range out {
		if s.Type != gstrings.StringTypeURL {
			t.Errorf("split part %q has type %q, want url", s.Value, s.Type)
		}
	}

	// Single-URL string must pass through unchanged
	single := gstrings.Classify([]gstrings.ExtractedString{
		{Value: "https://example.com/api"},
	})
	pass := gstrings.SplitConcatenatedURLs(single)
	if len(pass) != 1 || pass[0].Value != "https://example.com/api" {
		t.Errorf("single URL was modified: %v", pass)
	}
}
