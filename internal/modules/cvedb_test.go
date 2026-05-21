package modules

import (
	"testing"
)

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.1", "v1.0.0", false},
		{"v1.0.0", "v1.0.0", false},
		{"v1.4.1", "v1.4.2", true},
		{"v1.4.2", "v1.4.2", false},
		{"v1.4.3", "v1.4.2", false},
		{"v2.0.0", "v1.9.9", false},
		{"v0.9.9", "v1.0.0", true},
		// no v prefix
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.0", false},
	}

	for _, tc := range cases {
		got := versionLess(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("versionLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCheckCVEs_Vulnerable(t *testing.T) {
	// v1.4.1 < v1.4.2 so should be flagged for CVE-2020-27813
	cves := checkCVEs("github.com/gorilla/websocket", "v1.4.1")
	if len(cves) == 0 {
		t.Fatal("expected CVE for vulnerable gorilla/websocket version")
	}
	found := false
	for _, c := range cves {
		if c == "CVE-2020-27813" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CVE-2020-27813 in results, got %v", cves)
	}
}

func TestCheckCVEs_Patched(t *testing.T) {
	// v1.5.0 > v1.4.2 — should NOT be flagged
	cves := checkCVEs("github.com/gorilla/websocket", "v1.5.0")
	if len(cves) != 0 {
		t.Fatalf("expected no CVEs for patched version, got %v", cves)
	}
}

func TestCheckCVEs_UnknownModule(t *testing.T) {
	cves := checkCVEs("github.com/unknown/module", "v0.0.1")
	if len(cves) != 0 {
		t.Fatalf("expected no CVEs for unknown module, got %v", cves)
	}
}

func TestCheckCVEs_ExactBoundaryVersion(t *testing.T) {
	// exact maxVersion is NOT less than itself — should not be flagged
	cves := checkCVEs("github.com/gogo/protobuf", "v1.3.2")
	if len(cves) != 0 {
		t.Fatalf("expected no CVEs at exact boundary version, got %v", cves)
	}
}

func TestParseSemver(t *testing.T) {
	cases := []struct {
		input string
		want  []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"0.0.1", []int{0, 0, 1}},
		{"10.20.30", []int{10, 20, 30}},
		// pseudo-version prefix — stops at non-digit/non-dot
		{"0.0.0-20201204", []int{0, 0, 0}},
	}
	for _, tc := range cases {
		got := parseSemver(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("parseSemver(%q) length %d, want %d: %v", tc.input, len(got), len(tc.want), got)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("parseSemver(%q)[%d] = %d, want %d", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}
