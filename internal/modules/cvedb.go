package modules

type cveRecord struct {
	module     string
	maxVersion string
	id         string
}

var knownCVEs = []cveRecord{
	{"github.com/gorilla/websocket", "v1.4.2", "CVE-2020-27813"},
	{"golang.org/x/crypto", "v0.0.0-20201204", "CVE-2020-29652"},
	{"github.com/gin-gonic/gin", "v1.6.0", "CVE-2020-28483"},
	{"github.com/dgrijalva/jwt-go", "v4.0.0", "CVE-2020-26160"},
	{"github.com/gogo/protobuf", "v1.3.2", "CVE-2021-3121"},
	{"golang.org/x/net", "v0.0.0-20210521", "CVE-2021-33194"},
	{"github.com/miekg/dns", "v1.1.43", "CVE-2024-29868"},
}

func checkCVEs(modulePath, version string) []string {
	var found []string
	for _, c := range knownCVEs {
		if c.module == modulePath && versionLess(version, c.maxVersion) {
			found = append(found, c.id)
		}
	}
	return found
}

func versionLess(a, b string) bool { return compareVersion(a, b) < 0 }

func compareVersion(a, b string) int {
	if len(a) > 0 && a[0] == 'v' {
		a = a[1:]
	}
	if len(b) > 0 && b[0] == 'v' {
		b = b[1:]
	}
	ap, bp := parseSemver(a), parseSemver(b)
	for i := 0; i < 3; i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func parseSemver(v string) []int {
	parts := make([]int, 0, 3)
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else if c == '.' {
			parts = append(parts, n)
			n = 0
		} else {
			break
		}
	}
	return append(parts, n)
}
