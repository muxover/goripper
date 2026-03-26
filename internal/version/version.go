package version

import (
	"fmt"
	"runtime"
)

// Version vars are injected at build time via -ldflags.
// Fallback values are used for local dev builds.
var (
	Version = "v0.0.0-dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a formatted version string.
func String() string {
	return fmt.Sprintf("%s (%s %s/%s)\n  commit: %s\n  built:  %s",
		Version, runtime.Version(), runtime.GOOS, runtime.GOARCH, Commit, Date)
}
