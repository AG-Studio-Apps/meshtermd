// Package build holds version metadata stamped into the binary at link
// time. The default values are placeholders for `go run` / `go test`; the
// release build pipeline overrides them via -ldflags.
package build

import "fmt"

// Version is the semantic version of this build (e.g. "v0.1.0"). Set via
// -ldflags="-X github.com/AG-Studio-Apps/meshtermd/internal/build.Version=…".
var Version = "v0.0.0-dev"

// Commit is the short git SHA of the source this binary was built from.
var Commit = "unknown"

// Date is the RFC 3339 timestamp the binary was built at.
var Date = "unknown"

// String returns a single-line build identifier suitable for `version`
// output and for the bootstrap line's `version` field's audit trail.
func String() string {
	return fmt.Sprintf("%s (%s, built %s)", Version, Commit, Date)
}
