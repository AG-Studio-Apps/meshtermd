package release

import (
	"strconv"
	"strings"
)

// VersionsMatch returns true if `current` and `target` refer to the
// same version. The build stamp is whatever `git describe --tags
// --dirty --always` printed (e.g. "v0.1.1", "v0.1.1-3-gabc1234",
// "v0.1.1-dirty"); the target is typically a clean "vMAJ.MIN.PATCH"
// tag. We compare on the leading version prefix so a dirty / post-
// tag build cleanly matches its base tag.
func VersionsMatch(current, target string) bool {
	c, ok1 := ParseSemver(current)
	t, ok2 := ParseSemver(target)
	if !ok1 || !ok2 {
		return BaseTag(current) == BaseTag(target)
	}
	return c == t
}

// CompareSemver returns (-1, 0, +1) comparing a vs b on their
// MAJOR.MINOR.PATCH triplets, or (0, false) if either side doesn't
// parse. Anything after the first '-' (pre-release / metadata) is
// IGNORED for ordering — a "vX.Y.Z-rc1" is treated as equal to
// "vX.Y.Z" here. Deliberate coarse rule: we don't rank rc1 vs rc2,
// and our release pipeline only signs final tags. Anti-rollback
// uses strict ordering, so coarse-equality is the conservative side.
func CompareSemver(a, b string) (int, bool) {
	av, ok1 := ParseSemver(a)
	bv, ok2 := ParseSemver(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		switch {
		case av[i] < bv[i]:
			return -1, true
		case av[i] > bv[i]:
			return +1, true
		}
	}
	return 0, true
}

// ParseSemver extracts MAJOR.MINOR.PATCH ints from a version string
// of the form "vMAJOR.MINOR.PATCH" (with optional "v" prefix and
// optional "-suffix"). Returns the triplet plus an ok flag; ok is
// false if any field doesn't parse as a non-negative integer.
func ParseSemver(s string) ([3]int, bool) {
	base := BaseTag(s)
	parts := strings.SplitN(base, ".", 4)
	if len(parts) < 3 {
		return [3]int{}, false
	}
	out := [3]int{}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// BaseTag strips a leading "v" and a trailing "-anything" so we get
// the bare "X.Y.Z" form.
func BaseTag(s string) string {
	s = strings.TrimPrefix(s, "v")
	if i := strings.Index(s, "-"); i != -1 {
		s = s[:i]
	}
	return s
}
