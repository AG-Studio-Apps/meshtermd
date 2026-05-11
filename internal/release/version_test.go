package release

import (
	"strings"
	"testing"
)

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"v0.1.1", [3]int{0, 1, 1}, true},
		{"0.1.1", [3]int{0, 1, 1}, true},
		{"v1.2.3-rc1", [3]int{1, 2, 3}, true},
		{"v0.1.1-3-gabc1234", [3]int{0, 1, 1}, true}, // git describe form
		{"v0.0.0-dev", [3]int{0, 0, 0}, true},
		{"v0.1", [3]int{}, false},    // missing patch
		{"abc", [3]int{}, false},     // garbage
		{"v-1.0.0", [3]int{}, false}, // negative major
	}
	for _, c := range cases {
		got, ok := ParseSemver(c.in)
		if ok != c.ok {
			t.Errorf("ParseSemver(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("ParseSemver(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.1.1", "v0.1.1", 0, true},
		{"v0.1.0", "v0.1.1", -1, true},
		{"v0.1.2", "v0.1.1", +1, true},
		{"v0.2.0", "v0.1.99", +1, true},
		{"v1.0.0", "v0.99.99", +1, true},
		{"v0.1.1-rc1", "v0.1.1", 0, true},   // pre-release ignored
		{"v0.1.1", "v0.1.1-dirty", 0, true}, // git describe suffix ignored
		{"garbage", "v0.1.0", 0, false},     // unparseable
	}
	for _, c := range cases {
		got, ok := CompareSemver(c.a, c.b)
		if ok != c.ok {
			t.Errorf("CompareSemver(%q,%q) ok = %v, want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("CompareSemver(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestValidateTag(t *testing.T) {
	cases := []struct {
		in   string
		want bool // want valid?
	}{
		// Happy path.
		{"v0.1.1", true},
		{"v0.3.0", true},
		{"v1.2.3", true},
		{"v10.20.30", true},
		{"v1.0.0-rc1", true},
		{"v1.0.0-alpha.2", true},
		{"v1.0.0-beta-3", true},

		// Audit traversal / injection cases.
		{"v1.0/../../etc/passwd", false},
		{"v1.0.0/../../etc/passwd", false},
		{"v1.0.0;rm -rf /", false},
		{"v1.0.0 v1.0.0", false},
		{"v1.0.0\nv1.0.0", false},
		{"v1.0.0\x00", false},

		// Shape mismatches.
		{"", false},
		{"v1.0", false},
		{"1.0.0", false},                              // missing 'v'
		{"v1.0.0+meta", false},                        // build metadata rejected
		{"v01.0.0", true},                             // leading zero is permissive — semver allows it via regex
		{"V1.0.0", false},                             // uppercase V
		{"vX.Y.Z", false},                             // non-numeric
		{"v1.0.0-", false},                            // dangling dash
		{"v1.0.0-pre release", false},                 // space
		{strings.Repeat("v1.0.0-aa", 10) + "aa", false}, // > 64 chars
	}
	for _, c := range cases {
		err := ValidateTag(c.in)
		got := err == nil
		if got != c.want {
			t.Errorf("ValidateTag(%q) = ok:%v (err=%v), want ok:%v",
				c.in, got, err, c.want)
		}
	}
}

func TestVersionsMatchTreatsDevAndTagAsEqual(t *testing.T) {
	// A "dirty" or post-tag dev build should report up-to-date
	// against its base tag so re-running `update` doesn't loop.
	cases := []struct {
		current, target string
		want            bool
	}{
		{"v0.1.1", "v0.1.1", true},
		{"v0.1.1-3-gabc1234", "v0.1.1", true},
		{"v0.1.1-dirty", "v0.1.1", true},
		{"v0.1.0", "v0.1.1", false},
		{"v0.1.1", "v0.2.0", false},
	}
	for _, c := range cases {
		if got := VersionsMatch(c.current, c.target); got != c.want {
			t.Errorf("VersionsMatch(%q,%q) = %v, want %v",
				c.current, c.target, got, c.want)
		}
	}
}
