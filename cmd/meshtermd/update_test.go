package main

import "testing"

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
		{"v0.1", [3]int{}, false},     // missing patch
		{"abc", [3]int{}, false},      // garbage
		{"v-1.0.0", [3]int{}, false},  // negative major
	}
	for _, c := range cases {
		got, ok := parseSemver(c.in)
		if ok != c.ok {
			t.Errorf("parseSemver(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("parseSemver(%q) = %v, want %v", c.in, got, c.want)
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
		got, ok := compareSemver(c.a, c.b)
		if ok != c.ok {
			t.Errorf("compareSemver(%q,%q) ok = %v, want %v", c.a, c.b, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("compareSemver(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
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
		if got := versionsMatch(c.current, c.target); got != c.want {
			t.Errorf("versionsMatch(%q,%q) = %v, want %v",
				c.current, c.target, got, c.want)
		}
	}
}
