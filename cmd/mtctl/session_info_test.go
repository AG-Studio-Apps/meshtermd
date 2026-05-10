package main

import (
	"strings"
	"testing"

	"github.com/AG-Studio-Apps/meshtermd/internal/ipc"
)

func TestFormatAttachedModes(t *testing.T) {
	cases := []struct {
		name     string
		modes    []string
		fallback bool
		want     string
	}{
		{"nil + fallback false", nil, false, "—"},
		{"nil + fallback true (older daemon)", nil, true, "yes"},
		{"empty slice", []string{}, false, "—"},
		{"sole exclusive", []string{"exclusive"}, true, "exclusive"},
		{"sole readonly", []string{"readonly"}, true, "readonly"},
		{"two readonly", []string{"readonly", "readonly"}, true, "2× readonly"},
		{"three readonly", []string{"readonly", "readonly", "readonly"}, true, "3× readonly"},
		{"one of each", []string{"exclusive", "readonly"}, true, "exclusive+readonly"},
		{"excl + 2 ro", []string{"exclusive", "readonly", "readonly"}, true, "exclusive+2× readonly"},
		// Order shouldn't matter — daemon may emit in either order.
		{"ro listed first", []string{"readonly", "exclusive"}, true, "exclusive+readonly"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatAttachedModes(tc.modes, tc.fallback)
			if got != tc.want {
				t.Errorf("formatAttachedModes(%v, %v) = %q, want %q",
					tc.modes, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestPickSession(t *testing.T) {
	sessions := []ipc.SessionInfo{
		{ID: "abc1234567890def1234567890fedcba", Name: "alpha"},
		{ID: "abc987654321fedcba9876543210abcd", Name: "beta"},
		{ID: "deadbeefcafebabe0123456789abcdef", Name: "gamma"},
	}
	cases := []struct {
		name     string
		selector string
		wantID   string
		wantNil  bool
	}{
		{"exact full ID", "abc1234567890def1234567890fedcba", "abc1234567890def1234567890fedcba", false},
		{"exact name", "alpha", sessions[0].ID, false},
		{"unambiguous ID prefix", "deadbeef", "deadbeefcafebabe0123456789abcdef", false},
		{"ambiguous ID prefix (abc)", "abc", "", true},
		{"unknown selector", "missing", "", true},
		// Name match wins over ID-prefix match — both alpha's name
		// "alpha" and a hypothetical session-id starting "alpha" could
		// hypothetically clash, but names can't be hex (32-char
		// lowercase) by user convention. Just ensure name is checked.
		{"empty selector", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickSession(sessions, tc.selector)
			if tc.wantNil {
				if got != nil {
					t.Errorf("pickSession(%q) = %v, want nil", tc.selector, got)
				}
				return
			}
			if got == nil {
				t.Errorf("pickSession(%q) = nil, want %s", tc.selector, tc.wantID)
				return
			}
			if got.ID != tc.wantID {
				t.Errorf("pickSession(%q).ID = %q, want %q", tc.selector, got.ID, tc.wantID)
			}
		})
	}
}

func TestPickSessionEmptySelectorIsMiss(t *testing.T) {
	// Defensive: empty string shouldn't accidentally match every
	// ID via prefix. The empty-prefix branch is gated by the
	// length check (`len(ID) >= len(selector)`), but we want a
	// regression guard.
	sessions := []ipc.SessionInfo{
		{ID: "abc1234567890def1234567890fedcba", Name: "alpha"},
	}
	if got := pickSession(sessions, ""); got != nil {
		t.Errorf("pickSession(\"\") = %v, want nil", got)
	}
}

// stringContains is a tiny helper for assertions on rendered output.
// Not used today; kept for the planned end-to-end smoke test that
// shells out to a built mtctl binary. Avoids a third-party assertion
// library for two strings.
func stringContains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

var _ = stringContains
