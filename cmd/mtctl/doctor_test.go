package main

import "testing"

func TestVersionsMatchLoose(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mtctl  string
		daemon string
		want   bool
	}{
		{
			name:   "identical bare versions match",
			mtctl:  "v0.6.2",
			daemon: "v0.6.2",
			want:   true,
		},
		{
			name:   "daemon's verbose suffix tolerated",
			mtctl:  "v0.6.2",
			daemon: "v0.6.2 (abc123, built 2026-05-12T...)",
			want:   true,
		},
		{
			name:   "patch-version differ → skew",
			mtctl:  "v0.6.1",
			daemon: "v0.6.2 (abc, built ...)",
			want:   false,
		},
		{
			name:   "minor-version differ → skew",
			mtctl:  "v0.6.2",
			daemon: "v0.7.0",
			want:   false,
		},
		{
			name:   "empty mtctl → no false positive",
			mtctl:  "",
			daemon: "v0.6.2",
			want:   true,
		},
		{
			name:   "empty daemon → no false positive",
			mtctl:  "v0.6.2",
			daemon: "",
			want:   true,
		},
		{
			name:   "both have parenthetical suffixes",
			mtctl:  "v0.6.2 (xyz)",
			daemon: "v0.6.2 (abc)",
			want:   true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := versionsMatchLoose(tc.mtctl, tc.daemon)
			if got != tc.want {
				t.Errorf("versionsMatchLoose(%q, %q) = %v, want %v",
					tc.mtctl, tc.daemon, got, tc.want)
			}
		})
	}
}

func TestFirstToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"v0.6.2", "v0.6.2"},
		{"v0.6.2 (abc)", "v0.6.2"},
		{"v0.6.2\t(abc)", "v0.6.2"},
		{"v0.6.2(abc)", "v0.6.2"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := firstToken(tc.in); got != tc.want {
			t.Errorf("firstToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
