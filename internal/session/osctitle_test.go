package session

import "testing"

func TestOSCTitleTracker(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		feed  []byte
		want  string
	}{
		{
			name: "OSC 2 set window title, BEL terminated",
			feed: []byte("\x1b]2;Claude Code\x07"),
			want: "Claude Code",
		},
		{
			name: "OSC 0 set icon + window title, BEL terminated",
			feed: []byte("\x1b]0;bash — ~/proj\x07"),
			want: "bash — ~/proj",
		},
		{
			name: "OSC 2 ST terminated (ESC \\)",
			feed: []byte("\x1b]2;htop\x1b\\"),
			want: "htop",
		},
		{
			name: "OSC 1 (icon name only) is NOT captured",
			feed: []byte("\x1b]1;icon-name\x07"),
			want: "",
		},
		{
			name: "OSC 4 (color spec) is NOT captured",
			feed: []byte("\x1b]4;1;rgb:ff/00/00\x07"),
			want: "",
		},
		{
			name: "OSC 52 (clipboard) is NOT captured",
			feed: []byte("\x1b]52;c;ZWNobyBoaQ==\x07"),
			want: "",
		},
		{
			name: "Title with multiple words and punctuation",
			feed: []byte("\x1b]2;user@host:/path/to/dir$\x07"),
			want: "user@host:/path/to/dir$",
		},
		{
			name: "Title overwritten by later OSC keeps the latest",
			feed: []byte("\x1b]2;first\x07\x1b]2;second\x07"),
			want: "second",
		},
		{
			name: "Mixed OSC 0 then OSC 2 keeps the latest",
			feed: []byte("\x1b]0;icon-and-title\x07\x1b]2;just-title\x07"),
			want: "just-title",
		},
		{
			name: "Malformed OSC (premature ESC inside body without \\) aborts",
			feed: []byte("\x1b]2;par\x1bX"),
			want: "",
		},
		{
			name: "Non-OSC noise around a valid OSC",
			feed: []byte("hello \x1b[?1049h \x1b]2;Claude Code\x07 world"),
			want: "Claude Code",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := &oscTitleTracker{}
			tracker.feed(tc.feed)
			if got := tracker.Title(); got != tc.want {
				t.Fatalf("Title()=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestOSCTitleTrackerChunkBoundary(t *testing.T) {
	t.Parallel()
	// Title arrives split across two feed() calls. State must
	// persist across chunks.
	tracker := &oscTitleTracker{}
	tracker.feed([]byte("\x1b]2;Claude"))
	tracker.feed([]byte(" Code\x07"))
	if got := tracker.Title(); got != "Claude Code" {
		t.Fatalf("split-chunk Title()=%q, want %q", got, "Claude Code")
	}
}

func TestOSCTitleTrackerLengthCap(t *testing.T) {
	t.Parallel()
	huge := make([]byte, 0, maxTrackedTitleLen+512)
	huge = append(huge, []byte("\x1b]2;")...)
	for i := 0; i < maxTrackedTitleLen+200; i++ {
		huge = append(huge, 'A')
	}
	huge = append(huge, 0x07)
	tracker := &oscTitleTracker{}
	tracker.feed(huge)
	got := tracker.Title()
	if len(got) != maxTrackedTitleLen {
		t.Fatalf("over-cap title length=%d, want %d", len(got), maxTrackedTitleLen)
	}
}

func TestOSCTitleTrackerSetTitle(t *testing.T) {
	t.Parallel()
	tracker := &oscTitleTracker{}
	tracker.SetTitle("Restored Title")
	if got := tracker.Title(); got != "Restored Title" {
		t.Fatalf("SetTitle did not seed: got %q", got)
	}
	// Subsequent OSC overrides the seeded value.
	tracker.feed([]byte("\x1b]2;Fresh\x07"))
	if got := tracker.Title(); got != "Fresh" {
		t.Fatalf("OSC did not override seed: got %q", got)
	}
}
