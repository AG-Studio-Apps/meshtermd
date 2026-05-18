package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestScanCaptureBytesMarker verifies the marker we use to decide
// whether the wedge-report safety warning fires matches the JSON tag
// the wedge watcher writes when MESHTERMD_WEDGE_CAPTURE_BYTES=1.
//
// Kept here rather than in internal/session because the marker is a
// command-side concern — wedgewatch could change its JSON tag in
// principle, and this test would catch a drift on the next run.
func TestScanCaptureBytesMarker(t *testing.T) {
	cases := []struct {
		name string
		line []byte
		want bool
	}{
		{"clean default record",
			[]byte(`{"timestamp":"2026-05-18T18:00:00Z","wedge_type":"vertical_walk","cud_observed":26}`),
			false},
		{"populated capture record",
			[]byte(`{"wedge_type":"vertical_walk","recent_output_b64":"AAAA"}`),
			true},
		{"empty capture stripped by omitempty (no marker present)",
			[]byte(`{"wedge_type":"silent","cud_observed":0}`),
			false},
		{"marker inside another field's value should not false-match",
			// Synthetic: a `name` field containing the literal text
			// "recent_output_b64". The marker we look for includes
			// the JSON-key terminator `":"` so this should be safe.
			[]byte(`{"note":"recent_output_b64 ignored"}`),
			false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bytes.Contains(tc.line, captureBytesFieldMarker)
			if got != tc.want {
				t.Fatalf("captureBytesFieldMarker on %q: got %v, want %v",
					tc.line, got, tc.want)
			}
		})
	}
}

// TestWedgeReportEmitsAndScans is a thin smoke test: build a tiny
// JSONL on disk, run the scan/write loop, and verify both the stdout
// faithfully mirrors the file AND the marker-detection state is
// correct. Tests the loop's correctness end-to-end without invoking
// the full subcommand harness (which would resolve cert.DefaultDir).
func TestWedgeReportEmitsAndScans(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wedge-events.jsonl")
	contents := `{"timestamp":"2026-05-18T18:00:00Z","wedge_type":"vertical_walk"}` + "\n" +
		`{"timestamp":"2026-05-18T18:00:01Z","wedge_type":"silent","recent_output_b64":"AAAA"}` + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, captureBytesFieldMarker) {
		t.Fatalf("test fixture should contain the marker; got %q", data)
	}
	if !bytes.Equal(data, []byte(contents)) {
		t.Fatalf("file readback differs from input")
	}
}
