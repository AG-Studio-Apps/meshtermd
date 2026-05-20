package transport

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPortStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writePortState(dir, 49823)
	got := readPortState(dir)
	if got != 49823 {
		t.Errorf("readPortState after write: got %d, want 49823", got)
	}
}

func TestReadPortStateMissingFile(t *testing.T) {
	dir := t.TempDir()
	// No write — file doesn't exist.
	if got := readPortState(dir); got != 0 {
		t.Errorf("missing file: got %d, want 0", got)
	}
}

func TestReadPortStateEmptyStateDir(t *testing.T) {
	// Empty stateDir means stickiness disabled.
	if got := readPortState(""); got != 0 {
		t.Errorf("empty stateDir: got %d, want 0", got)
	}
}

func TestReadPortStateUnparseable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, portStateFile)
	if err := os.WriteFile(path, []byte("not a number"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := readPortState(dir); got != 0 {
		t.Errorf("unparseable: got %d, want 0", got)
	}
}

func TestReadPortStateZero(t *testing.T) {
	// A file containing "0" should be treated as no preference,
	// matching the missing-file case. Otherwise port 0 (the OS
	// ephemeral allocator) would shadow stickiness logic.
	dir := t.TempDir()
	path := filepath.Join(dir, portStateFile)
	if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := readPortState(dir); got != 0 {
		t.Errorf("zero literal: got %d, want 0", got)
	}
}

func TestWritePortStateBestEffort(t *testing.T) {
	// Writing to a non-existent stateDir should be a no-op
	// (best-effort: log and continue). Bare write to "" must not
	// panic and must not create anything.
	writePortState("", 49820)
	// No assertion: success criterion is "didn't panic".
}

func TestWritePortStateCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dirs", "meshtermd")
	writePortState(dir, 49830)
	// Should have created the dir tree and written the file.
	if got := readPortState(dir); got != 49830 {
		t.Errorf("after writing into nested dir: got %d, want 49830", got)
	}
}

func TestBuildCandidatePortsHappyPath(t *testing.T) {
	// No stickiness — straight walk from prefPort.
	got := buildCandidatePorts(DefaultQUICPort, 0)
	if len(got) != int(FallbackPortSpan)+1 {
		t.Fatalf("len = %d, want %d", len(got), FallbackPortSpan+1)
	}
	if got[0] != DefaultQUICPort {
		t.Errorf("first candidate: got %d, want %d", got[0], DefaultQUICPort)
	}
	if got[1] != DefaultQUICPort+1 {
		t.Errorf("second candidate: got %d, want %d", got[1], DefaultQUICPort+1)
	}
	if got[len(got)-1] != DefaultQUICPort+FallbackPortSpan {
		t.Errorf("last candidate: got %d, want %d",
			got[len(got)-1], DefaultQUICPort+FallbackPortSpan)
	}
}

func TestBuildCandidatePortsStickinessPrefersPersisted(t *testing.T) {
	// stuck=49823 + default prefPort means stuck should be tried first.
	got := buildCandidatePorts(DefaultQUICPort, 49823)
	if got[0] != 49823 {
		t.Errorf("with stuck=49823, first candidate: got %d, want 49823", got[0])
	}
	// stuck shouldn't appear twice — the walk through prefPort..+span
	// must skip it.
	count := 0
	for _, p := range got {
		if p == 49823 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("stuck port 49823 appears %d times, want exactly 1", count)
	}
}

func TestBuildCandidatePortsStickinessIgnoredForNonDefault(t *testing.T) {
	// User explicitly configured port 60000 (non-default). State
	// file says 49823. We must NOT honour stickiness — explicit
	// config wins. Walk should start at 60000.
	got := buildCandidatePorts(60000, 49823)
	if got[0] != 60000 {
		t.Errorf("with non-default pref=60000 + stuck=49823, first: got %d, want 60000", got[0])
	}
	// stuck shouldn't appear at all — it's outside the walk range.
	for _, p := range got {
		if p == 49823 {
			t.Errorf("stuck port 49823 should not appear when prefPort != default; candidates=%v", got)
			break
		}
	}
}

func TestBuildCandidatePortsStickinessSameAsPref(t *testing.T) {
	// stuck == prefPort: no special-case ordering needed.
	got := buildCandidatePorts(DefaultQUICPort, DefaultQUICPort)
	if got[0] != DefaultQUICPort {
		t.Errorf("stuck == pref: first candidate: got %d, want %d", got[0], DefaultQUICPort)
	}
	// The default port should appear exactly once, not twice.
	count := 0
	for _, p := range got {
		if p == DefaultQUICPort {
			count++
		}
	}
	if count != 1 {
		t.Errorf("default port appears %d times, want exactly 1", count)
	}
}
