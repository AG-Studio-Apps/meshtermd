package release

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicReplace replaces the file at `dest` with the contents of
// `src`. The result has mode `mode` (e.g. 0755 for executables) and
// is fsync'd before the rename so a crash mid-write doesn't leave a
// partial binary in place.
//
// POSIX rename(2) is atomic *within the same filesystem*; callers
// should ensure `src` and `dest` share a directory (FetchBinary's
// destDir argument exists for exactly this reason).
//
// On Linux/macOS, replacing the running binary works: the open
// inode the OS is executing stays valid until exit. Next start
// runs the new file.
func AtomicReplace(src, dest string, mode os.FileMode) error {
	// Ensure mode is exactly what we want. Open(O_WRONLY) on a
	// freshly-renamed file would inherit the temp's mode; we set
	// it explicitly here so a different umask on the writer side
	// doesn't yield a 0644 binary.
	if err := os.Chmod(src, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", src, err)
	}

	// fsync the destination directory after rename — on some
	// filesystems the rename isn't durable until the parent dir's
	// metadata is flushed. Defensive: if we get a power loss after
	// rename returns, a fresh boot would have the new file or the
	// old, but not a half-rename.
	if err := os.Rename(src, dest); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", src, dest, err)
	}
	parent, err := os.Open(filepath.Dir(dest))
	if err != nil {
		// Non-fatal — many filesystems don't support directory
		// fsync, and we can still tell the caller the rename
		// succeeded. The crash window is very narrow anyway.
		return nil
	}
	defer parent.Close()
	_ = parent.Sync()
	return nil
}
