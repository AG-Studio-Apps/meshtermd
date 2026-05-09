package ipc

import (
	"io/fs"
	"os"
)

// Tiny shim to keep the main test file readable. We could use
// os.Stat directly but routing through here makes the test diff
// clearer when we later add socket-mode assertions on multiple
// platforms.
func osStat(path string) (fs.FileInfo, error) { return os.Stat(path) }

func writeFile(path string, contents string, mode fs.FileMode) error {
	return os.WriteFile(path, []byte(contents), mode)
}
