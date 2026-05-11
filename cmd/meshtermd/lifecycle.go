package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
)

// killOrphanDaemon SIGTERMs any `meshtermd serve` owned by the
// current uid that isn't tracked by the active svcmgr. Catches the
// case where someone ran `meshtermd serve &` manually or where a
// previous install fell back to nohup and the supervisor handover
// left a free-running process.
//
// Returns nil on success or no-match. pkill exit 1 (= no processes
// matched) is collapsed into nil; we don't want callers to fail
// uninstall because nothing needed killing.
func killOrphanDaemon(ctx context.Context) error {
	uid := strconv.Itoa(os.Getuid())
	cmd := exec.CommandContext(ctx, "pkill", "-u", uid, "-f", "meshtermd serve")
	// We don't care about exit codes here — pkill returns 1 when
	// there's nothing to kill, which is the common case after
	// svcmgr.Stop already did its job.
	_ = cmd.Run()
	return nil
}
