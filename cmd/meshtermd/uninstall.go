package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/cert"
	"github.com/AG-Studio-Apps/meshtermd/internal/release"
	"github.com/AG-Studio-Apps/meshtermd/internal/svcmgr"
)

// runUninstall implements `meshtermd uninstall [--purge] [--yes]`.
//
// Plain `uninstall`:
//   - stops any running daemon
//   - removes the systemd unit / launchd plist
//   - removes the binary at ~/.local/bin/meshtermd
//   - LEAVES the state dir (~/.local/share/meshtermd) alone so a
//     reinstall keeps the same cert and iOS's pinned fingerprint
//     still matches
//
// `--purge` also wipes the state dir.
// `--yes` skips the confirmation prompt.
//
// Exit codes:
//   0  clean removal
//   1  partial removal (something couldn't be removed)
//   2  user cancelled or bad flags
func runUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false,
		"also remove ~/.local/share/meshtermd (cert, private key, sockets). "+
			"Default keeps state so a future reinstall can reuse the same identity.")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd uninstall [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	binPath := release.JoinBin()
	stateDir, _ := cert.DefaultDir()

	if !*yes {
		fmt.Println("This will:")
		fmt.Println("  • Stop any running meshtermd daemon")
		fmt.Println("  • Remove the systemd unit / launchd plist")
		fmt.Println("  • Remove the binary at", binPath)
		if *purge {
			fmt.Println("  • PURGE the state directory at", stateDir)
			fmt.Println("    (removes cert + private key — iOS will need to re-pair)")
		} else {
			fmt.Println("  • Keep the state directory at", stateDir)
			fmt.Println("    (use --purge to also remove it)")
		}
		fmt.Print("\nProceed? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
			fmt.Println("Cancelled.")
			return 2
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stragglers := 0

	// 1. Stop + remove supervisor record.
	mgr := svcmgr.Detect(ctx)
	fmt.Printf("▸ Stopping daemon via %s\n", mgr.Name())
	if err := mgr.Stop(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: stop: %v\n", err)
	}
	fmt.Printf("▸ Removing supervisor record\n")
	if err := mgr.Remove(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: remove: %v\n", err)
	}

	// Also catch a free-running daemon that wasn't under any
	// supervisor (e.g. user manually ran `meshtermd serve &`).
	// pkill returns 1 if no matches — fine.
	_ = killOrphanDaemon(ctx)

	// 2. Remove the binary itself. On Linux/macOS POSIX, unlinking
	//    a running executable is safe: our process keeps its inode
	//    open until exit, the directory entry is gone immediately.
	if fileExists(binPath) {
		if err := os.Remove(binPath); err != nil {
			fmt.Fprintf(os.Stderr, "  ✘ remove binary %s: %v\n", binPath, err)
			stragglers++
		} else {
			fmt.Printf("▸ Removed binary at %s\n", binPath)
		}
	} else {
		fmt.Printf("▸ No binary at %s (already removed?)\n", binPath)
	}

	// 3. Purge state dir if requested.
	if *purge {
		if fileExists(stateDir) {
			if err := os.RemoveAll(stateDir); err != nil {
				fmt.Fprintf(os.Stderr, "  ✘ purge state dir %s: %v\n", stateDir, err)
				stragglers++
			} else {
				fmt.Printf("▸ Purged state dir %s\n", stateDir)
			}
		} else {
			fmt.Printf("▸ No state dir at %s\n", stateDir)
		}
	}

	fmt.Println()
	if stragglers > 0 {
		fmt.Fprintf(os.Stderr, "✘ %d item(s) couldn't be removed — manual cleanup needed.\n", stragglers)
		return 1
	}
	fmt.Println("✓ Uninstall complete.")
	if !*purge {
		fmt.Println()
		fmt.Println("State directory kept at:", stateDir)
		fmt.Println("Run with --purge to remove cert + private key as well.")
	}
	return 0
}

// fileExists is the std existence check used by uninstall flow.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
