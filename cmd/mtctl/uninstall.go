package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"flag"
)

// runUninstall implements `mtctl uninstall [--yes]`.
//
// Simpler than `meshtermd uninstall` because mtctl is just a binary:
// no daemon to stop, no supervisor unit to remove, no state dir to
// purge. Single step: unlink ~/.local/bin/mtctl. POSIX semantics
// let us remove the running executable (mtctl uninstalling itself);
// the inode lives until our process exits.
//
// Exit codes:
//
//	0  binary removed (or already absent)
//	1  remove failed
//	2  user cancelled
func runUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl uninstall [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	binPath := mtctlBinPath()

	if !*yes {
		fmt.Printf("This will remove the mtctl binary at %s.\n", binPath)
		fmt.Print("Proceed? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
			fmt.Println("Cancelled.")
			return 2
		}
	}

	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		fmt.Printf("Nothing to do — %s does not exist.\n", binPath)
		return 0
	}
	if err := os.Remove(binPath); err != nil {
		fmt.Fprintf(os.Stderr, "uninstall: remove %s: %v\n", binPath, err)
		return 1
	}
	fmt.Printf("✓ Removed %s\n", binPath)
	return 0
}
