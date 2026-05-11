package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/build"
	"github.com/AG-Studio-Apps/meshtermd/internal/release"
)

// runUpdate implements `mtctl update [--check] [--yes] [--tag X] [--allow-downgrade]`.
//
// Mirrors `meshtermd update` exactly except for two differences:
//   - Downloads mtctl-<platform> instead of meshtermd-<platform>.
//   - No service restart afterwards. mtctl is short-lived (each
//     invocation re-execs the binary fresh), so swapping the file
//     in place is all that's needed.
//
// Exit codes match meshtermd update so wrapping scripts work for both:
//   0  up to date OR update succeeded
//   1  update available (only when --check is passed)
//   2  bad flags / user cancelled
//   3  verification failed
//   4  download / network failure
func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	checkOnly := fs.Bool("check", false,
		"print current vs available version and exit. "+
			"Exit 0 if up to date, 1 if an update is available, "+
			"3 on verification failure, 4 on network error.")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	tag := fs.String("tag", "", "update to a specific tag instead of the latest release")
	allowDowngrade := fs.Bool("allow-downgrade", false,
		"permit installing a tag older than the running version. "+
			"By default a downgrade refuses to proceed.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: mtctl update [flags]\n\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fetcher := release.NewFetcher()
	current := build.Version

	target := *tag
	if target == "" {
		var err error
		target, _, err = fetcher.LatestTag(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "update: %v\n", err)
			return 4
		}
	}
	if !strings.HasPrefix(target, "v") {
		target = "v" + target
	}
	if err := release.ValidateTag(target); err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 2
	}

	fmt.Printf("current:    %s\n", current)
	fmt.Printf("available:  %s\n", target)

	if release.VersionsMatch(current, target) {
		fmt.Println("✓ already on this version")
		return 0
	}

	cmp, ok := release.CompareSemver(target, current)
	if ok && cmp < 0 && !*allowDowngrade {
		fmt.Fprintf(os.Stderr,
			"update: refusing to downgrade %s → %s. "+
				"Re-run with --allow-downgrade if this is intentional.\n",
			current, target)
		return 3
	}

	if *checkOnly {
		fmt.Println("Update available. Run `mtctl update` to apply.")
		return 1
	}

	if !*yes {
		fmt.Print("\nApply update? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
			fmt.Println("Cancelled.")
			return 2
		}
	}

	return performUpdate(ctx, fetcher, target)
}

func performUpdate(ctx context.Context, fetcher *release.Fetcher, tag string) int {
	asset, err := mtctlAssetFilename()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 4
	}
	binPath := mtctlBinPath()
	destDir := filepath.Dir(binPath)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "update: create bin dir: %v\n", err)
		return 4
	}

	fmt.Println("▸ downloading signed checksums")
	shaSums, err := fetcher.FetchSmall(ctx, fetcher.AssetURL(tag, "SHA256SUMS"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 4
	}
	sigFile, err := fetcher.FetchSmall(ctx, fetcher.AssetURL(tag, "SHA256SUMS.minisig"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 4
	}

	fmt.Println("▸ verifying signature")
	roster, err := release.TrustedRoster()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: roster: %v\n", err)
		return 3
	}
	result, err := release.MinisignVerify(shaSums, sigFile, roster)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: signature: %v\n", err)
		return 3
	}
	fmt.Printf("  signed by key %d (%s)\n", result.KeyIndex, result.TrustedComment)
	if result.KeyIndex == 1 {
		fmt.Fprintln(os.Stderr,
			"  ! EMERGENCY signing key was used — verify this release with the maintainer")
	}

	fmt.Printf("▸ downloading %s\n", asset)
	tmpPath, err := fetcher.FetchBinary(ctx, fetcher.AssetURL(tag, asset), destDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 4
	}
	defer os.Remove(tmpPath)

	fmt.Println("▸ verifying binary hash")
	expected, err := release.LookupChecksum(shaSums, asset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 3
	}
	actual, err := release.ChecksumOf(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 3
	}
	if actual != expected {
		fmt.Fprintf(os.Stderr, "update: SHA-256 mismatch (expected %s, got %s)\n",
			expected, actual)
		return 3
	}

	fmt.Println("▸ swapping binary")
	if err := release.AtomicReplace(tmpPath, binPath, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "update: replace: %v\n", err)
		return 4
	}

	fmt.Printf("\n✓ Updated to %s — re-run mtctl to use the new version.\n", tag)
	return 0
}

// mtctlAssetFilename returns the release-asset filename for the
// current host's GOOS/GOARCH combination (e.g. "mtctl-linux-amd64").
// Parallel of release.AssetFilename which targets meshtermd.
func mtctlAssetFilename() (string, error) {
	osPart := runtime.GOOS
	archPart := runtime.GOARCH
	switch osPart {
	case "linux":
		switch archPart {
		case "amd64", "arm64":
			return fmt.Sprintf("mtctl-%s-%s", osPart, archPart), nil
		case "arm":
			return "mtctl-linux-armv7", nil
		}
	case "darwin", "freebsd":
		switch archPart {
		case "amd64", "arm64":
			return fmt.Sprintf("mtctl-%s-%s", osPart, archPart), nil
		}
	}
	return "", fmt.Errorf("no release asset for %s/%s", osPart, archPart)
}

// mtctlBinPath returns the conventional install path for mtctl.
// Used by update + uninstall.
func mtctlBinPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "mtctl")
	}
	return filepath.Join(home, ".local", "bin", "mtctl")
}
