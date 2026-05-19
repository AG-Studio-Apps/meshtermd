package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AG-Studio-Apps/meshtermd/internal/build"
	"github.com/AG-Studio-Apps/meshtermd/internal/release"
	"github.com/AG-Studio-Apps/meshtermd/internal/svcmgr"
)

// runUpdate implements `meshtermd update [--check] [--yes] [--tag X]`.
//
// What it does:
//  1. Resolve the target tag (latest or --tag).
//  2. If the current build matches the target, exit 0 with "up to date".
//  3. Download SHA256SUMS + SHA256SUMS.minisig + the platform binary.
//  4. Verify SHA256SUMS minisig signature against the embedded
//     primary + emergency public-key roster (same as iOS).
//  5. Verify SHA-256 of the downloaded binary against the entry in
//     the now-trusted SHA256SUMS.
//  6. Atomic-replace the running binary.
//  7. Restart the daemon via the detected supervisor.
//
// Exit codes:
//   0  up to date OR update succeeded
//   1  update available (only when --check is passed)
//   2  bad flags / user cancelled
//   3  verification failed
//   4  download / network failure
//   5  service restart failed (binary updated but daemon may be down)
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
			"By default a downgrade refuses to proceed — even with --tag — "+
			"so an accidental or attacker-induced 'latest' rollback can't "+
			"silently install a known-vulnerable older signed build.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: meshtermd update [flags]\n\n")
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

	// Anti-rollback: refuse to silently install a tag older than the
	// running version. The minisign signature on an older release is
	// still valid (it was signed at the time) — so without this check
	// a flipped GitHub "latest" pointer, a malicious mirror, or a
	// typoed `--tag` could downgrade us into a known-bad build.
	cmp, ok := release.CompareSemver(target, current)
	if ok && cmp < 0 && !*allowDowngrade {
		fmt.Fprintf(os.Stderr,
			"update: refusing to downgrade %s → %s. "+
				"Re-run with --allow-downgrade if this is intentional.\n",
			current, target)
		return 3
	}

	if *checkOnly {
		fmt.Println("Update available. Run `meshtermd update` to apply.")
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

// performUpdate runs the full verify-and-swap pipeline. Split out so
// `runUpdate` stays under the function-length lint ceiling.
func performUpdate(ctx context.Context, fetcher *release.Fetcher, tag string) int {
	asset, err := release.AssetFilename()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 4
	}
	binPath := release.JoinBin()
	destDir := filepath.Dir(binPath)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "update: create bin dir: %v\n", err)
		return 4
	}

	fmt.Println("▸ downloading signed checksums")
	shaSumsURL := fetcher.AssetURL(tag, "SHA256SUMS")
	sigURL := fetcher.AssetURL(tag, "SHA256SUMS.minisig")
	shaSums, err := fetcher.FetchSmall(ctx, shaSumsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		return 4
	}
	sigFile, err := fetcher.FetchSmall(ctx, sigURL)
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
	// Bind the signature to the requested tag — minisign verifies the
	// SHA list was signed by our key, but not WHICH release it belongs
	// to. Without this, a re-published older SHA256SUMS would still
	// verify and the anti-rollback semver check would still accept the
	// "newer" target, letting an older (potentially vulnerable) binary
	// in. See internal/release/trusted_comment.go for the contract.
	if err := release.EnforceTrustedComment(result.TrustedComment, tag); err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
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
	defer os.Remove(tmpPath) // best-effort; rename below moves it on success

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

	fmt.Println("▸ restarting daemon")
	mgr := svcmgr.Detect(ctx)
	if err := mgr.Restart(ctx, binPath); err != nil {
		fmt.Fprintf(os.Stderr, "update: restart via %s: %v\n", mgr.Name(), err)
		fmt.Fprintln(os.Stderr,
			"  binary is updated; restart the daemon manually to pick it up")
		return 5
	}

	fmt.Printf("\n✓ Updated to %s via %s\n", tag, mgr.Name())
	return 0
}

// Version comparison helpers moved to internal/release/version.go so
// mtctl's update path can share them. See release.VersionsMatch and
// release.CompareSemver.
