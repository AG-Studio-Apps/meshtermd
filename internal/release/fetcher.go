package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// GithubAPIBase is the host for tag-resolution API calls.
	// Overridable in tests via NewFetcher.
	defaultGithubAPIBase = "https://api.github.com"
	// ReleaseBase is where the actual asset bytes live.
	defaultReleaseBase = "https://github.com/AG-Studio-Apps/meshtermd/releases/download"
	// Owner/repo for the GitHub Releases API URL.
	releaseRepoPath = "AG-Studio-Apps/meshtermd"
)

// Fetcher resolves and downloads release artifacts from GitHub.
// Constructed via NewFetcher so tests can substitute the HTTP client
// and base URLs without touching networking.
type Fetcher struct {
	http        *http.Client
	apiBase     string
	releaseBase string
}

// NewFetcher returns a Fetcher with sensible defaults. Pass overrides
// from tests via the optional functional configuration.
func NewFetcher(opts ...FetcherOption) *Fetcher {
	f := &Fetcher{
		http: &http.Client{Timeout: 60 * time.Second},
		apiBase:     defaultGithubAPIBase,
		releaseBase: defaultReleaseBase,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// FetcherOption is the functional-option type for NewFetcher.
type FetcherOption func(*Fetcher)

// WithHTTPClient overrides the default http.Client. Use in tests to
// inject an httptest.NewServer-backed transport.
func WithHTTPClient(c *http.Client) FetcherOption {
	return func(f *Fetcher) { f.http = c }
}

// WithAPIBase overrides the GitHub API host. The path stays
// "/repos/AG-Studio-Apps/meshtermd/releases/...".
func WithAPIBase(base string) FetcherOption {
	return func(f *Fetcher) { f.apiBase = strings.TrimRight(base, "/") }
}

// WithReleaseBase overrides the asset-download host. Resulting URLs
// look like "<base>/<tag>/<filename>".
func WithReleaseBase(base string) FetcherOption {
	return func(f *Fetcher) { f.releaseBase = strings.TrimRight(base, "/") }
}

// LatestTag asks the GitHub API for the repo's latest non-prerelease
// tag. Returns the tag name (e.g. "v0.1.1") and the release's
// publish time so callers can decide whether to surface "available
// since 3 days ago" hints.
func (f *Fetcher) LatestTag(ctx context.Context) (string, time.Time, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", f.apiBase, releaseRepoPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	// GitHub's API requires either an Accept header or a User-Agent.
	// We send both — Accept pins the API version, User-Agent identifies
	// us so abuse can be traced back without rate-limiting all of
	// GitHub's anonymous traffic.
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "meshtermd-self-update/1")
	resp, err := f.http.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("github api: HTTP %d", resp.StatusCode)
	}
	var payload struct {
		TagName     string    `json:"tag_name"`
		PublishedAt time.Time `json:"published_at"`
		Prerelease  bool      `json:"prerelease"`
		Draft       bool      `json:"draft"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", time.Time{}, fmt.Errorf("parse release json: %w", err)
	}
	if payload.Draft || payload.Prerelease {
		return "", time.Time{}, fmt.Errorf("latest release is %s; refusing to self-update to it",
			condStr(payload.Draft, "a draft", "a pre-release"))
	}
	if payload.TagName == "" {
		return "", time.Time{}, fmt.Errorf("github api returned empty tag")
	}
	return payload.TagName, payload.PublishedAt, nil
}

// AssetURL constructs the download URL for one asset of a release.
// Filename should be one of the platform asset names (e.g.
// "meshtermd-linux-amd64").
//
// Both `tag` and `filename` are URL-path-escaped. Callers in the
// update path validate `tag` against ValidateTag upstream, so the
// escape here is defence-in-depth — if a future caller skips
// validation, a traversal payload still can't escape its path
// segments.
func (f *Fetcher) AssetURL(tag, filename string) string {
	return fmt.Sprintf("%s/%s/%s", f.releaseBase, url.PathEscape(tag), url.PathEscape(filename))
}

// FetchSmall returns the entire body of an asset in memory. Use for
// small files (SHA256SUMS, .minisig). Refuses anything over 8 MiB —
// a corrupt or malicious server can't trick us into allocating
// gigabytes via a huge Content-Length.
func (f *Fetcher) FetchSmall(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "meshtermd-self-update/1")
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	const maxSmall = 8 << 20
	limited := io.LimitReader(resp.Body, maxSmall+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(body) > maxSmall {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", url, maxSmall)
	}
	return body, nil
}

// FetchBinary downloads a release asset to a temp file in `destDir`
// (same dir as the eventual target so os.Rename is atomic) and
// returns the temp path. Caller is responsible for renaming +
// fsyncing the destination.
func (f *Fetcher) FetchBinary(ctx context.Context, url, destDir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "meshtermd-self-update/1")
	resp, err := f.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	// 100 MiB ceiling — far above any plausible meshtermd binary
	// size but a guard against runaway responses.
	const maxBinary = 100 << 20

	f1, err := os.CreateTemp(destDir, "meshtermd-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp: %w", err)
	}
	tmpPath := f1.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	written, err := io.Copy(f1, io.LimitReader(resp.Body, maxBinary+1))
	if err != nil {
		_ = f1.Close()
		cleanup()
		return "", fmt.Errorf("write binary: %w", err)
	}
	if written > maxBinary {
		_ = f1.Close()
		cleanup()
		return "", fmt.Errorf("download exceeds %d bytes", maxBinary)
	}
	if err := f1.Sync(); err != nil {
		_ = f1.Close()
		cleanup()
		return "", fmt.Errorf("fsync: %w", err)
	}
	if err := f1.Close(); err != nil {
		cleanup()
		return "", fmt.Errorf("close: %w", err)
	}
	return tmpPath, nil
}

// AssetFilename returns the release-asset filename for the current
// host's GOOS/GOARCH combination (e.g. "meshtermd-linux-amd64").
// Returns an error for platforms we don't ship binaries for.
func AssetFilename() (string, error) {
	osPart := runtime.GOOS
	archPart := runtime.GOARCH
	switch osPart {
	case "linux":
		switch archPart {
		case "amd64", "arm64":
			return fmt.Sprintf("meshtermd-%s-%s", osPart, archPart), nil
		case "arm":
			// We only ship armv7 (GOARCH=arm + GOARM=7). Lower
			// ARM variants aren't supported.
			return "meshtermd-linux-armv7", nil
		}
	case "darwin":
		switch archPart {
		case "amd64", "arm64":
			return fmt.Sprintf("meshtermd-%s-%s", osPart, archPart), nil
		}
	case "freebsd":
		switch archPart {
		case "amd64", "arm64":
			return fmt.Sprintf("meshtermd-%s-%s", osPart, archPart), nil
		}
	}
	return "", fmt.Errorf("no release asset for %s/%s", osPart, archPart)
}

// ChecksumOf returns the SHA-256 hex digest of the file at `path`.
func ChecksumOf(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// LookupChecksum scans the body of a SHA256SUMS file for the entry
// matching `filename`. Returns the lowercase hex digest, or an error
// if the file isn't present.
//
// Format per `sha256sum` output: "<64 hex chars><whitespace><name>\n".
// Some signers prefix names with "./"; we accept either form.
func LookupChecksum(shaSums []byte, filename string) (string, error) {
	for _, line := range strings.Split(string(shaSums), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimPrefix(parts[1], "./")
		if name == filename {
			return strings.ToLower(parts[0]), nil
		}
	}
	return "", fmt.Errorf("no SHA256SUMS entry for %s", filename)
}

func condStr(cond bool, ifTrue, ifFalse string) string {
	if cond {
		return ifTrue
	}
	return ifFalse
}

// JoinBin returns the conventional install path for the binary on
// this OS. Used by the uninstall + update commands to know where the
// running binary lives without depending on argv[0].
func JoinBin() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", "meshtermd")
	}
	return filepath.Join(home, ".local", "bin", "meshtermd")
}
