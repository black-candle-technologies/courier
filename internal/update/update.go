// Package update implements Courier's self-update (v0.5.0+): the client
// checks the GitHub releases API for a newer version and can replace its
// own binary in place. Downloads are verified against the SHA256SUMS asset
// published with each release before the binary is swapped.
//
// Trust note: the checksum file comes from the same release as the binary,
// so this verifies integrity of the download, not the release itself. If
// you don't trust the release channel, build from source instead.
package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository that publishes Courier releases.
const Repo = "black-candle-technologies/courier"

// SumsAsset is the per-release asset carrying SHA256 checksums.
const SumsAsset = "SHA256SUMS"

// maxDownloadBytes caps a single downloaded asset at 64 MiB.
const maxDownloadBytes = 64 << 20

// Release is a parsed GitHub release.
type Release struct {
	Tag    string            // e.g. "v0.5.0"
	Assets map[string]string // asset name -> download URL
	Sums   map[string]string // asset name -> hex SHA256 from SHA256SUMS
}

func getJSON(url string, v any) error {
	hc := &http.Client{Timeout: 15 * time.Second}
	resp, err := hc.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

// Latest queries the GitHub API for the newest Courier release.
func Latest() (*Release, error) {
	var gh struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := getJSON("https://api.github.com/repos/"+Repo+"/releases/latest", &gh); err != nil {
		return nil, fmt.Errorf("release check: %w", err)
	}
	if gh.TagName == "" {
		return nil, fmt.Errorf("release check: no tag_name in response")
	}
	rel := &Release{Tag: gh.TagName, Assets: map[string]string{}, Sums: map[string]string{}}
	for _, a := range gh.Assets {
		rel.Assets[a.Name] = a.URL
	}
	if sumsURL, ok := rel.Assets[SumsAsset]; ok {
		if raw, err := download(sumsURL); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				f := strings.Fields(line)
				if len(f) == 2 {
					rel.Sums[f[1]] = f[0]
				}
			}
		}
	}
	return rel, nil
}

func download(url string) ([]byte, error) {
	hc := &http.Client{Timeout: 120 * time.Second}
	resp, err := hc.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
}

// parseVersion splits "v1.2.3" (or "1.2.3") into numeric components.
func parseVersion(v string) ([]int, error) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// Ignore pre-release/build suffixes for comparison purposes.
		if i := strings.IndexAny(p, "-+"); i >= 0 {
			p = p[:i]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("bad version %q", v)
		}
		out = append(out, n)
	}
	return out, nil
}

// NewerThan reports whether tag is a newer version than current.
// Both may carry a "v" prefix or not.
func NewerThan(current, tag string) bool {
	a, err1 := parseVersion(current)
	b, err2 := parseVersion(tag)
	if err1 != nil || err2 != nil {
		return false
	}
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if y > x {
			return true
		}
		if y < x {
			return false
		}
	}
	return false
}

// binaryName is the release asset for this platform.
func binaryName() string {
	return fmt.Sprintf("courier-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// Apply downloads this release's binary for the current platform,
// verifies its SHA256 against the release's SHA256SUMS, and atomically
// replaces the running executable.
func (r *Release) Apply() error {
	name := binaryName()
	dlURL, ok := r.Assets[name]
	if !ok {
		return fmt.Errorf("no %s asset in release %s", name, r.Tag)
	}
	want, ok := r.Sums[name]
	if !ok {
		return fmt.Errorf("no checksum for %s in release %s; refusing to self-update without one", name, r.Tag)
	}
	raw, err := download(dlURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != strings.ToLower(want) {
		return fmt.Errorf("checksum mismatch for %s: download may be corrupted or tampered with", name)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, "courier-update-*")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	return nil
}
