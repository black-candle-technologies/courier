// Package update implements Courier's self-update (v0.5.0+): the client
// checks the GitHub releases API for a newer version and can replace its
// own binary in place.
//
// Trust model (two independent layers, #102):
//
//  1. Release authenticity: every release must publish a SHA256SUMS.sig
//     asset — a raw 64-byte Ed25519 signature over the exact bytes of the
//     SHA256SUMS file, made with the Courier release-signing key whose
//     public half is pinned below. The updater verifies this signature
//     BEFORE it trusts anything from the release, including the checksums
//     themselves.
//  2. Download integrity: the downloaded binary's SHA-256 must match the
//     (now authenticated) checksums entry for it.
//
// Fail closed: releases published before signing was adopted carry no
// SHA256SUMS.sig and are rejected outright — the updater will not trust
// their checksums. The first signed release bootstraps trust for every
// release after it.
//
// What this does NOT cover: a compromised release pipeline could still
// ship a legitimately-signed malicious binary — the signature proves the
// release came from the maintainer's signing key, not that the code is
// bug-free. A signing-key rotation requires a client release pinning the
// new public key, so rotations are announced and auditable in git history.
// If you don't trust the maintainer at all, build from source instead.
//
// Release-signing procedure (key custody, asset format, rotation): see
// docs/release-signing.md.
package update

import (
	"crypto/ed25519"
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

// SumsSigAsset is the per-release asset carrying the raw 64-byte Ed25519
// signature over the exact bytes of the SHA256SUMS file.
const SumsSigAsset = "SHA256SUMS.sig"

// releaseSigningPubKeyHex pins the public half of the Courier
// release-signing Ed25519 keypair. The private half is held by the
// maintainer offline (see docs/release-signing.md) and must never appear
// in this repository.
const releaseSigningPubKeyHex = "4d687198d5f666491b8215c58f58681c6d7745e869b8a27798540d0bf7d395d4"

// releaseSigningPubKey is the parsed pinned public key, validated once at
// package init. A bad constant is a build-time-class bug: panic loudly
// rather than run with a broken trust root.
var releaseSigningPubKey = mustParseSigningKey()

func mustParseSigningKey() ed25519.PublicKey {
	raw, err := hex.DecodeString(releaseSigningPubKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		panic("update: invalid pinned release-signing public key")
	}
	return ed25519.PublicKey(raw)
}

// verifyChecksumsSignature authenticates the SHA256SUMS file bytes against
// the release's SHA256SUMS.sig, using the given Ed25519 public key. The
// pinned releaseSigningPubKey is passed on the production path; tests pass
// freshly generated keys.
func verifyChecksumsSignature(sums, sig []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("release signing key has wrong size %d (want %d)",
			len(pub), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature has wrong size %d (want %d): %s is not a valid Ed25519 signature",
			len(sig), ed25519.SignatureSize, SumsSigAsset)
	}
	if !ed25519.Verify(pub, sums, sig) {
		return fmt.Errorf("invalid release signature: %s does not match the maintainer's signature; the release may be forged or tampered with", SumsAsset)
	}
	return nil
}

// maxDownloadBytes caps a single downloaded asset at 64 MiB.
const maxDownloadBytes = 64 << 20

// Release is a parsed GitHub release.
type Release struct {
	Tag    string            // e.g. "v0.5.0"
	Assets map[string]string // asset name -> download URL
	// Sums is the asset name -> hex SHA256 map from SHA256SUMS. It is only
	// populated after SHA256SUMS.sig verifies against the pinned
	// release-signing key, so a Release returned by Latest carries
	// authenticated checksums (trust layer 1). Apply enforces trust
	// layer 2 (binary hash must match the authenticated checksums).
	Sums map[string]string
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
	return latestFrom("https://api.github.com", releaseSigningPubKey)
}

// latestFrom is Latest parameterized by API base URL and signing key, so
// tests can exercise the full fetch-verify-parse path against a local
// server with a throwaway key.
func latestFrom(apiBase string, pub ed25519.PublicKey) (*Release, error) {
	var gh struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := getJSON(apiBase+"/repos/"+Repo+"/releases/latest", &gh); err != nil {
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
		raw, err := download(sumsURL)
		if err != nil {
			return nil, fmt.Errorf("release check: download %s: %w", SumsAsset, err)
		}
		// Layer 1 (authenticity): the checksums must carry a valid
		// maintainer signature before anything is trusted. Fail closed:
		// releases published before signing was adopted have no
		// SHA256SUMS.sig and are rejected outright.
		sigURL, ok := rel.Assets[SumsSigAsset]
		if !ok {
			return nil, fmt.Errorf("release check: release %s is not signed (no %s asset); refusing to trust unsigned release checksums — see docs/release-signing.md", rel.Tag, SumsSigAsset)
		}
		sig, err := download(sigURL)
		if err != nil {
			return nil, fmt.Errorf("release check: download %s: %w", SumsSigAsset, err)
		}
		if err := verifyChecksumsSignature(raw, sig, pub); err != nil {
			return nil, fmt.Errorf("release check: %w", err)
		}
		// Only parse the checksums after the signature has verified.
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				rel.Sums[f[1]] = f[0]
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

// Apply downloads this release's binary for the current platform and
// atomically replaces the running executable. Two checks gate the swap:
// the release's SHA256SUMS must already be signature-authenticated (layer
// 1, enforced when the Release was built by Latest), and the downloaded
// binary's SHA-256 must match its entry in those checksums (layer 2).
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
