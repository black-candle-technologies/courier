// Command courier-release-sign is the maintainer-side half of Courier's
// self-update trust model (see internal/update and docs/release-signing.md).
//
// One-time key generation (do this once, on an offline machine; keep the
// private key file offline, backed up, and out of every git repository):
//
//	courier-release-sign -generate -key /path/to/courier-release-signing.key
//
// This writes the raw 64-byte Ed25519 private key with mode 0600 and prints
// the public key hex, which must be pinned as releaseSigningPubKeyHex in
// internal/update/update.go before the first signed release is published.
//
// Signing a release (after SHA256SUMS is generated, before uploading assets):
//
//	courier-release-sign -key /path/to/courier-release-signing.key SHA256SUMS
//
// This writes SHA256SUMS.sig next to the checksums file: the raw 64-byte
// Ed25519 signature over the exact bytes of SHA256SUMS. Upload both as
// release assets.
//
// Verifying by hand:
//
//	courier-release-sign -check -pubkey <hex> SHA256SUMS
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "courier-release-sign: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	keyPath := flag.String("key", "", "path to the release-signing private key file")
	generate := flag.Bool("generate", false, "generate a new keypair instead of signing")
	check := flag.Bool("check", false, "verify <sums>.sig against -pubkey instead of signing")
	pubHex := flag.String("pubkey", "", "hex-encoded Ed25519 public key (for -check)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage:\n")
		fmt.Fprintf(os.Stderr, "  courier-release-sign -generate -key <keyfile>\n")
		fmt.Fprintf(os.Stderr, "  courier-release-sign -key <keyfile> <SHA256SUMS>\n")
		fmt.Fprintf(os.Stderr, "  courier-release-sign -check -pubkey <hex> <SHA256SUMS>\n")
	}
	flag.Parse()

	switch {
	case *generate:
		if *check {
			return fmt.Errorf("-generate and -check are mutually exclusive")
		}
		if *keyPath == "" {
			return fmt.Errorf("-key is required with -generate")
		}
		if flag.NArg() != 0 {
			return fmt.Errorf("-generate takes no file argument")
		}
		return generateKey(*keyPath)
	case *check:
		if *keyPath != "" {
			return fmt.Errorf("-key is not used with -check")
		}
		if *pubHex == "" {
			return fmt.Errorf("-pubkey is required with -check")
		}
		if flag.NArg() != 1 {
			return fmt.Errorf("-check takes exactly one SHA256SUMS file argument")
		}
		return checkSignature(flag.Arg(0), *pubHex)
	default:
		if *keyPath == "" {
			return fmt.Errorf("-key is required")
		}
		if flag.NArg() != 1 {
			return fmt.Errorf("signing takes exactly one SHA256SUMS file argument")
		}
		return signFile(*keyPath, flag.Arg(0))
	}
}

// generateKey creates a new Ed25519 release-signing keypair. The private key
// is written to path with mode 0600; an existing file is never overwritten.
func generateKey(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing key file %s", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	hexPub := hex.EncodeToString(pub)
	fmt.Printf("wrote private key: %s (0600)\n\n", path)
	fmt.Printf("Pin this public key in internal/update/update.go:\n\n")
	fmt.Printf("\tconst releaseSigningPubKeyHex = %q\n\n", hexPub)
	fmt.Printf("Keep the private key offline, backed up, and out of git.\n")
	return nil
}

// loadKey reads the raw 64-byte Ed25519 private key from path.
func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: want %d-byte Ed25519 private key, got %d bytes",
			path, ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
}

// signFile signs the exact bytes of sumsPath and writes sumsPath+".sig".
func signFile(keyPath, sumsPath string) error {
	priv, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", sumsPath, err)
	}
	sig := ed25519.Sign(priv, sums)
	sigPath := sumsPath + ".sig"
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", sigPath, err)
	}
	fmt.Printf("wrote %s (%d bytes) for %d bytes of checksums\n", sigPath, len(sig), len(sums))
	return nil
}

// checkSignature verifies sumsPath+".sig" against the given public key hex.
func checkSignature(sumsPath, pubHex string) error {
	pubRaw, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("bad -pubkey: want %d-byte hex Ed25519 public key", ed25519.PublicKeySize)
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", sumsPath, err)
	}
	sig, err := os.ReadFile(sumsPath + ".sig")
	if err != nil {
		return fmt.Errorf("read %s.sig: %w", sumsPath, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%s.sig: want %d-byte signature, got %d bytes",
			sumsPath, ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), sums, sig) {
		return fmt.Errorf("INVALID signature for %s", sumsPath)
	}
	fmt.Printf("OK: valid release signature for %s\n", sumsPath)
	return nil
}
