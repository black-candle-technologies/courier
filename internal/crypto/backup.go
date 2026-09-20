package crypto

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// This file implements Courier's identity backup and multi-device sync
// envelope (issue #47). Backup and sync share one encrypted container
// format and one key-derivation story; they differ only in the payload's
// Kind field and in how the client applies the payload.
//
// Backup: an encrypted copy of the identity seed plus the live X25519
// encryption keypairs, written to a file. Restoring it on a fresh device
// recreates the identity (same address, same keys).
//
// Sync: the same envelope carrying the live key material to another
// device that already holds the identity. The receiving device merges
// the keys instead of replacing its config.
//
// Format (outer JSON container, versioned):
//
//	{
//	  "format": "courier-backup", "version": 1,
//	  "kdf": "scrypt", "scrypt_n": 32768, "scrypt_r": 8, "scrypt_p": 1,
//	  "salt": "<base64url 16 bytes>",
//	  "nonce": "<base64url 24 bytes>",
//	  "ciphertext": "<base64url secretbox of the inner payload JSON>"
//	}
//
// The scrypt key (32 bytes) seals the inner payload with NaCl secretbox
// (XSalsa20-Poly1305). Everything but salt/nonce/ciphertext is public;
// the passphrase is the entire secret. A wrong passphrase fails the
// secretbox authentication check, which is indistinguishable from a
// corrupted file — the error message deliberately does not say which.
//
// Threat model notes:
//   - The backup file plus the passphrase owns the identity: seed and
//     live private encryption keys. Guard the file (0600 on write) and
//     pick a long, unique passphrase.
//   - The relay is never involved: backup/sync envelopes are files the
//     operator moves between machines (scp, USB, QR, ...). No new
//     protocol surface, no relay-retained key material.

const (
	// BackupFormat is the outer container's format tag.
	BackupFormat = "courier-backup"
	// BackupFormatVersion is the current outer container version.
	BackupFormatVersion = 1
	// BackupPayloadVersion is the current inner payload version.
	BackupPayloadVersion = 1

	// BackupKindBackup marks a payload meant for `backup restore`.
	BackupKindBackup = "backup"
	// BackupKindSync marks a payload meant for `backup import-sync`.
	BackupKindSync = "sync"
)

// Scrypt parameters for the passphrase KDF: the standard interactive
// settings (N=2^15, r=8, p=1), ~100ms on modern hardware.
const (
	backupScryptN      = 32768
	backupScryptR      = 8
	backupScryptP      = 1
	backupScryptKeyLen = 32
	backupSaltLen      = 16
)

// BackupEncKey is one X25519 encryption keypair carried in a payload.
type BackupEncKey struct {
	Pub       string `json:"pub"`        // base64url 32-byte X25519 public key
	Priv      string `json:"priv"`       // base64url 32-byte X25519 private key
	Epoch     int64  `json:"epoch"`      // unix seconds of rotation (monotonic)
	CreatedAt int64  `json:"created_at"` // unix seconds
}

// BackupPayload is the inner (encrypted) envelope. JSON-marshaled, then
// sealed with secretbox under the scrypt-derived key.
type BackupPayload struct {
	Version          int            `json:"version"` // BackupPayloadVersion
	Kind             string         `json:"kind"`    // "backup" or "sync"
	CreatedAt        int64          `json:"created_at"`
	Device           string         `json:"device,omitempty"` // producing device's name
	Address          string         `json:"address"`          // ed25519:<base64url>
	RelayURL         string         `json:"relay_url,omitempty"`
	RelayFingerprint string         `json:"relay_fingerprint,omitempty"`
	Seed             string         `json:"seed"`     // base64url 32-byte identity seed
	EncKeys          []BackupEncKey `json:"enc_keys"` // live keypairs, current first
}

// backupFile is the outer encrypted container.
type backupFile struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	ScryptN    int    `json:"scrypt_n"`
	ScryptR    int    `json:"scrypt_r"`
	ScryptP    int    `json:"scrypt_p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// backupKDF derives the 32-byte sealing key from the passphrase and salt.
func backupKDF(passphrase, salt []byte, n, r, p int) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}
	return scrypt.Key(passphrase, salt, n, r, p, backupScryptKeyLen)
}

// SealBackup encrypts the payload into the versioned outer container.
// The payload's Version/Kind/CreatedAt are filled in by the caller.
func SealBackup(passphrase []byte, p *BackupPayload) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var salt [backupSaltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	key, err := backupKDF(passphrase, salt[:], backupScryptN, backupScryptR, backupScryptP)
	if err != nil {
		return nil, err
	}
	var k [32]byte
	copy(k[:], key)
	inner, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var nonce [NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	sealed := secretbox.Seal(nil, inner, &nonce, &k)
	out := backupFile{
		Format:     BackupFormat,
		Version:    BackupFormatVersion,
		KDF:        "scrypt",
		ScryptN:    backupScryptN,
		ScryptR:    backupScryptR,
		ScryptP:    backupScryptP,
		Salt:       b64.EncodeToString(salt[:]),
		Nonce:      b64.EncodeToString(nonce[:]),
		Ciphertext: b64.EncodeToString(sealed),
	}
	return json.MarshalIndent(out, "", "  ")
}

// OpenBackup decrypts an envelope produced by SealBackup and returns the
// validated payload. A wrong passphrase and a corrupted file produce the
// same error.
func OpenBackup(passphrase, raw []byte) (*BackupPayload, error) {
	var f backupFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("not a courier backup file: %w", err)
	}
	if f.Format != BackupFormat {
		return nil, fmt.Errorf("not a courier backup file (format %q)", f.Format)
	}
	if f.Version != BackupFormatVersion {
		return nil, fmt.Errorf("unsupported backup format version %d", f.Version)
	}
	if f.KDF != "scrypt" {
		return nil, fmt.Errorf("unsupported kdf %q", f.KDF)
	}
	salt, err := b64.DecodeString(f.Salt)
	if err != nil || len(salt) != backupSaltLen {
		return nil, errors.New("bad salt in backup file")
	}
	nonceRaw, err := b64.DecodeString(f.Nonce)
	if err != nil || len(nonceRaw) != NonceLen {
		return nil, errors.New("bad nonce in backup file")
	}
	ct, err := b64.DecodeString(f.Ciphertext)
	if err != nil {
		return nil, errors.New("bad ciphertext in backup file")
	}
	key, err := backupKDF(passphrase, salt, f.ScryptN, f.ScryptR, f.ScryptP)
	if err != nil {
		return nil, err
	}
	var k [32]byte
	copy(k[:], key)
	var nonce [NonceLen]byte
	copy(nonce[:], nonceRaw)
	inner, ok := secretbox.Open(nil, ct, &nonce, &k)
	if !ok {
		return nil, errors.New("cannot decrypt backup: wrong passphrase or corrupted file")
	}
	var p BackupPayload
	if err := json.Unmarshal(inner, &p); err != nil {
		return nil, errors.New("backup payload is corrupted")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the payload's structural integrity: version, kind,
// address, seed, and at least one encryption key. It also verifies the
// seed actually derives the claimed address, catching corruption that
// slips past structural checks.
func (p *BackupPayload) Validate() error {
	if p.Version != BackupPayloadVersion {
		return fmt.Errorf("unsupported backup payload version %d", p.Version)
	}
	if p.Kind != BackupKindBackup && p.Kind != BackupKindSync {
		return fmt.Errorf("bad backup kind %q", p.Kind)
	}
	edPub, err := ParseAddress(p.Address)
	if err != nil {
		return fmt.Errorf("bad address in backup: %w", err)
	}
	seedRaw, err := b64.DecodeString(p.Seed)
	if err != nil || len(seedRaw) != SeedLen {
		return errors.New("bad seed in backup")
	}
	id, err := IdentityFromSeed(seedRaw)
	if err != nil {
		return fmt.Errorf("bad seed in backup: %w", err)
	}
	if id.EdPub != edPub {
		return errors.New("backup seed does not match backup address")
	}
	if len(p.EncKeys) == 0 {
		return errors.New("backup carries no encryption keys")
	}
	for i, k := range p.EncKeys {
		pub, err1 := b64.DecodeString(k.Pub)
		priv, err2 := b64.DecodeString(k.Priv)
		if err1 != nil || err2 != nil || len(pub) != PubKeyLen || len(priv) != PubKeyLen {
			return fmt.Errorf("bad encryption key %d in backup", i)
		}
	}
	return nil
}
