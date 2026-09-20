package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// This file implements the client side of identity backup and
// multi-device sync (issue #47). The encrypted envelope format and KDF
// live in internal/crypto (shared by backup and sync); this file covers
// building payloads from the live config, restoring a config from a
// backup payload, and merging a sync payload's keys.

// minBackupPassphraseLen is the minimum accepted passphrase for creating
// a backup or sync envelope. The passphrase is the entire secret: the
// scrypt KDF only slows guessing, it cannot save a weak passphrase.
const minBackupPassphraseLen = 8

// defaultDeviceName reports the machine's hostname for the backup's
// Device field, falling back to "unknown".
func defaultDeviceName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// backupPayload builds the inner envelope from the live config.
func (c *Config) backupPayload(kind, device string) (*crypto.BackupPayload, error) {
	if kind != crypto.BackupKindBackup && kind != crypto.BackupKindSync {
		return nil, fmt.Errorf("bad backup kind %q", kind)
	}
	seedRaw, err := base64.RawURLEncoding.DecodeString(c.Seed)
	if err != nil || len(seedRaw) != crypto.SeedLen {
		return nil, errors.New("identity seed in config is corrupt")
	}
	if len(c.EncKeys) == 0 {
		return nil, errors.New("no encryption keys in config")
	}
	if device == "" {
		device = defaultDeviceName()
	}
	keys := make([]crypto.BackupEncKey, 0, len(c.EncKeys))
	for _, k := range c.EncKeys {
		keys = append(keys, crypto.BackupEncKey{
			Pub:       k.Pub,
			Priv:      k.Priv,
			Epoch:     k.Epoch,
			CreatedAt: k.CreatedAt,
		})
	}
	return &crypto.BackupPayload{
		Version:          crypto.BackupPayloadVersion,
		Kind:             kind,
		CreatedAt:        time.Now().Unix(),
		Device:           device,
		Address:          c.Address,
		RelayURL:         c.RelayURL,
		RelayFingerprint: c.RelayFingerprint,
		Seed:             base64.RawURLEncoding.EncodeToString(seedRaw),
		EncKeys:          keys,
	}, nil
}

// CreateBackup encrypts the identity seed, the live X25519 encryption
// keypairs, and the relay connection info into a backup/sync envelope.
// kind is "backup" (for `backup restore`) or "sync" (for
// `backup import-sync`); the envelope format is identical.
func (c *Config) CreateBackup(passphrase []byte, kind, device string) ([]byte, error) {
	if len(passphrase) < minBackupPassphraseLen {
		return nil, fmt.Errorf("passphrase must be at least %d characters", minBackupPassphraseLen)
	}
	p, err := c.backupPayload(kind, device)
	if err != nil {
		return nil, err
	}
	return crypto.SealBackup(passphrase, p)
}

// DecryptBackup decrypts and validates a backup/sync envelope. A wrong
// passphrase and a corrupted file produce the same error.
func DecryptBackup(passphrase, raw []byte) (*crypto.BackupPayload, error) {
	return crypto.OpenBackup(passphrase, raw)
}

// RestoreBackup decrypts a backup envelope and writes it as this
// machine's identity. It refuses when an identity already exists unless
// force is set. The payload must be kind "backup": sync envelopes are
// merged with MergeSyncKeys instead.
//
// The restored config carries the seed, address, encryption keys, and
// relay info from the backup; everything else (contacts, dashboard,
// cursors) starts fresh. Callers should best-effort PublishKey after a
// restore so the relay directory holds the current key announcement,
// and import a fresh sync from an active device when one is available.
func RestoreBackup(passphrase, raw []byte, force bool) (*Config, error) {
	p, err := crypto.OpenBackup(passphrase, raw)
	if err != nil {
		return nil, err
	}
	if p.Kind != crypto.BackupKindBackup {
		return nil, fmt.Errorf("not a backup envelope (kind %q): `backup restore` needs a backup, `backup import-sync` merges sync envelopes", p.Kind)
	}
	var out *Config
	err = withConfigLock(func() error {
		if ConfigExists() && !force {
			existing, cfgErr := loadConfigRaw()
			addr := ""
			if cfgErr == nil {
				addr = existing.Address
			}
			return fmt.Errorf("an identity already exists%s; use --force to overwrite it", addrSuffix(addr))
		}
		relayURL := p.RelayURL
		if relayURL == "" {
			relayURL = DefaultRelay
		}
		keys := make([]EncKey, 0, len(p.EncKeys))
		for _, k := range p.EncKeys {
			keys = append(keys, EncKey{
				Pub:       k.Pub,
				Priv:      k.Priv,
				Epoch:     k.Epoch,
				CreatedAt: k.CreatedAt,
			})
		}
		out = &Config{
			Version:          ConfigVersion,
			RelayURL:         relayURL,
			RelayFingerprint: p.RelayFingerprint,
			Seed:             p.Seed,
			Address:          p.Address,
			EncKeys:          keys,
		}
		return out.saveAtomic()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func addrSuffix(addr string) string {
	if addr == "" {
		return ""
	}
	return " (" + addr + ")"
}

// MergeSyncKeys merges a sync envelope's encryption keys into the live
// config. The payload must be kind "sync" and belong to this identity
// (address match); a backup envelope is never merged — restore it
// instead.
//
// Merge rule: union by public key. The key with the highest epoch
// becomes current (ties keep the local current key); the rest follow in
// epoch order, bounded to maxRetainedKeys total like rotation does. The
// two devices having independently rotated is the only real conflict,
// and newest-wins is the principled resolution: rotations are
// monotonic in time. Returns the number of keys the sync added.
func (c *Config) MergeSyncKeys(p *crypto.BackupPayload) (added int, err error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	if p.Kind != crypto.BackupKindSync {
		return 0, fmt.Errorf("not a sync envelope (kind %q): `backup import-sync` merges sync envelopes, `backup restore` installs backups", p.Kind)
	}
	err = c.Update(func(fresh *Config) error {
		if fresh.Address != p.Address {
			return fmt.Errorf("sync envelope is for a different identity (%s)", p.Address)
		}
		seen := make(map[string]bool, len(fresh.EncKeys))
		merged := make([]EncKey, 0, len(fresh.EncKeys)+len(p.EncKeys))
		for _, k := range fresh.EncKeys {
			seen[k.Pub] = true
			merged = append(merged, k)
		}
		for _, k := range p.EncKeys {
			if seen[k.Pub] {
				continue
			}
			seen[k.Pub] = true
			merged = append(merged, EncKey{
				Pub:       k.Pub,
				Priv:      k.Priv,
				Epoch:     k.Epoch,
				CreatedAt: k.CreatedAt,
			})
			added++
		}
		// Current = highest epoch; stable sort keeps the local
		// current key first on ties.
		sort.SliceStable(merged, func(i, j int) bool {
			return merged[i].Epoch > merged[j].Epoch
		})
		if len(merged) > maxRetainedKeys {
			merged = merged[:maxRetainedKeys]
		}
		fresh.EncKeys = merged
		return nil
	})
	return added, err
}
