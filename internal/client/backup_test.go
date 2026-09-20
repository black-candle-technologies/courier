package client

import (
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// testBackupConfig creates and saves an identity in a fresh temp HOME.
func testBackupConfig(t *testing.T) *Config {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cfg, err := NewIdentity("https://example.invalid:8470")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestCreateDecryptRoundTrip(t *testing.T) {
	cfg := testBackupConfig(t)
	raw, err := cfg.CreateBackup([]byte("a-long-enough-passphrase"), crypto.BackupKindBackup, "device-a")
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecryptBackup([]byte("a-long-enough-passphrase"), raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != crypto.BackupKindBackup || p.Device != "device-a" {
		t.Fatalf("kind/device = %q/%q", p.Kind, p.Device)
	}
	if p.Address != cfg.Address || p.Seed != cfg.Seed {
		t.Fatal("address/seed mismatch")
	}
	if len(p.EncKeys) != len(cfg.EncKeys) || p.EncKeys[0].Pub != cfg.EncKeys[0].Pub {
		t.Fatal("enc keys mismatch")
	}
	if p.RelayURL != cfg.RelayURL {
		t.Fatal("relay URL not carried")
	}
	if _, err := DecryptBackup([]byte("wrong-passphrase-here"), raw); err == nil {
		t.Fatal("expected failure with wrong passphrase")
	}
}

func TestCreateBackupRejectsShortPassphrase(t *testing.T) {
	cfg := testBackupConfig(t)
	if _, err := cfg.CreateBackup([]byte("short"), crypto.BackupKindBackup, ""); err == nil {
		t.Fatal("expected rejection of short passphrase")
	}
}

func TestRestoreBackupFreshDevice(t *testing.T) {
	src := testBackupConfig(t)
	raw, err := src.CreateBackup([]byte("a-long-enough-passphrase"), crypto.BackupKindBackup, "src")
	if err != nil {
		t.Fatal(err)
	}

	// Fresh device: empty HOME, no identity.
	t.Setenv("HOME", t.TempDir())
	restored, err := RestoreBackup([]byte("a-long-enough-passphrase"), raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Address != src.Address {
		t.Fatal("restored address mismatch")
	}
	// The restored seed must derive the same identity.
	id, err := restored.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if crypto.FormatAddress(id.EdPub[:]) != src.Address {
		t.Fatal("restored seed does not derive the source address")
	}
	if len(restored.EncKeys) != len(src.EncKeys) {
		t.Fatal("restored enc keys mismatch")
	}
	if restored.RelayURL != src.RelayURL {
		t.Fatal("restored relay URL mismatch")
	}
	// Reload from disk: the restore must have persisted.
	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Address != src.Address || reloaded.Seed != src.Seed {
		t.Fatal("restored config did not persist")
	}
}

func TestRestoreBackupRefusesExisting(t *testing.T) {
	src := testBackupConfig(t)
	raw, err := src.CreateBackup([]byte("a-long-enough-passphrase"), crypto.BackupKindBackup, "src")
	if err != nil {
		t.Fatal(err)
	}
	// Same HOME: an identity already exists.
	if _, err := RestoreBackup([]byte("a-long-enough-passphrase"), raw, false); err == nil {
		t.Fatal("expected refusal when identity exists")
	}
	// --force overwrites.
	if _, err := RestoreBackup([]byte("a-long-enough-passphrase"), raw, true); err != nil {
		t.Fatalf("force restore failed: %v", err)
	}
}

func TestRestoreBackupRejectsSyncKind(t *testing.T) {
	cfg := testBackupConfig(t)
	raw, err := cfg.CreateBackup([]byte("a-long-enough-passphrase"), crypto.BackupKindSync, "src")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	if _, err := RestoreBackup([]byte("a-long-enough-passphrase"), raw, false); err == nil {
		t.Fatal("expected rejection of sync envelope by restore")
	}
}

// TestMergeSyncKeys simulates two devices sharing one identity: device B
// rotates (new current key), then device A merges B's sync envelope.
func TestMergeSyncKeys(t *testing.T) {
	homeA := t.TempDir()
	t.Setenv("HOME", homeA)
	cfgA, err := NewIdentity("https://example.invalid:8470")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfgA.Save(); err != nil {
		t.Fatal(err)
	}
	oldCurrent := cfgA.EncKeys[0].Pub

	// Device B: same seed/address, but rotated to a newer key.
	t.Setenv("HOME", t.TempDir())
	cfgB, err := NewIdentity("https://example.invalid:8470")
	if err != nil {
		t.Fatal(err)
	}
	cfgB.Seed = cfgA.Seed
	cfgB.Address = cfgA.Address
	cfgB.EncKeys = cfgA.EncKeys // start from the same keys...
	// ...then rotate: prepend a newer key with a higher epoch.
	pub, priv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	newEpoch := cfgB.EncKeys[0].Epoch + 100
	cfgB.EncKeys = append([]EncKey{{
		Pub:       b64enc(pub[:]),
		Priv:      b64enc(priv[:]),
		Epoch:     newEpoch,
		CreatedAt: newEpoch,
	}}, cfgB.EncKeys...)

	syncRaw, err := cfgB.CreateBackup([]byte("a-long-enough-passphrase"), crypto.BackupKindSync, "device-b")
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecryptBackup([]byte("a-long-enough-passphrase"), syncRaw)
	if err != nil {
		t.Fatal(err)
	}

	// Merge into device A.
	t.Setenv("HOME", homeA)
	cfgA, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	added, err := cfgA.MergeSyncKeys(p)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	if cfgA.EncKeys[0].Pub != b64enc(pub[:]) {
		t.Fatal("newest-epoch key is not current after merge")
	}
	// The old key is retained for in-flight messages.
	found := false
	for _, k := range cfgA.EncKeys[1:] {
		if k.Pub == oldCurrent {
			found = true
		}
	}
	if !found {
		t.Fatal("pre-rotation key was dropped by the merge")
	}
	if len(cfgA.EncKeys) > maxRetainedKeys {
		t.Fatalf("merged keys exceed maxRetainedKeys: %d", len(cfgA.EncKeys))
	}
	// Merging the same sync again adds nothing.
	added, err = cfgA.MergeSyncKeys(p)
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("re-merge added = %d, want 0", added)
	}
}

func TestMergeSyncKeysRejects(t *testing.T) {
	homeA := t.TempDir()
	t.Setenv("HOME", homeA)
	a, err := NewIdentity("https://example.invalid:8470")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}

	// Different identity's sync.
	t.Setenv("HOME", t.TempDir())
	other, err := NewIdentity("https://example.invalid:8470")
	if err != nil {
		t.Fatal(err)
	}
	syncRaw, err := other.CreateBackup([]byte("a-long-enough-passphrase"), crypto.BackupKindSync, "other")
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecryptBackup([]byte("a-long-enough-passphrase"), syncRaw)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", homeA)
	a, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.MergeSyncKeys(p); err == nil {
		t.Fatal("expected rejection of another identity's sync")
	}

	// Backup-kind envelope is never merged.
	backupRaw, err := a.CreateBackup([]byte("a-long-enough-passphrase"), crypto.BackupKindBackup, "a")
	if err != nil {
		t.Fatal(err)
	}
	bp, err := DecryptBackup([]byte("a-long-enough-passphrase"), backupRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.MergeSyncKeys(bp); err == nil {
		t.Fatal("expected rejection of backup-kind envelope by merge")
	}
}
