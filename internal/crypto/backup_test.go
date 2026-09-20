package crypto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testBackupPayload(t *testing.T) *BackupPayload {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	return &BackupPayload{
		Version:   BackupPayloadVersion,
		Kind:      BackupKindBackup,
		CreatedAt: time.Now().Unix(),
		Device:    "test-device",
		Address:   FormatAddress(id.EdPub[:]),
		RelayURL:  "https://example.invalid:8470",
		Seed:      b64.EncodeToString(id.Seed[:]),
		EncKeys: []BackupEncKey{{
			Pub:       b64.EncodeToString(pub[:]),
			Priv:      b64.EncodeToString(priv[:]),
			Epoch:     time.Now().Unix(),
			CreatedAt: time.Now().Unix(),
		}},
	}
}

func TestBackupRoundTrip(t *testing.T) {
	p := testBackupPayload(t)
	raw, err := SealBackup([]byte("correct horse battery staple"), p)
	if err != nil {
		t.Fatal(err)
	}
	// The outer container must not leak the seed or keys in the clear.
	for _, leak := range []string{p.Seed, p.EncKeys[0].Priv, p.Address} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("backup file leaks plaintext field")
		}
	}
	got, err := OpenBackup([]byte("correct horse battery staple"), raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != p.Address || got.Seed != p.Seed || got.Kind != p.Kind {
		t.Fatal("payload mismatch after round trip")
	}
	if len(got.EncKeys) != 1 || got.EncKeys[0].Pub != p.EncKeys[0].Pub {
		t.Fatal("enc keys mismatch after round trip")
	}
}

func TestBackupWrongPassphrase(t *testing.T) {
	raw, err := SealBackup([]byte("right"), testBackupPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup([]byte("wrong"), raw); err == nil {
		t.Fatal("expected decryption failure with wrong passphrase")
	}
}

func TestBackupTamperedCiphertext(t *testing.T) {
	raw, err := SealBackup([]byte("pass"), testBackupPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	var f backupFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	ct, _ := b64.DecodeString(f.Ciphertext)
	ct[0] ^= 0xff
	f.Ciphertext = b64.EncodeToString(ct)
	tampered, _ := json.Marshal(f)
	if _, err := OpenBackup([]byte("pass"), tampered); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}
}

func TestBackupNotABackupFile(t *testing.T) {
	if _, err := OpenBackup([]byte("pass"), []byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("expected error for non-backup JSON")
	}
	if _, err := OpenBackup([]byte("pass"), []byte(`not json at all`)); err == nil {
		t.Fatal("expected error for non-JSON")
	}
}

func TestBackupEmptyPassphrase(t *testing.T) {
	if _, err := SealBackup(nil, testBackupPayload(t)); err == nil {
		t.Fatal("expected error for empty passphrase on seal")
	}
	raw, err := SealBackup([]byte("pass"), testBackupPayload(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(nil, raw); err == nil {
		t.Fatal("expected error for empty passphrase on open")
	}
}

func TestBackupValidateRejects(t *testing.T) {
	p := testBackupPayload(t)

	bad := *p
	bad.Kind = "weird"
	if _, err := SealBackup([]byte("x"), &bad); err == nil {
		t.Fatal("expected rejection of bad kind")
	}

	bad = *p
	bad.Seed = b64.EncodeToString(make([]byte, 32)) // seed not matching address
	if _, err := SealBackup([]byte("x"), &bad); err == nil {
		t.Fatal("expected rejection of seed/address mismatch")
	}

	bad = *p
	bad.EncKeys = nil
	if _, err := SealBackup([]byte("x"), &bad); err == nil {
		t.Fatal("expected rejection of empty enc keys")
	}

	bad = *p
	bad.Version = 99
	if _, err := SealBackup([]byte("x"), &bad); err == nil {
		t.Fatal("expected rejection of bad payload version")
	}
}

func TestBackupSyncKindRoundTrip(t *testing.T) {
	p := testBackupPayload(t)
	p.Kind = BackupKindSync
	raw, err := SealBackup([]byte("pass"), p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenBackup([]byte("pass"), raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != BackupKindSync {
		t.Fatalf("kind = %q, want sync", got.Kind)
	}
}

func TestBackupSaltsDiffer(t *testing.T) {
	p := testBackupPayload(t)
	a, err := SealBackup([]byte("same"), p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealBackup([]byte("same"), p)
	if err != nil {
		t.Fatal(err)
	}
	var fa, fb backupFile
	json.Unmarshal(a, &fa)
	json.Unmarshal(b, &fb)
	if fa.Salt == fb.Salt || fa.Nonce == fb.Nonce || fa.Ciphertext == fb.Ciphertext {
		t.Fatal("two seals of the same payload must differ (fresh salt+nonce)")
	}
}
