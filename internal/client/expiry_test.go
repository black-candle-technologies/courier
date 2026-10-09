package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTtlExpiry(t *testing.T) {
	if exp, err := ttlExpiry(0); err != nil || exp != 0 {
		t.Errorf("ttlExpiry(0) = %d, %v; want 0, nil", exp, err)
	}
	if _, err := ttlExpiry(-time.Second); err == nil {
		t.Error("negative ttl accepted")
	}
	before := time.Now().Unix()
	exp, err := ttlExpiry(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if exp < before+600 || exp > before+601 {
		t.Errorf("ttlExpiry(10m) = %d, want ~%d", exp, before+600)
	}
}

func TestSendWithTTLValidation(t *testing.T) {
	cfg := testConfig(t)
	c := New(cfg)
	if _, err := c.SendWithTTL("ed25519:xxx", "hi", 0); err == nil {
		t.Error("zero ttl accepted")
	}
	if _, err := c.SendWithTTL("ed25519:xxx", "hi", -time.Minute); err == nil {
		t.Error("negative ttl accepted")
	}
}

func TestReadSentLogPrunesExpired(t *testing.T) {
	setTestHome(t, t.TempDir())
	now := time.Now().Unix()
	p, err := sentLogPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// One expired entry, one live expiring entry, one immortal entry.
	if err := appendSentLog(SentEntry{CourierID: 1, To: "a", Body: "gone", SentAt: now - 100, ExpiresAt: now - 10}); err != nil {
		t.Fatal(err)
	}
	if err := appendSentLog(SentEntry{CourierID: 2, To: "a", Body: "live", SentAt: now, ExpiresAt: now + 3600}); err != nil {
		t.Fatal(err)
	}
	if err := appendSentLog(SentEntry{CourierID: 3, To: "a", Body: "forever", SentAt: now}); err != nil {
		t.Fatal(err)
	}
	entries, err := readSentLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].CourierID != 2 || entries[1].CourierID != 3 {
		t.Fatalf("pruned log = %+v, want ids 2,3", entries)
	}
	// The file itself was rewritten without the expired entry.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"gone"`) {
		t.Error("expired entry still in sent.jsonl")
	}
	// Old log lines without expires_at parse as never-expiring.
	raw2 := "{\"courier_id\":9,\"to\":\"b\",\"body\":\"legacy\",\"sent_at\":123}\n"
	if err := os.WriteFile(p, []byte(raw2), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err = readSentLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Body != "legacy" || entries[0].ExpiresAt != 0 {
		t.Fatalf("legacy entry misparsed: %+v", entries)
	}
}
