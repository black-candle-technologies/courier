package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

func TestNamedInboxReplyFallbackCannotReadLegacyPlaintext(t *testing.T) {
	_, legacy := reviewConfig(t, false)
	legacy.writeReplyCache([]replyCacheEntry{{CourierID: 42, Snippet: "other identity private plaintext"}})
	var wire any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{wire}})
	}))
	defer server.Close()
	cfg, err := NewIdentity(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(server.Certificate().Raw)
	cfg.RelayFingerprint = hex.EncodeToString(pin[:])
	h := Hosts{Enabled: true, Bindings: map[string]RelayBinding{"r": {ID: "r", Endpoint: cfg.RelayURL, Pin: cfg.RelayFingerprint}}, Identities: map[string]NamedIdentity{"i": {Principal: cfg.Address, BindingID: "r"}}, Hosts: map[string]Host{"h": {BindingID: "r", Identity: "i"}}}
	scope, err := h.Resolve(legacy.root, "h", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.localContext = &scope
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body, err := encodeReplyPayload("reply", 42, "", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire = pushTestEnvelope(t, sender, cfg, 43, string(body))
	cl := New(cfg)
	msgs, _, _, _, _, err := cl.inbox(0, 50, false, seenConsumerPush)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("inbox: %v %+v", err, msgs)
	}
	if msgs[0].ReplyQuote != "" {
		t.Fatalf("foreign quote leaked: %q", msgs[0].ReplyQuote)
	}
	scope.writeReplyCache([]replyCacheEntry{{CourierID: 42, Snippet: "named parent"}})
	msgs, _, _, _, _, err = cl.inbox(0, 50, false, seenConsumerPush)
	if err != nil || len(msgs) != 1 || msgs[0].ReplyQuote != "named parent" {
		t.Fatalf("named cache not used: %v %+v", err, msgs)
	}
}

func TestMigratedDefaultReplyAndBackupAdapters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("migration disabled on Windows")
	}
	cfg, legacy := reviewConfig(t, false)
	legacy.writeReplyCache([]replyCacheEntry{{CourierID: 42, Snippet: "retained stale parent"}})
	backup, err := cfg.CreateBackup([]byte("fixture-passphrase"), crypto.BackupKindBackup, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	target := migrationTarget(t, legacy)
	if err = legacy.MigrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true}); err != nil {
		t.Fatal(err)
	}
	target.writeReplyCache([]replyCacheEntry{{CourierID: 42, Snippet: "active parent"}})
	if quote, ok := LookupReplyParent(42); !ok || quote != "active parent" {
		t.Errorf("adapter read wrong context: %q %v", quote, ok)
	}
	if quote, ok := legacy.LookupReplyParent(42); ok || quote != "" {
		t.Errorf("retained legacy lookup returned plaintext: %q", quote)
	}
	before, err := os.ReadFile(filepath.Join(legacy.root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreBackup([]byte("fixture-passphrase"), backup, true)
	if err != nil {
		t.Fatalf("active restore: %v", err)
	}
	if restored.Context() != target {
		t.Fatal("restore selected wrong context")
	}
	after, err := os.ReadFile(filepath.Join(legacy.root, "config.json"))
	if err != nil || string(after) != string(before) {
		t.Fatal("restore changed retained legacy config", err)
	}
	if err := os.WriteFile(filepath.Join(legacy.root, "active-context.json"), []byte("invalid manifest"), 0600); err != nil {
		t.Fatal(err)
	}
	if quote, ok := LookupReplyParent(42); ok || quote != "" {
		t.Fatal("invalid manifest fell back to retained plaintext")
	}
	if _, err := RestoreBackup([]byte("fixture-passphrase"), backup, true); err == nil {
		t.Fatal("invalid manifest allowed backup restore")
	}

}
