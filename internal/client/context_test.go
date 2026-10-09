package client

import (
	"errors"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyContextCapturesRootWithoutWriting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ctx := LegacyContext()
	other := t.TempDir()
	t.Setenv("HOME", other)
	t.Setenv("USERPROFILE", other)
	root, err := ctx.StateRoot()
	if err != nil || root != filepath.Join(home, ".courier") {
		t.Fatalf("root = %q, %v", root, err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("context creation touched disk: %v", err)
	}
	for _, name := range []string{"../config.json", "", ".", ".."} {
		if _, err := ctx.path(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if _, err := (Context{}).StateRoot(); err == nil {
		t.Fatal("zero context resolved")
	}
}

func TestContextStoresRemainBound(t *testing.T) {
	a := Context{root: t.TempDir()}
	b := Context{root: t.TempDir()}
	cfg, err := NewIdentity("https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	cfg.localContext = &a
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	other, err := NewIdentity("https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	other.localContext = &b
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	cfg.Contacts = map[string]string{"peer": other.Address}
	cfg.SeenInboxHashes = []string{"same-envelope"}
	cfg.SeenPushHashes = []string{"push-envelope"}
	cfg.Cursor, cfg.WakeCursor, cfg.DirectoryEpoch = 17, 18, 19
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	// A changed process default must not redirect either Update or sidecars.
	otherHome := t.TempDir()
	t.Setenv("HOME", otherHome)
	t.Setenv("USERPROFILE", otherHome)
	if err := cfg.Update(func(f *Config) error { f.Cursor++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.updateFS(func(f *fsFile) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.updateVHL(func(f *vhlFile) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.updateGroups(func(g map[string]*groupState) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.updateReceipts(func(r *receiptStore) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := a.appendSentLog(SentEntry{CourierID: 42, Body: "context-a"}); err != nil {
		t.Fatal(err)
	}
	a.writeReplyCache([]replyCacheEntry{{CourierID: 43, Snippet: "private-a"}})
	fresh, err := b.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Cursor != 0 || fresh.DirectoryEpoch != 0 || len(fresh.Contacts) != 0 || len(fresh.SeenInboxHashes) != 0 {
		t.Fatal("config crossed contexts")
	}
	for _, name := range []string{"fs.json", "vhl.json", "groups.json", "receipts.json", "sent.jsonl", "thread_cache.jsonl"} {
		if _, err := os.Stat(filepath.Join(a.root, name)); err != nil {
			t.Fatal(name, err)
		}
		if _, err := os.Stat(filepath.Join(b.root, name)); !os.IsNotExist(err) {
			t.Fatal("sidecar crossed contexts", name, err)
		}
	}
	if _, ok := b.LookupReplyParent(42); ok {
		t.Fatal("sent log crossed contexts")
	}
	if _, ok := b.LookupReplyParent(43); ok {
		t.Fatal("reply cache crossed contexts")
	}
	fresh, err = a.LoadConfig()
	if err != nil || fresh.Cursor != 18 || fresh.WakeCursor != 18 || fresh.DirectoryEpoch != 19 {
		t.Fatalf("bound update failed: %+v %v", fresh, err)
	}
}

func TestHostsAliasesAndSecurityBindings(t *testing.T) {
	cfg, err := NewIdentity("https://relay.invalid")
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("a", 64)
	h := Hosts{Enabled: true, Bindings: map[string]RelayBinding{"r": {ID: "r", Endpoint: "https://RELAY.invalid:443/", Pin: pin}}, Identities: map[string]NamedIdentity{"alice": {Principal: cfg.Address, BindingID: "r"}}, Hosts: map[string]Host{"work": {BindingID: "r", Identity: "alice"}, "alias": {BindingID: "r", Identity: "alice"}}}
	root := t.TempDir()
	a, err := h.Resolve(root, "work", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Resolve(root, "alias", "")
	if err != nil || a != b {
		t.Fatal("aliases diverge", err)
	}
	cfg.RelayFingerprint = pin
	cfg.localContext = &a
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	h.Bindings["r"] = RelayBinding{ID: "r", Endpoint: "https://replacement.invalid", Pin: pin}
	changed, err := h.Resolve(root, "work", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.LoadConfig(); !errors.Is(err, ErrContextMismatch) {
		t.Fatal("endpoint change accepted", err)
	}
	h.Bindings["other"] = RelayBinding{ID: "other", Endpoint: "https://other.invalid", Pin: pin}
	h.Identities["duplicate"] = NamedIdentity{Principal: cfg.Address, BindingID: "other"}
	if _, err := h.Resolve(root, "work", ""); err == nil {
		t.Fatal("cross-relay principal accepted")
	}
	h.Enabled = false
	if _, err := h.Resolve(root, "work", ""); !errors.Is(err, ErrContextsDisabled) {
		t.Fatal("default gate bypassed")
	}
}

func TestContextRequiredFSAndVHLDoNotCross(t *testing.T) {
	a, b := Context{root: t.TempDir()}, Context{root: t.TempDir()}
	first, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	first.localContext = &a
	second.localContext = &b
	if err = first.Save(); err != nil {
		t.Fatal(err)
	}
	if err = second.Save(); err != nil {
		t.Fatal(err)
	}
	ca, cb := New(first), New(second)
	if err = ca.FSRequire(second.Address, true); err != nil {
		t.Fatal(err)
	}
	if err = ca.VHLSetRequiredTier(1); err != nil {
		t.Fatal(err)
	}
	if required, err := ca.FSRequired(second.Address); err != nil || !required {
		t.Fatal(required, err)
	}
	if required, err := cb.FSRequired(second.Address); err != nil || required {
		t.Fatal("FS policy leaked", err)
	}
	if tier, err := cb.VHLGetRequiredTier(); err != nil || tier != 0 {
		t.Fatal("VHL policy leaked", err)
	}
}

func TestLegacyUpdateRefusesReplacedPrincipal(t *testing.T) {
	s := Context{root: t.TempDir()}
	old, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	old.localContext = &s
	if err = old.Save(); err != nil {
		t.Fatal(err)
	}
	replacement, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	replacement.localContext = &s
	if err = replacement.Save(); err != nil {
		t.Fatal(err)
	}
	if err = old.Update(func(f *Config) error { f.Cursor = 100; return nil }); !errors.Is(err, ErrContextMismatch) {
		t.Fatal("running client switched principal", err)
	}
	fresh, err := s.LoadConfig()
	if err != nil || fresh.Address != replacement.Address || fresh.Cursor != 0 {
		t.Fatal("replacement changed", err)
	}
}

func TestNamedContextBackupResetAndSyncBinding(t *testing.T) {
	legacy := Context{root: t.TempDir()}
	cfg, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RelayFingerprint = strings.Repeat("a", 64)
	cfg.localContext = &legacy
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	scoped := migrationTarget(t, legacy)
	// Restore into a separate installation; the original fixture remains a
	// different device. Same-installation duplication is rejected below.
	separateRoot := t.TempDir()
	scoped, err = scoped.manifest().resolve(separateRoot)
	if err != nil {
		t.Fatal(err)
	}
	cfg.localContext = &scoped
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	if err = c.FSRequire(cfg.Address, true); err != nil {
		t.Fatal(err)
	}
	if err = c.VHLSetRequiredTier(1); err != nil {
		t.Fatal(err)
	}
	payload, err := cfg.backupPayload(crypto.BackupKindSync, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	payload.RelayURL = "https://other.invalid"
	if _, err = cfg.MergeSyncKeys(payload); !errors.Is(err, ErrContextMismatch) {
		t.Fatal("cross-relay sync accepted", err)
	}
	raw, err := cfg.CreateBackup([]byte("fixture-only-passphrase"), crypto.BackupKindBackup, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	restored, err := scoped.RestoreBackup([]byte("fixture-only-passphrase"), raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Context() != scoped || restored.Cursor != 0 || len(restored.Contacts) != 0 {
		t.Fatal("restore scope or fresh state incorrect")
	}
	for _, name := range []string{"fs.json", "vhl.json"} {
		if _, err = os.Stat(filepath.Join(scoped.root, name)); !os.IsNotExist(err) {
			t.Fatal("restore retained state", name, err)
		}
	}
	original, err := legacy.loadConfigRaw()
	if err != nil || original.Address != cfg.Address {
		t.Fatal("restore changed another context", err)
	}
}

func TestPrincipalBindingSurvivesAliasRemoval(t *testing.T) {
	root := t.TempDir()
	cfg, err := NewIdentity("https://first.invalid")
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("a", 64)
	cfg.RelayFingerprint = pin
	registry := func(binding, endpoint string) Hosts {
		return Hosts{Enabled: true, Bindings: map[string]RelayBinding{binding: {ID: binding, Endpoint: endpoint, Pin: pin}}, Identities: map[string]NamedIdentity{"identity": {cfg.Address, binding}}, Hosts: map[string]Host{"host": {binding, "identity"}}}
	}
	first, err := registry("first", cfg.RelayURL).Resolve(root, "host", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.localContext = &first
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	// Entirely replace aliases; the durable principal binding must still win.
	second, err := registry("second", "https://second.invalid").Resolve(root, "host", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.localContext = &second
	cfg.RelayURL = "https://second.invalid"
	if err = cfg.Save(); !errors.Is(err, ErrContextMismatch) {
		t.Fatal("alias removal reset D3", err)
	}
	if second.ConfigExists() {
		t.Fatal("rejected binding wrote a config")
	}
}

func TestNamedRestoreCannotBypassLegacyMigration(t *testing.T) {
	legacy := Context{root: t.TempDir()}
	cfg, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RelayFingerprint = strings.Repeat("a", 64)
	cfg.localContext = &legacy
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	target := migrationTarget(t, legacy)
	raw, err := cfg.CreateBackup([]byte("fixture-only-passphrase"), crypto.BackupKindBackup, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = target.RestoreBackup([]byte("fixture-only-passphrase"), raw, true); !errors.Is(err, ErrMigrationRequired) {
		t.Fatal("backup bypassed migration", err)
	}
	if target.ConfigExists() {
		t.Fatal("duplicate principal store created")
	}
}
