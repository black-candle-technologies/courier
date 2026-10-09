package client

import (
	"errors"
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
	t.Setenv("HOME", t.TempDir())
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
