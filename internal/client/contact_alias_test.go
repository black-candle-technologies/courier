package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPreferredContactAliasRepointAndFailedSave(t *testing.T) {
	cfg := testConfig(t)
	old, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContact("bob", old.Address); err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContactAlias("zach", old.Address); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		path, err := configPath()
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(path)
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0700)
		for _, change := range []func() error{
			func() error { return cfg.AddContactAlias("zach", next.Address) },
			func() error { return cfg.RemoveContact("zach") },
		} {
			if err := change(); err == nil {
				t.Fatal("save unexpectedly succeeded")
			}
			if cfg.ContactNameForAddress(old.Address) != "zach" || cfg.Contacts["zach"] != old.Address {
				t.Fatal("failed save lost in-memory preference")
			}
			saved, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if saved.ContactNameForAddress(old.Address) != "zach" {
				t.Fatal("failed save changed persisted preference")
			}
		}
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := cfg.AddContactAlias("zach", next.Address); err != nil {
		t.Fatal(err)
	}
	saved, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if saved.ContactNameForAddress(old.Address) != "bob" || saved.ContactNameForAddress(next.Address) != "zach" {
		t.Fatal("repointed alias mislabeled identities")
	}
	if saved.PreferredContactNames[old.Address] != "" {
		t.Fatal("obsolete preference retained")
	}
}

func TestAliasMutationPreservesConcurrentState(t *testing.T) {
	cfg := testConfig(t)
	a, _ := NewIdentity("")
	b, _ := NewIdentity("")
	if err := cfg.AddContactAlias("peer", a.Address); err != nil {
		t.Fatal(err)
	}
	stale, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(f *Config) error {
		f.EncKeys[0].Epoch++
		f.VerifiedKeyEpochs = map[string]int64{a.Address: 123}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	epoch := cfg.EncKeys[0].Epoch
	if err := stale.AddContactAlias("peer", b.Address); err != nil {
		t.Fatal(err)
	}
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.EncKeys[0].Epoch != epoch || fresh.VerifiedKeyEpochs[a.Address] != 123 || fresh.ContactNameForAddress(b.Address) != "peer" {
		t.Fatal("alias lost concurrent state/preference")
	}
}

func TestDiscoveredContactChecksFreshCollisions(t *testing.T) {
	cfg := testConfig(t)
	a, _ := NewIdentity("")
	b, _ := NewIdentity("")
	stale, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContactAlias("alice", a.Address); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.AddDiscoveredContact("alice", b.Address); err == nil {
		t.Fatal("stale discovery repointed saved identity")
	}
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Contacts["alice"] != a.Address {
		t.Fatal("collision mutated contact")
	}
	if err := cfg.AddContactAlias("private-bob", b.Address); err != nil {
		t.Fatal(err)
	}
	name, err := stale.AddDiscoveredContact("bob", b.Address)
	if err != nil || name != "private-bob" {
		t.Fatal("concurrent alias not preserved", name, err)
	}
	fresh, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Contacts) != 2 || fresh.ContactNameForAddress(b.Address) != "private-bob" {
		t.Fatal("discovery added duplicate alias")
	}
}
