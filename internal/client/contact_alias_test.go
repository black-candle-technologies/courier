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
