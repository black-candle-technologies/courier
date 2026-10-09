package client

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestContactReplacementErasesOnlyOrphanedFS(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "final-alias", true: "shared-alias"}[shared], func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			cfg, err := NewIdentity("")
			if err != nil {
				t.Fatal(err)
			}
			old, err := NewIdentity("")
			if err != nil {
				t.Fatal(err)
			}
			next, err := NewIdentity("")
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.AddContact("peer", old.Address); err != nil {
				t.Fatal(err)
			}
			if shared {
				if err := cfg.AddContact("alias", old.Address); err != nil {
					t.Fatal(err)
				}
			}
			if err := updateFS(func(ff *fsFile) error {
				ff.Sessions[old.Address] = &fsSession{RootKey: "old-private-ratchet-material"}
				ff.RequireFS[old.Address] = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := cfg.AddContact("peer", next.Address); err != nil {
				t.Fatal(err)
			}
			saved, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if saved.Contacts["peer"] != next.Address {
				t.Fatal("replacement not persisted")
			}
			ff, err := loadFS()
			if err != nil {
				t.Fatal(err)
			}
			if (ff.session(old.Address) != nil) != shared || ff.RequireFS[old.Address] != shared {
				t.Fatal("incorrect old-identity session or policy retention")
			}
		})
	}
}

func TestContactReplacementSaveFailurePreservesFS(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix permissions as non-root")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	old, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContact("peer", old.Address); err != nil {
		t.Fatal(err)
	}
	if err := updateFS(func(ff *fsFile) error {
		ff.Sessions[old.Address] = &fsSession{RootKey: "old-private-ratchet-material"}
		ff.RequireFS[old.Address] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".courier")
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if err := cfg.AddContact("peer", next.Address); err == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	if cfg.Contacts["peer"] != old.Address {
		t.Fatal("failed replacement changed in-memory mapping")
	}
	saved, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Contacts["peer"] != old.Address {
		t.Fatal("failed replacement changed persisted mapping")
	}
	ff, err := loadFS()
	if err != nil {
		t.Fatal(err)
	}
	if ff.session(old.Address) == nil || !ff.RequireFS[old.Address] {
		t.Fatal("failed persistence erased FS state")
	}
}

func TestContactReplacementRejectsUnreadablePolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	old, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContact("peer", old.Address); err != nil {
		t.Fatal(err)
	}
	p, err := fsFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("malformed private archive"), 0600); err != nil {
		t.Fatal(err)
	}
	err = cfg.AddContact("peer", next.Address)
	if err == nil || !strings.Contains(err.Error(), "cannot inspect replacement FS policy") {
		t.Fatalf("missing policy diagnosis: %v", err)
	}
	saved, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if saved.Contacts["peer"] != old.Address {
		t.Fatal("unreadable policy allowed replacement")
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "malformed private archive" {
		t.Fatal("failed cleanup modified archive", err)
	}
}
