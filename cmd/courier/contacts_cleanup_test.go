package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
)

func TestContactCleanupRetryAfterReopen(t *testing.T) {
	for _, removal := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement", true: "removal"}[removal], func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			cfg, err := client.NewIdentity("")
			if err != nil {
				t.Fatal(err)
			}
			old, err := client.NewIdentity("")
			if err != nil {
				t.Fatal(err)
			}
			next, err := client.NewIdentity("")
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.AddContact("peer", old.Address); err != nil {
				t.Fatal(err)
			}
			if err := client.New(cfg).FSRequire(old.Address, true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, ".courier", "fs.json")
			good, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("malformed private archive"), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"add", "peer", next.Address}
			if removal {
				args = []string{"remove", "peer"}
			}
			err = cmdContacts(args)
			command := "courier contacts retry-fs-cleanup " + old.Address
			if !removal {
				command = "cannot inspect replacement FS policy"
			}
			if err == nil || !strings.Contains(err.Error(), command) {
				t.Fatalf("missing durable retry input: %v", err)
			}
			reopened, err := client.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			want := old.Address
			if removal {
				want = ""
			}
			if reopened.Contacts["peer"] != want {
				t.Fatal("contact change was not persisted")
			}
			if err := os.WriteFile(path, good, 0600); err != nil {
				t.Fatal(err)
			}
			if !removal {
				if err := cmdContacts(args); err != nil {
					t.Fatal(err)
				}
				reopened, err = client.LoadConfig()
				if err != nil {
					t.Fatal(err)
				}
			}
			// A newly saved alias must protect the old policy even from this stale client.
			stale := client.New(reopened)
			if err := reopened.AddContact("restored", old.Address); err != nil {
				t.Fatal(err)
			}
			cleaned, err := stale.FSCleanupOrphan(old.Address)
			if err != nil || cleaned {
				t.Fatal("stale retry bypassed saved alias", cleaned, err)
			}
			if err := cmdContacts([]string{"retry-fs-cleanup", old.Address}); err == nil {
				t.Fatal("CLI erased referenced identity")
			}
			if err := cmdContacts([]string{"retry-fs-cleanup", "restored"}); err == nil {
				t.Fatal("retry accepted contact name instead of raw address")
			}
			// Model a repaired archive after the saved alias was removed while cleanup
			// was unavailable, then execute the original error's command twice.
			if err := os.WriteFile(path, []byte("malformed private archive"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := reopened.RemoveContact("restored"); err == nil {
				t.Fatal("cleanup failure hidden")
			}
			if err := os.WriteFile(path, good, 0600); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := cmdContacts([]string{"retry-fs-cleanup", old.Address}); err != nil {
					t.Fatal(err)
				}
			}
			reopened, err = client.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			required, err := client.New(reopened).FSRequired(old.Address)
			if err != nil || required {
				t.Fatal("retry retained orphaned policy", required, err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := cmdContacts([]string{"retry-fs-cleanup", old.Address}); err != nil {
				t.Fatalf("retry failed with absent FS file: %v", err)
			}
		})
	}
}
