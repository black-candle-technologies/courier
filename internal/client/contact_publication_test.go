package client

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestOrphanCleanupRequiresDurableMapping(t *testing.T) {
	for _, mutation := range []string{"remove", "replace"} {
		for _, phase := range []string{"rename", "directory-sync"} {
			t.Run(mutation+"/"+phase, func(t *testing.T) {
				c := testConfig(t)
				a, _ := NewIdentity("")
				b, _ := NewIdentity("")
				if err := c.AddContact("peer", a.Address); err != nil {
					t.Fatal(err)
				}
				if err := updateFS(func(f *fsFile) error {
					f.LastInitAt[a.Address] = time.Now().Unix()
					f.RequireFS[a.Address] = true
					f.Sessions[a.Address] = &fsSession{RootKey: "retained"}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				// Model a visible mapping from an earlier interrupted publication.
				if err := c.Update(func(f *Config) error {
					if mutation == "remove" {
						delete(f.Contacts, "peer")
					} else {
						f.Contacts["peer"] = b.Address
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				failure := errors.New("injected " + phase)
				save := func(f *Config) error {
					return f.saveWithPublication(func(from, to string) error {
						if phase == "rename" {
							return failure
						}
						return os.Rename(from, to)
					}, func(string) error { return failure })
				}
				for retry := 0; retry < 2; retry++ {
					cleaned, err := New(c).fsCleanupOrphanWithSave(a.Address, save)
					if cleaned || !errors.Is(err, failure) {
						t.Fatalf("cleanup crossed failed publication: %v %v", cleaned, err)
					}
					f, err := loadFSLocked()
					if err != nil {
						t.Fatal(err)
					}
					if !f.RequireFS[a.Address] || f.Sessions[a.Address] == nil || f.LastInitAt[a.Address] == 0 {
						t.Fatal("failed publication erased FS protection")
					}
				}
				cleaned, err := New(c).FSCleanupOrphan(a.Address)
				if err != nil || !cleaned {
					t.Fatalf("durable retry: %v %v", cleaned, err)
				}
			})
		}
	}
}
