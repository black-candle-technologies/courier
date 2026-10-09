package client

import (
	"errors"
	"os"
	"testing"
)

func TestPublicationFailures(t *testing.T) {
	for _, store := range []string{"config", "groups"} {
		for _, phase := range []string{"rename", "directory-sync"} {
			t.Run(store+"/"+phase, func(t *testing.T) {
				c := testConfig(t)
				failure := errors.New("injected publication failure")
				synced := false
				rename := func(from, to string) error {
					if phase == "rename" {
						return failure
					}
					return os.Rename(from, to)
				}
				syncDir := func(string) error { synced = true; return failure }
				var err error
				if store == "config" {
					err = c.saveWithPublication(rename, syncDir)
				} else {
					err = saveGroupsWithPublication(map[string]*groupState{}, rename, syncDir)
				}
				if !errors.Is(err, failure) {
					t.Fatalf("publication returned %v", err)
				}
				if synced != (phase == "directory-sync") {
					t.Fatalf("unexpected barrier order: synced=%v", synced)
				}
			})
		}
	}
}

func TestGroupRetryRequiresDurablePublication(t *testing.T) {
	c := testConfig(t)
	if err := saveGroupsLocked(map[string]*groupState{"g": {KeyPending: true}}); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"rename", "directory-sync"} {
		failure := errors.New("injected " + phase)
		err := New(c).retryGroupKeyWithSave("g", func(gs map[string]*groupState) error {
			return saveGroupsWithPublication(gs, func(from, to string) error {
				if phase == "rename" {
					return failure
				}
				return os.Rename(from, to)
			}, func(string) error { return failure })
		})
		if !errors.Is(err, failure) {
			t.Fatalf("distribution crossed failed %s: %v", phase, err)
		}
		gs, err := loadGroups()
		if err != nil {
			t.Fatal(err)
		}
		if !gs["g"].KeyPending {
			t.Fatal("failed publication acknowledged distribution")
		}
	}
}
