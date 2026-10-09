package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestLegacyEnabledPrivatePeerMigration(t *testing.T) {
	h := newFSHarness(t)
	h.asAlice(func() {
		bob := h.bobCfg.Address
		off, _ := NewIdentity("")
		unknown, _ := NewIdentity("")
		path, err := fsFilePath()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{"sessions": map[string]any{}, "peer_modes": map[string]string{bob: "on", off.Address: "off", unknown.Address: "future", "not-an-address": "on"}, "require_fs": map[string]bool{bob: true, off.Address: true}})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			f, err := loadFS()
			if err != nil {
				t.Fatal(err)
			}
			if len(f.LegacyEnabledPeers) != 1 || !f.LegacyEnabledPeers[bob] {
				t.Fatalf("wrong migrated authorization: %v", f.LegacyEnabledPeers)
			}
			if len(f.FSPins) != 0 {
				t.Fatal("operator assertion became cryptographic capability proof")
			}
			if !f.RequireFS[bob] || !f.RequireFS[off.Address] {
				t.Fatal("migration weakened required policy")
			}
			if err = updateFS(func(*fsFile) error { return nil }); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(saved, []byte(`"peer_modes"`)) {
				t.Fatal("old representation persisted")
			}
		}
		// No directory profile or session exists. Explicit migrated authorization
		// alone must initiate; required policy still refuses application fallback.
		if err := updateFS(func(f *fsFile) error { delete(f.RequireFS, bob); return nil }); err != nil {
			t.Fatal(err)
		}
		if !h.alice.fsShouldInit(bob) {
			t.Fatal("private peer lost legacy bootstrap authorization")
		}
		if err := h.alice.FSRequire(bob, true); err != nil {
			t.Fatal(err)
		}
		if _, err := h.alice.fsPrepareSend(bob); !errors.Is(err, errFSRequired) {
			t.Fatalf("required policy weakened: %v", err)
		}
		f, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if f.Sessions[bob] == nil {
			t.Fatal("private peer did not bootstrap")
		}
		if err = updateFS(func(f *fsFile) error { forgetFSAddress(f, bob); return nil }); err != nil {
			t.Fatal(err)
		}
		f, err = loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if f.LegacyEnabledPeers[bob] {
			t.Fatal("forget retained explicit authorization")
		}
	})
}
func TestMalformedLegacyModeDoesNotRewrite(t *testing.T) {
	_ = testConfig(t)
	path, err := fsFilePath()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"sessions":{},"peer_modes":{"bad":42},"require_fs":{"retained":true}}`)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = updateFS(func(*fsFile) error { return nil }); err == nil {
		t.Fatal("malformed legacy mode accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, after) {
		t.Fatal("failed migration rewrote state")
	}
}
