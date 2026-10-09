package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func reviewConfig(t *testing.T, named bool) (*Config, Context) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RelayFingerprint = strings.Repeat("a", 64)
	scope := LegacyContext()
	if named {
		h := Hosts{Enabled: true, Bindings: map[string]RelayBinding{"r": {ID: "r", Endpoint: cfg.RelayURL, Pin: cfg.RelayFingerprint}}, Identities: map[string]NamedIdentity{"i": {Principal: cfg.Address, BindingID: "r"}}, Hosts: map[string]Host{"h": {BindingID: "r", Identity: "i"}}}
		scope, err = h.Resolve(home, "h", "")
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg.localContext = &scope
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	return cfg, scope
}
func reviewRotateLocal(t *testing.T, scope Context) *Config {
	t.Helper()
	fresh, err := scope.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	err = fresh.Update(func(f *Config) error {
		f.EncKeys = append([]EncKey{{Pub: enc(pub[:]), Priv: enc(priv[:]), Epoch: f.EncKeys[0].Epoch + 1}}, f.EncKeys...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fresh
}
func TestContextFollowRefresh(t *testing.T) {
	for _, named := range []bool{false, true} {
		name := "legacy"
		if named {
			name = "named"
		}
		t.Run(name, func(t *testing.T) {
			cfg, scope := reviewConfig(t, named)
			cl := New(cfg)
			fresh := reviewRotateLocal(t, scope)
			// cmdInbox's successful empty poll refreshes this original pointer.
			if err := cfg.Update(func(f *Config) error { f.Cursor = 10; return nil }); err != nil {
				t.Fatal(err)
			}
			sender, err := crypto.GenerateIdentity()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(pushTestEnvelope(t, sender, fresh, 11, "after rotation"))
			if err != nil {
				t.Fatal(err)
			}
			var msg inboxEnvelope
			if err = json.Unmarshal(raw, &msg); err != nil {
				t.Fatal(err)
			}
			plain, err := cl.openEnvelope(msg)
			if err != nil || string(plain) != "after rotation" {
				t.Fatalf("client failed after poll config refresh: %q %v (caller keys=%d, client keys=%d)", plain, err, len(cfg.EncKeys), len(cl.cfg.EncKeys))
			}
		})
	}
}
func TestContextAddContactPreservesCache(t *testing.T) {
	for _, named := range []bool{false, true} {
		name := "legacy"
		if named {
			name = "named"
		}
		t.Run(name, func(t *testing.T) {
			cfg, scope := reviewConfig(t, named)
			cl := New(cfg)
			peer, err := NewIdentity("https://fixture.invalid")
			if err != nil {
				t.Fatal(err)
			}
			// CacheDirectoryProfile calls this only after signature verification.
			if err = cl.cachePeerHandle(peer.Address, "bob"); err != nil {
				t.Fatal(err)
			}
			if err = cfg.AddContact("bob", peer.Address); err != nil {
				t.Fatal(err)
			}
			disk, err := scope.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if disk.HandleCache[peer.Address].Handle != "bob" {
				t.Fatal("contact save erased freshly verified directory cache")
			}
		})
	}
}
func TestContextStaleContactPreservesRotation(t *testing.T) {
	cfg, scope := reviewConfig(t, false)
	fresh := reviewRotateLocal(t, scope)
	if err := cfg.AddContact("peer", cfg.Address); err != nil {
		t.Fatal(err)
	}
	disk, err := scope.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if disk.EncKeys[0].Pub != fresh.EncKeys[0].Pub {
		t.Fatal("stale contact Save erased independently committed rotation")
	}
}

func TestContextDashboardSetupRefreshesCallerAndPreservesRotation(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(fmt.Sprint("named=", named), func(t *testing.T) {
			cfg, scope := reviewConfig(t, named)
			var rotated *Config
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/dashboard/register" {
					http.NotFound(w, r)
					return
				}
				rotated = reviewRotateLocal(t, scope)
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"username":"fixture-user","api_token":"fixture-token"}`))
			}))
			defer server.Close()
			cfg.DashboardURL = server.URL
			pin := sha256.Sum256(server.Certificate().Raw)
			if _, err := New(cfg).DashboardSetup("fixture-user", hex.EncodeToString(pin[:])); err != nil {
				t.Fatal(err)
			}
			if cfg.DashboardUser != "fixture-user" || cfg.DashboardURL != server.URL || cfg.DashboardToken != "fixture-token" {
				t.Fatal("successful setup did not refresh caller output fields")
			}
			disk, err := scope.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if rotated == nil || disk.EncKeys[0].Pub != rotated.EncKeys[0].Pub {
				t.Fatal("dashboard setup overwrote concurrent rotation")
			}
		})
	}
}

func TestContextStaleMutationsPreserveRotation(t *testing.T) {
	for _, named := range []bool{false, true} {
		for _, action := range []string{"add-contact", "remove-contact", "add-gateway", "remove-gateway"} {
			t.Run(fmt.Sprintf("named=%v/%s", named, action), func(t *testing.T) {
				cfg, scope := reviewConfig(t, named)
				if err := cfg.AddContact("peer", cfg.Address); err != nil {
					t.Fatal(err)
				}
				if err := cfg.AddBridgeGateway(cfg.Address); err != nil {
					t.Fatal(err)
				}
				rotated := reviewRotateLocal(t, scope)
				var err error
				switch action {
				case "add-contact":
					err = cfg.AddContact("second", cfg.Address)
				case "remove-contact":
					err = cfg.RemoveContact("peer")
				case "add-gateway":
					err = cfg.AddBridgeGateway(cfg.Address)
				case "remove-gateway":
					err = cfg.RemoveBridgeGateway(cfg.Address)
				}
				if err != nil {
					t.Fatal(err)
				}
				disk, err := scope.LoadConfig()
				if err != nil {
					t.Fatal(err)
				}
				if disk.EncKeys[0].Pub != rotated.EncKeys[0].Pub {
					t.Fatal("stale mutation erased rotation")
				}
			})
		}
	}
}
