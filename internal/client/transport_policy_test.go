package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTransportPolicyAllConstructorsRejectBeforeIO(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	for _, mode := range []string{"cloud", "unknown"} {
		for _, dashboard := range []bool{false, true} {
			cfg, _ := NewIdentity(srv.URL)
			cfg.DashboardURL, cfg.DashboardToken = srv.URL, "synthetic-token"
			if dashboard {
				cfg.DashboardTransport = mode
			} else {
				cfg.RelayTransport = mode
			}
			c := New(cfg)
			if _, err := c.httpClient(); err == nil {
				t.Fatal("relay accepted unsupported policy")
			}
			if _, err := c.dashboardHTTPClient(); err == nil {
				t.Fatal("dashboard accepted unsupported policy")
			}
			if _, err := c.longPollHTTPClient(); err == nil {
				t.Fatal("wake accepted unsupported policy")
			}
			cfg.DashboardToken = ""
			if _, err := c.DashboardSetup("synthetic", ""); err == nil {
				t.Fatal("bootstrap accepted unsupported policy")
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unsupported mode caused I/O")
	}
}

func TestTransportDirectPinAndRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" || r.URL.Path == "/v1/health" {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	for _, mode := range []string{"", "direct-tls"} {
		cfg, _ := NewIdentity(srv.URL)
		cfg.RelayTransport, cfg.RelayFingerprint = mode, hex.EncodeToString(sum[:])
		hc, err := New(cfg).httpClient()
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hc.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if _, err := hc.Get(srv.URL + "/redirect"); err == nil {
			t.Fatal("followed redirect")
		}
		cfg.RelayFingerprint = strings.Repeat("00", 32)
		hc, err = New(cfg).httpClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hc.Get(srv.URL); err == nil {
			t.Fatal("accepted wrong pin")
		}
	}
	if _, err := FetchRelayFingerprint(srv.URL); err == nil {
		t.Fatal("bootstrap followed redirect")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect leaked traffic")
	}
}

func TestTransportLegacyNoRewriteAndLockedRefresh(t *testing.T) {
	ctx := Context{root: t.TempDir()}
	cfg, _ := NewIdentity("http://localhost:1234")
	cfg.localContext = &ctx
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ctx.root, "config.json")
	before, _ := os.ReadFile(path)
	loaded, err := ctx.LoadTransportConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(loaded).httpClient(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || loaded.RelayTransport != "" {
		t.Fatal("rewrote legacy config")
	}
	if err := cfg.Update(func(f *Config) error { f.RelayTransport = "direct-tls"; return nil }); err == nil {
		t.Fatal("accepted direct TLS on HTTP")
	}
	after, _ = os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("invalid policy changed config")
	}
	if err := cfg.Update(func(f *Config) error {
		f.RelayURL = "https://example.invalid"
		f.RelayTransport = "direct-tls"
		f.Cursor = 42
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Update(func(f *Config) error { f.TransportReviewed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if loaded.RelayTransport != "direct-tls" || loaded.Cursor != 42 {
		t.Fatal("lost concurrent fields or refresh")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("wrong permissions")
	}
	raw := strings.Replace(string(after), `"version": 2`, `"version": 2, "relay_transport": "cloud"`, 1)
	if _, err := decodeConfig([]byte(raw)); err == nil {
		t.Fatal("decode accepted cloud")
	}
}

func TestDashboardBootstrapRequiresIndependentTrust(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	cfg, _ := NewIdentity("https://different.example.invalid")
	if _, err := New(cfg).DashboardSetupAt("synthetic", "", srv.URL); err == nil {
		t.Fatal("trusted candidate without expected pin")
	}
	if calls.Load() != 0 {
		t.Fatal("discovery before trust input")
	}
}

func TestTransportBackupPreservesPolicy(t *testing.T) {
	cfg, _ := NewIdentity("https://example.invalid")
	cfg.localContext = &Context{root: t.TempDir()}
	cfg.RelayTransport = "direct-tls"
	raw, err := cfg.CreateBackup([]byte("synthetic-test-passphrase"), "backup", "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{root: t.TempDir()}
	restored, err := ctx.RestoreBackup([]byte("synthetic-test-passphrase"), raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if restored.RelayTransport != "direct-tls" {
		t.Fatal("lost backup policy")
	}
}

func TestPinnedTransportRetainsProxyPolicy(t *testing.T) {
	tr, err := pinnedTransport(strings.Repeat("00", 32))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Proxy == nil {
		t.Fatal("removed proxy support")
	}
	// A proxy presence never disables certificate authentication.
	if err := tr.TLSClientConfig.VerifyPeerCertificate([][]byte{[]byte("synthetic interception cert")}, nil); err == nil {
		t.Fatal("accepted interception")
	}
}

func TestDashboardSetupPreservesConcurrentTrust(t *testing.T) {
	cfg, scope := reviewConfig(t, false)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/dashboard/register" {
			w.WriteHeader(http.StatusOK)
			return
		}
		fresh, err := scope.LoadTransportConfig()
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		err = fresh.Update(func(f *Config) error {
			f.DashboardURL = "https://replacement.invalid"
			f.DashboardFingerprint = strings.Repeat("ab", 32)
			f.DashboardToken = "replacement-synthetic-token"
			return nil
		})
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"username":"fixture","api_token":"stale-synthetic-token"}`))
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	if _, err := New(cfg).DashboardSetupAt("fixture", hex.EncodeToString(sum[:]), srv.URL); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("want stale trust rejection: %v", err)
	}
	fresh, err := scope.LoadTransportConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.DashboardURL != "https://replacement.invalid" || fresh.DashboardFingerprint != strings.Repeat("ab", 32) || fresh.DashboardToken != "replacement-synthetic-token" {
		t.Fatal("overwrote concurrently configured dashboard")
	}
}

func TestDashboardSetupRejectsBootstrapAndRegistrationRedirects(t *testing.T) {
	for _, redirectPath := range []string{"/v1/health", "/v1/dashboard/register"} {
		t.Run(redirectPath, func(t *testing.T) {
			cfg, _ := reviewConfig(t, false)
			var calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			defer target.Close()
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == redirectPath {
					http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			sum := sha256.Sum256(srv.Certificate().Raw)
			if _, err := New(cfg).DashboardSetupAt("fixture", hex.EncodeToString(sum[:]), srv.URL); err == nil {
				t.Fatal("accepted redirect")
			}
			if calls.Load() != 0 {
				t.Fatal("redirect transmitted dashboard setup")
			}
			persisted, err := cfg.Context().LoadTransportConfig()
			if err != nil {
				t.Fatal(err)
			}
			if persisted.DashboardToken != "" || persisted.DashboardFingerprint != "" {
				t.Fatal("failed setup persisted trust")
			}
		})
	}
}

func TestDashboardSetupRejectsStaleBindingBeforeIO(t *testing.T) {
	for _, field := range []string{"url", "fingerprint"} {
		for _, override := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/override=%v", field, override), func(t *testing.T) {
				cfg, scope := reviewConfig(t, false)
				var calls atomic.Int32
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"username":"fixture","api_token":"synthetic"}`))
				}))
				defer srv.Close()
				if err := cfg.Update(func(f *Config) error { f.DashboardURL = srv.URL; return nil }); err != nil {
					t.Fatal(err)
				}
				newer, err := scope.LoadTransportConfig()
				if err != nil {
					t.Fatal(err)
				}
				if err := newer.Update(func(f *Config) error {
					if field == "url" {
						f.DashboardURL = "https://replacement.invalid"
					} else {
						f.DashboardFingerprint = strings.Repeat("ab", 32)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				path, _ := scope.configPath()
				before, _ := os.ReadFile(path)
				sum := sha256.Sum256(srv.Certificate().Raw)
				pin := hex.EncodeToString(sum[:])
				if override {
					_, err = New(cfg).DashboardSetupAt("fixture", pin, srv.URL)
				} else {
					_, err = New(cfg).DashboardSetup("fixture", pin)
				}
				if !errors.Is(err, ErrContextMismatch) {
					t.Fatalf("want stale binding error: %v", err)
				}
				if calls.Load() != 0 {
					t.Fatal("stale setup performed network I/O")
				}
				after, _ := os.ReadFile(path)
				if !bytes.Equal(before, after) {
					t.Fatal("stale setup changed persisted trust")
				}
			})
		}
	}
}
