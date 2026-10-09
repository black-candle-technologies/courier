package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
)

type noRead struct{ t *testing.T }

func (r noRead) Read([]byte) (int, error) { r.t.Fatal("read noninteractive stdin"); return 0, io.EOF }

func TestTransportSetupSelection(t *testing.T) {
	for _, input := range []string{"", "yes\n", "cloud\n", "cancel\n"} {
		if _, err := setupTransport("", "https://example.invalid", true, strings.NewReader(input), io.Discard); err == nil {
			t.Fatal("accepted", input)
		}
	}
	if _, err := setupTransport("", "https://example.invalid", false, noRead{t}, io.Discard); err == nil {
		t.Fatal("missing explicit policy")
	}
	if _, err := setupTransport("direct-tls", "https://example.invalid", false, noRead{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := setupTransport("direct-tls", "http://localhost", false, noRead{t}, io.Discard); err == nil {
		t.Fatal("new plaintext setup")
	}
}

func TestTransportUpgradePreservesState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg, err := client.NewIdentity("https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	root, _ := cfg.Context().StateRoot()
	path := filepath.Join(root, "config.json")
	before, _ := os.ReadFile(path)
	for _, input := range []string{"", "yes\n", "cancel\n"} {
		if err = reviewTransport(cfg, true, strings.NewReader(input), io.Discard); err == nil {
			t.Fatal("accepted cancel/EOF/yes")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("cancel changed config")
		}
	}
	for i := 0; i < 2; i++ {
		if err = reviewTransport(cfg, false, noRead{t}, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("noninteractive changed config")
	}
	if err = reviewTransport(cfg, true, strings.NewReader("keep\n"), io.Discard); err != nil {
		t.Fatal(err)
	}
	if cfg.RelayTransport != "" || cfg.RelayURL != "https://example.invalid" || cfg.RelayFingerprint != "" {
		t.Fatal("changed trust")
	}
	if err = reviewTransport(cfg, true, noRead{t}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestInitUnavailableBeforeIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	scope := command{context: client.LegacyContext()}
	for _, args := range [][]string{{"--transport", "cloud"}, {"--transport", "direct-tls", "--relay", "https://example.invalid"}} {
		if err := scope.cmdInit(args); err == nil {
			t.Fatal("accepted unavailable or missing trust")
		}
		if scope.context.ConfigExists() {
			t.Fatal("created identity")
		}
	}
}

func TestTransportUpgradeConcurrentTrustChange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg, _ := client.NewIdentity("https://example.invalid")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	newer, err := cfg.Context().LoadTransportConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err = newer.Update(func(f *client.Config) error { f.RelayFingerprint = strings.Repeat("ab", 32); f.Cursor = 19; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = reviewTransport(cfg, true, strings.NewReader("keep\n"), io.Discard); err == nil {
		t.Fatal("acknowledged stale trust")
	}
	fresh, err := cfg.Context().LoadTransportConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.TransportReviewed || fresh.Cursor != 19 || fresh.RelayFingerprint != strings.Repeat("ab", 32) {
		t.Fatal("clobbered concurrent trust")
	}
}

func TestTransportBootstrapMismatchDoesNotRepin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/health" {
			t.Error("identity-bearing bootstrap traffic")
		}
	}))
	defer srv.Close()
	cfg, _ := client.NewIdentity(srv.URL)
	cfg.RelayFingerprint = strings.Repeat("ab", 32)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	root, _ := cfg.Context().StateRoot()
	path := filepath.Join(root, "config.json")
	before, _ := os.ReadFile(path)
	scope := command{context: cfg.Context()}
	if err := scope.cmdInit([]string{"--repin", "--fingerprint", strings.Repeat("cd", 32)}); err == nil {
		t.Fatal("accepted interception certificate")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed repin modified identity")
	}
	sum := sha256.Sum256(srv.Certificate().Raw)
	if got, err := verifiedRelayFingerprint(srv.URL, hex.EncodeToString(sum[:])); err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatal(got, err)
	}
}

func TestUpgradeAcknowledgementDoesNotMigrateLegacyIdentity(t *testing.T) {
	for _, seedKind := range []string{"missing", "malformed", "healthy"} {
		t.Run(seedKind, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			ctx := client.LegacyContext()
			root, _ := ctx.StateRoot()
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			fields := map[string]any{"version": 2, "seen_envelope_hashes": []string{"legacy-replay"}, "future_extension": map[string]any{"preserve": true}}
			if seedKind == "malformed" {
				fields["seed"] = "invalid"
			}
			if seedKind == "healthy" {
				fixture, err := client.NewIdentity("")
				if err != nil {
					t.Fatal(err)
				}
				fields["seed"] = fixture.Seed
				fields["address"] = fixture.Address
			}
			raw, _ := json.Marshal(fields)
			path := filepath.Join(root, "config.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := ctx.LoadTransportConfig()
			if err != nil {
				t.Fatal(err)
			}
			if seedKind != "healthy" {
				// Negative control: the generic mutator rejects this damaged identity.
				if err := cfg.Update(func(*client.Config) error { return nil }); err == nil {
					t.Fatal("fixture should fail lazy key migration")
				}
			}
			if err := reviewTransport(cfg, true, strings.NewReader("keep\n"), io.Discard); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(after, &got); err != nil {
				t.Fatal(err)
			}
			if got["transport_reviewed"] != true {
				t.Fatal("missing acknowledgement")
			}
			delete(got, "transport_reviewed")
			var want map[string]any
			_ = json.Unmarshal(raw, &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("acknowledgement changed unrelated fields: got %v want %v", got, want)
			}
			if len(cfg.EncKeys) != 0 || len(cfg.SeenEnvelopeHashes) != 1 || len(cfg.SeenInboxHashes) != 0 {
				t.Fatal("migrated in-memory legacy state")
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatal("changed config permissions")
			}
			if err := reviewTransport(cfg, true, noRead{t}, io.Discard); err != nil {
				t.Fatal(err)
			}
		})
	}
}
