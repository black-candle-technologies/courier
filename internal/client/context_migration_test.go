package client

import (
	"encoding/json"
	"errors"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func migrationTarget(t *testing.T, source Context) Context {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(source.root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	h := Hosts{Enabled: true, Bindings: map[string]RelayBinding{"test-relay": {ID: "test-relay", Endpoint: cfg.RelayURL, Pin: cfg.RelayFingerprint}}, Identities: map[string]NamedIdentity{"test": {cfg.Address, "test-relay"}}, Hosts: map[string]Host{"test": {"test-relay", "test"}}}
	target, err := h.Resolve(source.root, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestMigrationCrashRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("migration remains gated on Windows")
	}
	for _, point := range append([]string{"journal", "staged", "verified", "binding", "committed"}, migrationCopyPoints()...) {
		t.Run(point, func(t *testing.T) {
			source := Context{root: t.TempDir()}
			cfg, err := NewIdentity("https://fixture.invalid")
			if err != nil {
				t.Fatal(err)
			}
			cfg.RelayFingerprint = strings.Repeat("a", 64)
			cfg.localContext = &source
			if err = cfg.Save(); err != nil {
				t.Fatal(err)
			}
			for _, name := range contextFiles {
				if name != "config.json" {
					if err = os.WriteFile(filepath.Join(source.root, name), []byte("fixture:"+name), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			original := map[string][]byte{}
			for _, name := range contextFiles {
				original[name], err = os.ReadFile(filepath.Join(source.root, name))
				if err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestMigrationCrashChild$")
			cmd.Env = append(os.Environ(), "COURIER_CONTEXT_FIXTURE="+source.root, "COURIER_CONTEXT_CRASH="+point)
			output, err := cmd.CombinedOutput()
			if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 77 {
				t.Fatalf("child did not crash at %s: %v %s", point, err, output)
			}
			target := migrationTarget(t, source)
			active, err := source.ActiveContext()
			if err != nil {
				t.Fatal(err)
			}
			if point == "committed" {
				if active != target {
					t.Fatal("committed context not selected")
				}
			} else if active != source {
				t.Fatal("partial context selected")
			}
			if point != "committed" {
				if _, _, e := target.IdentityStore().Load(); !errors.Is(e, ErrMigrationIncomplete) {
					t.Fatalf("partial named target accessible: %v", e)
				}
			}
			if err = source.MigrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true}); err != nil {
				t.Fatal(err)
			}
			if err = source.MigrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true}); err != nil {
				t.Fatal("idempotent recovery", err)
			}
			for _, name := range contextFiles {
				for _, root := range []string{source.root, target.root} {
					got, err := os.ReadFile(filepath.Join(root, name))
					if err != nil || string(got) != string(original[name]) {
						t.Fatalf("file changed %s: %v", name, err)
					}
				}
			}
			if err = cfg.Save(); !errors.Is(err, ErrLegacyMigrated) {
				t.Fatalf("stale writer accepted: %v", err)
			}
		})
	}
}
func migrationCopyPoints() []string {
	var out []string
	for _, name := range contextFiles {
		out = append(out, "copy:"+name)
	}
	return out
}
func TestMigrationCrashChild(t *testing.T) {
	root := os.Getenv("COURIER_CONTEXT_FIXTURE")
	if root == "" {
		t.Skip("child only")
	}
	source := Context{root: root}
	target := migrationTarget(t, source)
	err := source.migrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true}, func(point string) error {
		if point == os.Getenv("COURIER_CONTEXT_CRASH") {
			os.Exit(77)
		}
		return nil
	})
	t.Fatalf("child failed to reach crash: %v", err)
}

func TestMigrationRefusesUnsafeInputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("migration gated")
	}
	source := Context{root: t.TempDir()}
	cfg, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RelayFingerprint = strings.Repeat("a", 64)
	cfg.localContext = &source
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	target := migrationTarget(t, source)
	if err = source.MigrateLegacy(target, MigrationOptions{}); err == nil {
		t.Fatal("missing quiescence accepted")
	}
	release, err := acquireWakeLock(source.DefaultWakePIDFile())
	if err != nil {
		t.Fatal(err)
	}
	err = source.MigrateLegacy(target, MigrationOptions{true})
	release()
	if err == nil {
		t.Fatal("live daemon accepted")
	}
	boom := errors.New("stop")
	if err = source.migrateLegacy(target, MigrationOptions{true}, func(point string) error {
		if point == "journal" {
			return boom
		}
		return nil
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(target.root), 0700); err != nil {
		t.Fatal(err)
	}
	foreign := t.TempDir()
	if err = os.Symlink(foreign, target.root+".staging"); err != nil {
		t.Fatal(err)
	}
	if err = source.MigrateLegacy(target, MigrationOptions{true}); err == nil {
		t.Fatal("symlink staging accepted")
	}
	entries, err := os.ReadDir(foreign)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside staging", err)
	}
}

func TestMigrationUsesLegacyRelayDefaults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("migration gated")
	}
	for _, tc := range []struct {
		name, relay, binding       string
		omit, unsupported, wantErr bool
	}{
		{name: "omitted", binding: DefaultRelay, omit: true},
		{name: "empty", binding: DefaultRelay},
		{name: "explicit", relay: "https://explicit.invalid", binding: "https://explicit.invalid"},
		{name: "explicit-not-defaulted", relay: "https://explicit.invalid", binding: DefaultRelay, wantErr: true},
		{name: "malformed-not-defaulted", relay: ":bad", binding: DefaultRelay, wantErr: true},
		{name: "unsupported-scheme", relay: "http://fixture.invalid", binding: DefaultRelay, wantErr: true},
		{name: "unsupported-version", binding: DefaultRelay, unsupported: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := Context{root: t.TempDir()}
			cfg, err := NewIdentity(DefaultRelay)
			if err != nil {
				t.Fatal(err)
			}
			cfg.RelayFingerprint = strings.Repeat("a", 64)
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err = json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if tc.omit {
				delete(doc, "relay")
			} else {
				doc["relay"] = tc.relay
			}
			if tc.unsupported {
				doc["version"] = 999
			}
			raw, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(source.root, "config.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			h := Hosts{Enabled: true, Bindings: map[string]RelayBinding{"r": {ID: "r", Endpoint: tc.binding, Pin: cfg.RelayFingerprint}}, Identities: map[string]NamedIdentity{"i": {Principal: cfg.Address, BindingID: "r"}}, Hosts: map[string]Host{"h": {BindingID: "r", Identity: "i"}}}
			target, err := h.Resolve(source.root, "h", "")
			if err != nil {
				t.Fatal(err)
			}
			if !tc.wantErr {
				loaded, err := source.loadConfigRaw()
				if err != nil || loaded.RelayURL != tc.binding {
					t.Fatalf("normal load control: %v %+v", err, loaded)
				}
			}
			err = source.MigrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true})
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid config/binding migrated")
				}
				for _, name := range []string{"context-migration.json", "active-context.json"} {
					if _, err := os.Stat(filepath.Join(source.root, name)); !os.IsNotExist(err) {
						t.Fatalf("invalid input created %s: %v", name, err)
					}
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := target.LoadConfig()
				if err != nil || loaded.RelayURL != tc.binding {
					t.Fatalf("migrated config: %v %+v", err, loaded)
				}
				copied, err := os.ReadFile(filepath.Join(target.root, "config.json"))
				if err != nil || string(copied) != string(raw) {
					t.Fatal("migration changed source bytes", err)
				}
			}
			retained, err := os.ReadFile(path)
			if err != nil || string(retained) != string(raw) {
				t.Fatal("legacy source changed", err)
			}
		})
	}
}

func TestMigrationPinAndOriginEquivalence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("migration gated")
	}
	canonical := strings.Repeat("abcdef01", 8)
	for _, tc := range []struct {
		name, pin, relay string
		wantErr          bool
	}{
		{"lowercase", canonical, "https://relay.invalid", false},
		{"uppercase", strings.ToUpper(canonical), "https://relay.invalid", false},
		{"mixed-case", strings.Repeat("aBcDeF01", 8), "https://relay.invalid", false},
		{"origin-equivalent", strings.ToUpper(canonical), "https://RELAY.invalid:443/", false},
		{"invalid-encoding", strings.Repeat("g", 64), "https://relay.invalid", true},
		{"short", canonical[:62], "https://relay.invalid", true},
		{"long", canonical + "00", "https://relay.invalid", true},
		{"empty", "", "https://relay.invalid", true},
		{"different", strings.Repeat("b", 64), "https://relay.invalid", true},
		{"different-origin", canonical, "https://other.invalid", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := Context{root: t.TempDir()}
			cfg, err := NewIdentity(tc.relay)
			if err != nil {
				t.Fatal(err)
			}
			cfg.RelayFingerprint = tc.pin
			cfg.localContext = &source
			if err = cfg.Save(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(source.root, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := source.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			// Positive controls match the pre-migration transport's hex semantics.
			if !tc.wantErr {
				if _, err := New(loaded).httpClient(); err != nil {
					t.Fatalf("legacy transport: %v", err)
				}
			}
			h := Hosts{Enabled: true, Bindings: map[string]RelayBinding{"r": {ID: "r", Endpoint: "https://relay.invalid", Pin: canonical}}, Identities: map[string]NamedIdentity{"i": {Principal: cfg.Address, BindingID: "r"}}, Hosts: map[string]Host{"h": {BindingID: "r", Identity: "i"}}}
			target, err := h.Resolve(source.root, "h", "")
			if err != nil {
				t.Fatal(err)
			}
			err = source.MigrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true})
			if tc.wantErr {
				if !errors.Is(err, ErrContextMismatch) {
					t.Fatalf("invalid pin/origin accepted: %v", err)
				}
				if _, err := os.Stat(filepath.Join(source.root, "context-migration.json")); !os.IsNotExist(err) {
					t.Fatal("invalid binding created journal", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				active, err := target.LoadConfig()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := New(active).httpClient(); err != nil {
					t.Fatal(err)
				}
				if active.RelayFingerprint != tc.pin || active.RelayURL != tc.relay {
					t.Fatal("stored representation changed")
				}
				copied, err := os.ReadFile(filepath.Join(target.root, "config.json"))
				if err != nil || string(copied) != string(raw) {
					t.Fatal("migration changed config bytes", err)
				}
				syncPayload, err := active.backupPayload(crypto.BackupKindSync, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := active.MergeSyncKeys(syncPayload); err != nil {
					t.Fatalf("equivalent sync pin rejected: %v", err)
				}
				syncPayload.RelayFingerprint = strings.Repeat("b", 64)
				if _, err := active.MergeSyncKeys(syncPayload); !errors.Is(err, ErrContextMismatch) {
					t.Fatalf("different sync pin accepted: %v", err)
				}

			}
		})
	}
}

func TestMigrationPreservesLazyLegacyLoadSemantics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("migration gated")
	}
	source := Context{root: t.TempDir()}
	cfg, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	cfg.RelayFingerprint = strings.Repeat("AB", 32)
	cfg.EncKeys = nil
	cfg.SeenEnvelopeHashes = []string{"fixture-envelope"}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source.root, "config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	control := Context{root: t.TempDir()}
	if err = os.WriteFile(filepath.Join(control.root, "config.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	want, err := control.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	target := migrationTarget(t, source)
	if err = source.MigrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true}); err != nil {
		t.Fatal(err)
	}
	got, err := target.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.EncKeys) != 1 || got.EncKeys[0].Pub != want.EncKeys[0].Pub || got.EncKeys[0].Priv != want.EncKeys[0].Priv || got.EncKeys[0].Epoch != want.EncKeys[0].Epoch {
		t.Fatal("lazy encryption-key migration differs")
	}
	if len(got.SeenEnvelopeHashes) != 0 || len(got.SeenInboxHashes) != 1 || got.SeenInboxHashes[0] != "fixture-envelope" || len(got.SeenPushHashes) != 1 || got.SeenPushHashes[0] != "fixture-envelope" {
		t.Fatal("lazy replay migration differs")
	}
	retained, err := os.ReadFile(filepath.Join(source.root, "config.json"))
	if err != nil || string(retained) != string(raw) {
		t.Fatal("legacy source changed", err)
	}
}
