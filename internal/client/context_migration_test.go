package client

import (
	"encoding/json"
	"errors"
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
	for _, point := range append([]string{"journal", "staged", "verified", "committed"}, migrationCopyPoints()...) {
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
