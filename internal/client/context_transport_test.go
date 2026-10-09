package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNamedHTTPConstructorsRejectBindingMutation(t *testing.T) {
	for _, field := range []string{"relay", "pin", "principal", "seed"} {
		t.Run(field, func(t *testing.T) {
			cfg, _ := reviewConfig(t, true)
			cl := New(cfg)
			switch field {
			case "relay":
				cfg.RelayURL = "http://127.0.0.1:1"
			case "pin":
				cfg.RelayFingerprint = strings.Repeat("b", 64)
			case "principal":
				other, _ := NewIdentity("https://fixture.invalid")
				cfg.Address = other.Address
			case "seed":
				other, _ := NewIdentity("https://fixture.invalid")
				cfg.Seed = other.Seed
			}
			if _, err := cl.httpClient(); !errors.Is(err, ErrContextMismatch) {
				t.Fatalf("relay: %v", err)
			}
			if _, err := cl.longPollHTTPClient(); !errors.Is(err, ErrContextMismatch) {
				t.Fatalf("long poll: %v", err)
			}
			if _, err := cl.dashboardHTTPClient(); !errors.Is(err, ErrContextMismatch) {
				t.Fatalf("dashboard: %v", err)
			}
			if _, err := cl.DashboardSetup("fixture", ""); !errors.Is(err, ErrContextMismatch) {
				t.Fatalf("dashboard setup: %v", err)
			}
			// A canceled context guarantees no live subscription even if validation regresses.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, last, _, err := cl.Subscribe(ctx, 42); !errors.Is(err, ErrContextMismatch) || last != 42 {
				t.Fatalf("subscribe: cursor=%d err=%v", last, err)
			}
		})
	}
}

func TestMigratedDefaultWakeLockMatchesCapturedContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory migration disabled on Windows")
	}
	_, source := reviewConfig(t, false)
	target := migrationTarget(t, source)
	if err := source.MigrateLegacy(target, MigrationOptions{ConfirmLegacyWritersStopped: true}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cliPath := cfg.Context().DefaultWakePIDFile()
	apiPath := DefaultWakePIDFile()
	if apiPath != cliPath || apiPath == source.DefaultWakePIDFile() {
		t.Fatalf("API %q differs from captured CLI context %q", apiPath, cliPath)
	}
	release, err := acquireWakeLock(cliPath)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if unlock, err := acquireWakeLock(apiPath); err == nil {
		unlock()
		t.Fatal("API acquired a second dispatcher lock")
	}
}

func TestDefaultWakeLockFailsClosedOnInvalidManifest(t *testing.T) {
	_, scope := reviewConfig(t, false)
	root, err := scope.StateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active-context.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	path := DefaultWakePIDFile()
	if path == "" {
		t.Fatal("resolution failure disabled locking")
	}
	if release, err := acquireWakeLock(path); err == nil {
		release()
		t.Fatal("invalid active manifest allowed a wake lock")
	}
}
