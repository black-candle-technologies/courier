package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
)

func TestCommandContextSelection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := filepath.Join(home, ".courier")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	cfg, err := client.NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	h := client.Hosts{Enabled: true, Bindings: map[string]client.RelayBinding{"r": {ID: "r", Endpoint: cfg.RelayURL, Pin: strings.Repeat("a", 64)}}, Identities: map[string]client.NamedIdentity{"i": {Principal: cfg.Address, BindingID: "r"}}, Hosts: map[string]client.Host{"work": {BindingID: "r", Identity: "i"}}}
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "hosts.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	scope, args, err := selectCommand([]string{"--host", "work", "--identity", "i", "address"})
	if err != nil || len(args) != 1 || args[0] != "address" || scope.context.Principal() != cfg.Address {
		t.Fatal(args, err)
	}
	if err = scope.cmdInit(nil); err == nil {
		t.Fatal("named init could fall back to legacy")
	}
	if err = scope.cmdWakeInstall(nil); err == nil {
		t.Fatal("named service install could overwrite default unit")
	}
	if err = scope.cmdContext([]string{"migrate"}); err == nil {
		t.Fatal("migration without quiescence confirmation")
	}
	for _, args := range [][]string{{"--identity", "i", "address"}, {"--host", "missing", "address"}, {"--host"}, {"--host", "work", "--host", "work"}} {
		if _, _, err := selectCommand(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
	legacy, _, err := selectCommand([]string{"address"})
	if err != nil || legacy.context.Principal() != "" {
		t.Fatal("default changed", err)
	}
}

func TestBadManifestCommandSelection(t *testing.T) {
	for _, manifest := range []string{"malformed", "unsupported", "unreadable"} {
		t.Run(manifest, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			root := filepath.Join(home, ".courier")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "active-context.json")
			if manifest == "unreadable" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				raw := []byte("invalid")
				if manifest == "unsupported" {
					raw = []byte(`{"version":999}`)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}, {"update"}, {"bridge", "token", "revoke"}, {"bridge", "audit"}, {"dashboard", "set-admin"}} {
				if _, _, err := selectCommand(args); err != nil {
					t.Errorf("context-free %v blocked: %v", args, err)
				}
			}
			for _, args := range [][]string{{"address"}, {"inbox"}, {"bridge", "trust"}, {"dashboard", "push"}, {"backup", "restore"}} {
				if _, _, err := selectCommand(args); err == nil {
					t.Errorf("identity command %v did not fail closed", args)
				}
			}
			if _, _, err := selectCommand([]string{"--host", "work", "bridge", "token", "revoke"}); err == nil {
				t.Fatal("identity selector silently scoped context-free admin command")
			}
		})
	}
}

func TestBadManifestBridgeRevocationDispatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := filepath.Join(home, ".courier")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active-context.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	db, cleanup := testBridgeEnv(t)
	defer cleanup()
	if err := cmdBridgeTokenIssue(db, []string{"--name", "fixture", "--allow", testAddr}); err != nil {
		t.Fatal(err)
	}
	scope, args, err := selectCommand([]string{"bridge", "token", "revoke", "--name", "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.cmdBridge(args[1:]); err != nil {
		t.Fatal(err)
	}
	if err := cmdBridgeTokenRevoke(db, []string{"--name", "fixture"}); err == nil {
		t.Fatal("dispatch did not revoke fixture token")
	}
}
