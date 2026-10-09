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
