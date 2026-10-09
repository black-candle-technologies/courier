package main

import (
	"github.com/black-candle-technologies/courier/internal/client"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestContactRemovalPreservesSharedFSPolicy(t *testing.T) {
	setTestHome(t, t.TempDir())
	cfg, err := client.NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := client.NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first", "second"} {
		if err := cfg.AddContact(name, peer.Address); err != nil {
			t.Fatal(err)
		}
	}
	c := client.New(cfg)
	if err := c.FSRequire(peer.Address, true); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetReceiptsOptIn(peer.Address, true); err != nil {
		t.Fatal(err)
	}
	if err := cmdContacts([]string{"remove", "first"}); err != nil {
		t.Fatal(err)
	}
	required, err := c.FSRequired(peer.Address)
	if err != nil || !required {
		t.Fatal("remaining alias lost policy", required, err)
	}
	saved, err := client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !saved.ReceiptsEnabledFor(peer.Address) {
		t.Fatal("remaining alias lost receipt opt-in")
	}
	if err := cmdContacts([]string{"remove", "missing"}); err == nil {
		t.Fatal("missing removal accepted")
	}
	required, err = c.FSRequired(peer.Address)
	if err != nil || !required {
		t.Fatal("failed removal lost policy", required, err)
	}
	if err := cmdContacts([]string{"remove", "second"}); err != nil {
		t.Fatal(err)
	}
	required, err = c.FSRequired(peer.Address)
	if err != nil || required {
		t.Fatal("final removal retained policy", required, err)
	}
	saved, err = client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if saved.ReceiptsEnabledFor(peer.Address) {
		t.Fatal("final alias removal retained receipt opt-in")
	}

}

func TestContactRemoveRejectsRawNonContactAddress(t *testing.T) {
	setTestHome(t, t.TempDir())
	cfg, err := client.NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := client.NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	c := client.New(cfg)
	if err := c.FSRequire(peer.Address, true); err != nil {
		t.Fatal(err)
	}
	if err := cmdContacts([]string{"remove", peer.Address}); err == nil {
		t.Fatal("raw non-contact address accepted for removal")
	}
	required, err := c.FSRequired(peer.Address)
	if err != nil || !required {
		t.Fatal("non-contact removal erased policy", required, err)
	}
}

func TestContactRemovalSaveFailurePreservesFS(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires Unix permissions as non-root")
	}
	home := t.TempDir()
	setTestHome(t, home)
	cfg, err := client.NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := client.NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContact("peer", peer.Address); err != nil {
		t.Fatal(err)
	}
	c := client.New(cfg)
	if err := c.FSRequire(peer.Address, true); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".courier")
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	if err := cmdContacts([]string{"remove", "peer"}); err == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	required, err := c.FSRequired(peer.Address)
	if err != nil || !required {
		t.Fatal("failed persistence erased policy", required, err)
	}
}

// setTestHome isolates filesystem state on both Unix and Windows.
func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}
