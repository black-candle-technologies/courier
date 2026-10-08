package main

import (
	"github.com/black-candle-technologies/courier/internal/client"
	"testing"
)

func TestContactRemovalPreservesSharedFSPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
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
	if err := cmdContacts([]string{"remove", "first"}); err != nil {
		t.Fatal(err)
	}
	required, err := c.FSRequired(peer.Address)
	if err != nil || !required {
		t.Fatal("remaining alias lost policy", required, err)
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
}
