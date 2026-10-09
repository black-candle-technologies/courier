package main

import (
	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContactHandleRequiresConfirmationAndPreservesAlias(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()
	t.Setenv("HOME", t.TempDir())
	peer, err := client.NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Save(); err != nil {
		t.Fatal(err)
	}
	if err := client.New(peer).PublishKey(); err != nil {
		t.Fatal(err)
	}
	if err := client.New(peer).DirectoryRegister("bob", "public", nil, "open"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	cfg, err := client.NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "send-output")
	if err != nil {
		t.Fatal(err)
	}
	oldOut := os.Stdout
	os.Stdout = out
	sendErr := cmdSend([]string{"@bob", "hello", "--force"})
	os.Stdout = oldOut
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	if _, err := out.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(out)
	out.Close()
	if err != nil || !strings.Contains(string(output), "sent to @bob ("+peer.Address+")") {
		t.Fatalf("lost verified handle: %s %v", output, err)
	}
	if err := cmdContacts([]string{"add", "@bob"}); err == nil {
		t.Fatal("unconfirmed handle became trusted contact")
	}
	cfg, err = client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Contacts) != 0 {
		t.Fatal("refused add mutated contacts")
	}
	if err := cfg.AddContact("bobby", peer.Address); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"@bob", peer.Address} {
		if err := cmdContacts([]string{"add", target}); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err = client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got := client.New(cfg).CachedPeerHandle(peer.Address); got != "bob" {
		t.Fatalf("verified add did not cache profile: %q", got)
	}
	if len(cfg.Contacts) != 1 || cfg.Contacts["bobby"] != peer.Address {
		t.Fatal("private alias replaced or duplicated", cfg.Contacts)
	}
	if err := cfg.RemoveContact("bobby"); err != nil {
		t.Fatal(err)
	}
	if err := cmdContacts([]string{"add", "@bob", "--force"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = client.LoadConfig()
	if err != nil || cfg.Contacts["bob"] != peer.Address {
		t.Fatal("confirmed add failed", err)
	}
}
