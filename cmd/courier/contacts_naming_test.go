package main

import (
	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContactHandleRequiresConfirmationAndPreservesAlias(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()
	setTestHome(t, t.TempDir())
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
	setTestHome(t, t.TempDir())
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
	// An explicit alias must shadow the auto-derived name regardless of sort
	// order, without deleting existing aliases or their trust records.
	if err := cfg.AddContact("aaron", peer.Address); err != nil {
		t.Fatal(err)
	}
	other, err := client.NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContact("unrelated", other.Address); err != nil {
		t.Fatal(err)
	}
	record := client.ContactVerification{Address: peer.Address, VerifiedAt: 123, KeyEpoch: 7, SafetyNumber: "retained"}
	cfg.ContactVerifications = map[string]client.ContactVerification{"bob": record, "aaron": record}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := cmdContacts([]string{"add", "zach", peer.Address}); err != nil {
		t.Fatal(err)
	}
	cfg, err = client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got := client.New(cfg).ContactDisplayName(peer.Address); got != "zach" {
		t.Fatalf("explicit alias lost to handle: %s", got)
	}
	if got := existingContactAlias(cfg, peer.Address); got != "zach" {
		t.Fatalf("CLI alias disagrees: %s", got)
	}
	if len(cfg.Contacts) != 4 || cfg.Contacts["bob"] != peer.Address || cfg.Contacts["aaron"] != peer.Address || cfg.Contacts["unrelated"] != other.Address {
		t.Fatal("existing aliases changed", cfg.Contacts)
	}
	if cfg.ContactVerifications["bob"] != record || cfg.ContactVerifications["aaron"] != record {
		t.Fatal("trust metadata changed")
	}
	if err := cmdContacts([]string{"add", "@bob"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got := client.New(cfg).ContactDisplayName(peer.Address); got != "zach" {
		t.Fatalf("handle re-add replaced explicit preference: %s", got)
	}
	if err := cmdContacts([]string{"remove", "zach"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PreferredContactNames[peer.Address] != "" || client.New(cfg).ContactDisplayName(peer.Address) != "aaron" {
		t.Fatal("removed preference did not fall back safely")
	}
}

func TestContactAddressDistinguishesDirectoryFailure(t *testing.T) {
	for _, failed := range []bool{true, false} {
		t.Run(map[bool]string{true: "failure", false: "no-public-handle"}[failed], func(t *testing.T) {
			setTestHome(t, t.TempDir())
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failed {
					http.Error(w, "temporary outage", http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"results":[]}`)
			}))
			defer srv.Close()
			cfg, err := client.NewIdentity(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := client.NewIdentity(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			err = cmdContacts([]string{"add", peer.Address})
			if err == nil {
				t.Fatal("missing handle unexpectedly created a contact")
			}
			if failed {
				if !strings.Contains(err.Error(), "lookup failed; retry") || strings.Contains(err.Error(), "no directory handle known") {
					t.Fatal(err)
				}
			} else if !strings.Contains(err.Error(), "no directory handle known") {
				t.Fatal(err)
			}
			saved, err := client.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if len(saved.Contacts) != 0 {
				t.Fatal("lookup failure or absence created contact")
			}
			_, cached := saved.HandleCache[peer.Address]
			if cached == failed {
				t.Fatal("lookup failure cached as authoritative absence, or verified absence not cached")
			}
		})
	}
}

func TestContactRawAddressRefreshesSavedAliasHandle(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()
	setTestHome(t, t.TempDir())
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
	if err := client.New(peer).DirectoryRegister("public-bob", "public", nil, "open"); err != nil {
		t.Fatal(err)
	}
	setTestHome(t, t.TempDir())
	cfg, err := client.NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContactAlias("private-bob", peer.Address); err != nil {
		t.Fatal(err)
	}
	for _, expired := range []bool{false, true} {
		cfg.HandleCache = map[string]client.HandleCacheEntry{}
		if expired {
			cfg.HandleCache[peer.Address] = client.HandleCacheEntry{Handle: "old-handle", At: time.Now().Unix() - 25*3600}
		}
		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}
		if err := cmdContacts([]string{"add", peer.Address}); err != nil {
			t.Fatal(err)
		}
		cfg, err = client.LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if got := client.New(cfg).CachedPeerHandle(peer.Address); got != "public-bob" {
			t.Fatalf("raw add did not refresh verified handle: %q", got)
		}
		if len(cfg.Contacts) != 1 || cfg.Contacts["private-bob"] != peer.Address || cfg.PreferredContactNames[peer.Address] != "private-bob" {
			t.Fatal("lookup changed private alias", cfg.Contacts)
		}
	}
}
