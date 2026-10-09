package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

func TestDirectoryReverseRejectsSignedNoncanonicalHandle(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	for _, handle := range []string{"Alice", " alice ", "a!ice"} {
		t.Run(handle, func(t *testing.T) {
			p := DirectoryProfile{Handle: handle, Address: addrOf(id), Epoch: 1, Visibility: "public", ContactPolicy: "open"}
			p.Sig = b64enc(id.Sign(envelope.DirectoryRegister(handle, id.EdPub[:], 1, "public", "open", nil)))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"results": []DirectoryProfile{p}})
			}))
			defer srv.Close()
			cfg := testConfig(t)
			cfg.RelayURL = srv.URL
			if _, err := New(cfg).DirectoryReverse(p.Address); err == nil {
				t.Fatal("accepted signed noncanonical handle")
			}
		})
	}
}

func TestLookupPeerHandleReportsCachePublicationFailure(t *testing.T) {
	cfg := testConfig(t)
	id, _ := crypto.GenerateIdentity()
	profile := DirectoryProfile{Handle: "alice", Address: addrOf(id), Epoch: 1, Visibility: "public", ContactPolicy: "open"}
	profile.Sig = b64enc(id.Sign(envelope.DirectoryRegister(profile.Handle, id.EdPub[:], 1, "public", "open", nil)))
	path, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	backup := path + ".backup"
	var injected error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injected = os.Rename(path, backup)
		if injected == nil {
			injected = os.Mkdir(path, 0700)
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []DirectoryProfile{profile}})
	}))
	defer srv.Close()
	cfg.RelayURL = srv.URL
	handle, err := New(cfg).LookupPeerHandle(profile.Address)
	if injected != nil {
		t.Fatal(injected)
	}
	if err == nil || handle != "" {
		t.Fatalf("cache failure reported success: %q %v", handle, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.HandleCache[profile.Address]; ok {
		t.Fatal("failed cache publication recorded success")
	}
}
