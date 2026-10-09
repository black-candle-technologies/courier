package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
)

func TestDirectoryMisdirectionRejectedBySendAndAdd(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p := client.DirectoryProfile{Handle: "mallory", Address: crypto.FormatAddress(id.EdPub[:]), Epoch: 1, Visibility: "public", ContactPolicy: "open"}
	p.Sig = base64.RawURLEncoding.EncodeToString(id.Sign(envelope.DirectoryRegister(p.Handle, id.EdPub[:], 1, "public", "open", nil)))
	deliveries := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/directory/lookup" {
			json.NewEncoder(w).Encode(p)
			return
		}
		deliveries++
		http.Error(w, "unexpected", 500)
	}))
	defer srv.Close()
	setTestHome(t, t.TempDir())
	cfg, err := client.NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err = cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err = cmdSend([]string{"@alice", "secret", "--force"}); err == nil || !strings.Contains(err.Error(), "different handle") {
		t.Fatalf("misdirected send not rejected at binding check: %v", err)
	}
	if err = cmdContacts([]string{"add", "@alice", "--force"}); err == nil || !strings.Contains(err.Error(), "different handle") {
		t.Fatalf("misdirected add not rejected at binding check: %v", err)
	}
	fresh, err := client.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if deliveries != 0 || len(fresh.Contacts) != 0 || len(fresh.HandleCache) != 0 {
		t.Fatalf("mutation/delivery after misdirection: %d %+v", deliveries, fresh.Contacts)
	}
}

func TestConfirmedSendCachesDirectoryProfile(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{{"normal", nil, true}, {"tier", []string{"--tier", "1"}, true}, {"ttl", []string{"--ttl", "1h"}, true}, {"reply", []string{"--reply-to", "42"}, true}, {"refused", nil, false}, {"failed-tier", []string{"--tier", "1"}, false}, {"delivery-failure", nil, false}, {"cache-failure", nil, true}} {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			routes := relay.New(st).Routes()
			configPath := ""
			sends := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/send" {
					sends++
					if tc.name == "delivery-failure" {
						http.Error(w, "injected delivery failure", 500)
						return
					}
					if tc.name == "cache-failure" && sends == 2 {
						// Replace only this disposable fixture config after send has loaded it.
						if err := os.Rename(configPath, configPath+".saved"); err != nil {
							t.Error(err)
						}
						if err := os.Mkdir(configPath, 0700); err != nil {
							t.Error(err)
						}
					}
				}
				routes.ServeHTTP(w, r)
			}))
			defer srv.Close()
			setTestHome(t, t.TempDir())
			peer, err := client.NewIdentity(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if err = peer.Save(); err != nil {
				t.Fatal(err)
			}
			cl := client.New(peer)
			if err = cl.PublishKey(); err != nil {
				t.Fatal(err)
			}
			if err = cl.DirectoryRegister("bob", "public", nil, "open"); err != nil {
				t.Fatal(err)
			}
			setTestHome(t, t.TempDir())
			cfg, err := client.NewIdentity(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if err = cfg.Save(); err != nil {
				t.Fatal(err)
			}
			home, _ := os.UserHomeDir()
			configPath = filepath.Join(home, ".courier", "config.json")
			if tc.name == "tier" {
				mintSendDirectoryToken(t, cfg)
			}
			args := append([]string{"@bob", "hello"}, tc.args...)
			if tc.name != "refused" {
				args = append(args, "--force")
			}
			capture, captureErr := os.CreateTemp(t.TempDir(), "stderr")
			if captureErr != nil {
				t.Fatal(captureErr)
			}
			oldErr := os.Stderr
			os.Stderr = capture
			err = cmdSend(args)
			os.Stderr = oldErr
			capture.Seek(0, 0)
			stderr, _ := io.ReadAll(capture)
			capture.Close()
			if tc.name == "cache-failure" {
				if !strings.Contains(string(stderr), "warning: message delivered, but could not cache recipient handle") {
					t.Fatalf("missing success warning: %s", stderr)
				}
				if e := os.Remove(configPath); e != nil {
					t.Fatal(e)
				}
				if e := os.Rename(configPath+".saved", configPath); e != nil {
					t.Fatal(e)
				}
			}
			if (err == nil) != tc.want {
				t.Fatalf("send result %v want success %v", err, tc.want)
			}
			fresh, err := client.LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			got := client.New(fresh).CachedPeerHandle(peer.Address)
			if (got == "bob") != (tc.want && tc.name != "cache-failure") {
				t.Fatalf("cached handle %q want cached %v", got, tc.want)
			}
		})
	}
}
