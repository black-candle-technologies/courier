package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A directory response suspends a real opportunistic send after its initial
// no-session decision. Another handshake completes before that response returns.
func TestFSOpportunisticInitPreservesCompetingHandshake(t *testing.T) {
	h := newFSHarness(t)
	h.asBob(func() {
		if err := h.bob.DirectoryRegister("race-bob", "public", nil, "open"); err != nil {
			t.Fatal(err)
		}
	})
	target, err := url.Parse(h.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	entered, release := make(chan struct{}), make(chan struct{})
	var sends atomic.Int64
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/directory/reverse" {
			close(entered)
			<-release
		}
		if r.URL.Path == "/v1/send" {
			sends.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer gate.Close()
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	h.aliceCfg.RelayURL = gate.URL
	setTestHome(t, h.aliceHome)
	done := make(chan error, 1)
	go func() { _, err := h.alice.fsPrepareSend(h.bobCfg.Address); done <- err }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("send never reached directory barrier")
	}
	h.doHandshake(t)
	var before []byte
	h.asAlice(func() {
		if err := updateFS(func(ff *fsFile) error {
			ff.RequireFS[h.bobCfg.Address] = true
			delete(ff.LastInitAt, h.bobCfg.Address)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		before, err = json.Marshal(h.establishedSession(t, h.bobCfg.Address))
		if err != nil {
			t.Fatal(err)
		}
	})
	sentBefore := sends.Load()
	unblock.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("send did not finish")
	}
	ff, err := loadFS()
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(ff.session(h.bobCfg.Address))
	if string(before) != string(after) {
		t.Fatal("opportunistic init replaced competing established session")
	}
	if !ff.RequireFS[h.bobCfg.Address] {
		t.Fatal("required policy changed")
	}
	if sends.Load() != sentBefore {
		t.Fatal("opportunistic init sent after competing handshake")
	}
}

func TestFSUnknownSIDRecoveryStillReplacesStaleSession(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	h.asAlice(func() {
		before := h.establishedSession(t, h.bobCfg.Address).SID
		if err := updateFS(func(ff *fsFile) error {
			delete(ff.LastInitAt, h.bobCfg.Address)
			ff.RequireFS[h.bobCfg.Address] = true
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		_, _, err := h.alice.fsDecryptMessage(h.bobCfg.Address, fsPayload{SID: b64fs.EncodeToString(make([]byte, 16))})
		if !errors.Is(err, errFSNoSession) {
			t.Fatalf("recovery error: %v", err)
		}
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess := ff.session(h.bobCfg.Address)
		if sess == nil || sess.Established || sess.SID == before {
			t.Fatal("unknown SID did not initiate recovery")
		}
		if !ff.RequireFS[h.bobCfg.Address] {
			t.Fatal("recovery erased required policy")
		}
	})
	h.bobInbox(t)
	h.aliceInbox(t)
	h.asAlice(func() { h.establishedSession(t, h.bobCfg.Address) })
}
