package client

import (
	"encoding/json"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDashboardHandleRenderingNeverQueriesDirectory(t *testing.T) {
	cfg := testConfig(t)
	unknown, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	unknownAddress := crypto.FormatAddress(unknown.EdPub[:])
	var directoryCalls atomic.Int32
	var pushedMu sync.Mutex
	var pushed []map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/dashboard/push" {
			directoryCalls.Add(1)
			http.Error(w, "directory unavailable", http.StatusServiceUnavailable)
			return
		}
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		pushedMu.Lock()
		pushed = append(pushed, payload)
		pushedMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stored":2}`))
	}))
	defer srv.Close()
	cfg.RelayURL, cfg.DashboardURL = srv.URL, srv.URL
	cfg.HandleCache = map[string]HandleCacheEntry{cfg.Address: {Handle: "known", At: time.Now().Unix()}}
	cfg.Contacts = map[string]string{"unknown": unknownAddress, "known": cfg.Address}
	cfg.ContactVerifications = map[string]ContactVerification{"known": {Address: cfg.Address, KeyEpoch: 1}}
	cfg.VerifiedKeyEpochs = map[string]int64{cfg.Address: 1}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	batch := []pushItem{{msg: pushMsg{From: cfg.Address, CourierID: 1}}, {msg: pushMsg{From: unknownAddress, CourierID: 2}}}
	for i := 0; i < 2; i++ {
		if n, max, _, err := cl.pushBatch(srv.Client(), batch); err != nil || n != 2 || max != 2 {
			t.Fatalf("push stalled/failed: %d %d %v", n, max, err)
		}
	}
	cl.refreshPeerHandles(srv.Client())
	if st, _ := cl.CachedContactTrust("unknown"); st != TrustUnverified {
		t.Fatal("unknown became verified")
	}
	if err := cfg.Update(func(fresh *Config) error {
		fresh.VerifiedKeyEpochs[cfg.Address] = 2
		fresh.HandleRefreshAt = 0
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cl.refreshPeerHandles(srv.Client())
	if directoryCalls.Load() != 0 {
		t.Fatalf("dashboard made %d directory requests", directoryCalls.Load())
	}
	if _, ok := cfg.HandleCache[unknownAddress]; ok {
		t.Fatal("rendering persisted false identity knowledge")
	}
	pushedMu.Lock()
	defer pushedMu.Unlock()
	if len(pushed) != 4 {
		t.Fatalf("want two batches and two cached refreshes, got %d", len(pushed))
	}
	for i, want := range []string{"verified_cached", "stale"} {
		var states map[string]string
		if err := json.Unmarshal(pushed[i+2]["verified"], &states); err != nil {
			t.Fatal(err)
		}
		if states[cfg.Address] != want || states[unknownAddress] != "" {
			t.Fatalf("incorrect cached trust: %v", states)
		}
	}
	for _, p := range pushed {
		var handles map[string]string
		if err := json.Unmarshal(p["handles"], &handles); err != nil {
			t.Fatal(err)
		}
		if handles[cfg.Address] != "known" || len(handles) != 1 {
			t.Fatalf("unexpected cached labels: %v", handles)
		}
	}
}
