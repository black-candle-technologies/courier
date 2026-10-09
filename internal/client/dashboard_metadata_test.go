package client

import (
	"context"
	"encoding/json"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDashboardMetadataRefreshRenewsAndBacksOff(t *testing.T) {
	_, owner, peer := introIdentities(t)
	cl := introClient(t, owner, map[string]string{"peer": addrOf(peer)})
	address := addrOf(peer)
	now := time.Now()
	cl.cfg.HandleCache = map[string]HandleCacheEntry{address: {Handle: "old", At: now.Add(-25 * time.Hour).Unix()}}
	caps := []string{"chat"}
	profile := DirectoryProfile{Handle: "new", Address: address, Epoch: 1, Visibility: "public", ContactPolicy: "open", Capabilities: caps}
	profile.Sig = b64enc(peer.Sign(envelope.DirectoryRegister("new", peer.EdPub[:], 1, "public", "open", caps)))
	var calls atomic.Int32
	var failing atomic.Bool
	failing.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if failing.Load() {
			http.Error(w, "temporary", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []DirectoryProfile{profile}})
	}))
	defer srv.Close()
	cl.cfg.RelayURL = srv.URL
	if err := cl.cfg.Save(); err != nil {
		t.Fatal(err)
	}
	retries := map[string]time.Time{}
	cl.refreshDashboardMetadata(context.Background(), retries, now)
	cl.refreshDashboardMetadata(context.Background(), retries, now.Add(time.Minute))
	if calls.Load() != 1 || cl.cfg.HandleCache[address].Handle != "old" || cl.cfg.HandleCache[address].At != now.Add(-25*time.Hour).Unix() {
		t.Fatal("failure retried immediately or persisted false cache knowledge")
	}
	failing.Store(false)
	cl.refreshDashboardMetadata(context.Background(), retries, now.Add(6*time.Minute))
	if calls.Load() != 2 || cl.CachedPeerHandle(address) != "new" || cl.cfg.HandleRefreshAt != 0 {
		t.Fatal("expired handle was not renewed for next dashboard push")
	}
}
func TestDashboardMetadataRefreshHonorsAggregateDeadline(t *testing.T) {
	_, owner, peer := introIdentities(t)
	cl := introClient(t, owner, map[string]string{"peer": addrOf(peer)})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	cl.cfg.RelayURL = srv.URL
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	cl.refreshDashboardMetadata(ctx, map[string]time.Time{}, start)
	if time.Since(start) > time.Second {
		t.Fatal("metadata request exceeded aggregate context deadline")
	}
	if _, ok := cl.cfg.HandleCache[addrOf(peer)]; ok {
		t.Fatal("timeout created persistent negative identity knowledge")
	}
}

func TestDashboardMetadataWorkerDoesNotBlockRendering(t *testing.T) {
	_, owner, peer := introIdentities(t)
	cl := introClient(t, owner, map[string]string{"peer": addrOf(peer)})
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/dashboard/push" {
			_, _ = w.Write([]byte(`{"stored":1}`))
			return
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	cl.cfg.RelayURL, cl.cfg.DashboardURL = srv.URL, srv.URL
	if err := cl.cfg.Save(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RunDashboardMetadataRefresh(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh worker did not start")
	}
	if n, _, _, err := cl.pushBatch(srv.Client(), []pushItem{{msg: pushMsg{From: addrOf(peer), CourierID: 1}}}); err != nil || n != 1 {
		t.Fatalf("blocked directory prevented delivery: %d %v", n, err)
	}
}
