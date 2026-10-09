package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

func TestDashboardDiscoveryAuthenticatedUnknownSurvivesRestart(t *testing.T) {
	e := newAttachTestEnv(t)
	e.asRecipient()
	if err := e.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	e.asSender()
	if err := e.sender.PublishKey(); err != nil {
		t.Fatal(err)
	}
	if err := e.sender.DirectoryRegister("stranger", "public", nil, "open"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.sender.Send(e.recipCfg.Address, "accepted message"); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.PendingPeerDiscovery[e.recipCfg.Address]; !ok {
		t.Fatal("successful send did not queue recipient")
	}
	e.asRecipient()
	msgs, _, _, _, err := e.recipient.Inbox(0, 50)
	if err != nil || len(msgs) != 1 || msgs[0].Request {
		t.Fatalf("message not accepted: %v %v", msgs, err)
	}
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.PendingPeerDiscovery[e.senderCfg.Address]; !ok {
		t.Fatal("unknown sender missing after restart")
	}
	cl := New(cfg)
	cl.refreshDashboardMetadata(context.Background(), map[string]time.Time{}, time.Now())
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HandleCache[e.senderCfg.Address].Handle != "stranger" {
		t.Fatal("unknown sender not discovered")
	}
	if _, ok := cfg.PendingPeerDiscovery[e.senderCfg.Address]; ok {
		t.Fatal("successful result left pending")
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/dashboard/push" {
			calls.Add(1)
			t.Error("render queried directory")
			return
		}
		var body struct {
			Handles map[string]string `json:"handles"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Handles[e.senderCfg.Address] != "stranger" {
			t.Error("next push omitted discovered handle")
		}
		fmt.Fprint(w, `{"stored":1}`)
	}))
	defer srv.Close()
	cfg.RelayURL = srv.URL
	cfg.DashboardURL = srv.URL
	if _, _, _, err = New(cfg).pushBatch(srv.Client(), []pushItem{{msg: pushMsg{From: e.senderCfg.Address, CourierID: 1}}}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("unexpected network discovery")
	}
}

func TestDashboardDiscoveryHeldDoesNotQueue(t *testing.T) {
	e := newAttachTestEnv(t)
	e.asRecipient()
	e.recipCfg.DMPolicy = DMPolicyContacts
	if err := e.recipCfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := e.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	e.asSender()
	if _, err := e.sender.Send(e.recipCfg.Address, "held"); err != nil {
		t.Fatal(err)
	}
	e.asRecipient()
	msgs, _, _, _, err := e.recipient.Inbox(0, 50)
	if err != nil || len(msgs) != 1 || !msgs[0].Request {
		t.Fatalf("expected held: %v %v", msgs, err)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PendingPeerDiscovery) != 0 {
		t.Fatal("held sender queued")
	}
}

func TestDashboardDiscoveryBoundAndDurableRetry(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	peers := make([]string, maxPendingPeerDiscovery+3)
	for i := range peers {
		id, err := crypto.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		peers[i] = crypto.FormatAddress(id.EdPub[:])
		if err = cl.queuePeerDiscovery(peers[i]); err != nil {
			t.Fatal(err)
		}
	}
	if len(cfg.PendingPeerDiscovery) != maxPendingPeerDiscovery {
		t.Fatal("queue unbounded")
	}
	// Contacts sort before most strangers but cannot consume their work budget.
	cfg.Contacts = map[string]string{"contact": "aaa"}
	var mu sync.Mutex
	var queried []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queried = append(queried, r.URL.String())
		mu.Unlock()
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	cfg.RelayURL = srv.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cl.refreshDashboardMetadata(context.Background(), map[string]time.Time{}, now)
	mu.Lock()
	first := append([]string(nil), queried...)
	mu.Unlock()
	if len(first) != 8 {
		t.Fatalf("budget %d", len(first))
	}
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	delayed := 0
	for _, e := range fresh.PendingPeerDiscovery {
		if e.RetryAt > now.Unix() {
			delayed++
		}
	}
	if delayed != 8 {
		t.Fatal("retry schedule not persisted")
	}
	New(fresh).refreshDashboardMetadata(context.Background(), map[string]time.Time{}, now.Add(time.Second))
	mu.Lock()
	defer mu.Unlock()
	if len(queried) != 16 {
		t.Fatal("new peers starved")
	}
	for _, a := range first {
		for _, b := range queried[8:] {
			if a == b {
				t.Fatal("restarted worker ignored durable retry")
			}
		}
	}
}

func TestDashboardTrustRevocationDurableAndConcurrent(t *testing.T) {
	cfg := testConfig(t)
	address := cfg.Address
	cfg.Contacts = map[string]string{"bob": address, "alias": address}
	cfg.ContactVerifications = map[string]ContactVerification{"bob": {Address: address, KeyEpoch: 1}}
	cfg.VerifiedKeyEpochs = map[string]int64{address: 1}
	var mu sync.Mutex
	var pushes []map[string]string
	var fail atomic.Bool
	var block atomic.Bool
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Verified map[string]string `json:"verified"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		pushes = append(pushes, body.Verified)
		mu.Unlock()
		if block.Load() {
			started <- struct{}{}
			<-release
		}
		if fail.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"stored":0}`)
	}))
	defer srv.Close()
	defer releaseOnce.Do(func() { close(release) })
	cfg.DashboardURL = srv.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	stale := New(cfg)
	stale.refreshPeerHandles(srv.Client())
	fresh, _ := LoadConfig()
	if fresh.PublishedPeerTrust[address] != "verified_cached" {
		t.Fatal("ACK snapshot missing")
	}
	// Remaining verified alias keeps the aggregate badge.
	if err := fresh.Update(func(c *Config) error { delete(c.Contacts, "alias"); c.HandleRefreshAt = 0; return nil }); err != nil {
		t.Fatal(err)
	}
	stale.refreshPeerHandles(srv.Client())
	mu.Lock()
	if pushes[len(pushes)-1][address] != "verified_cached" {
		t.Error("surviving alias badge cleared")
	}
	mu.Unlock()
	if err := fresh.Update(func(c *Config) error { delete(c.Contacts, "bob"); c.HandleRefreshAt = 0; return nil }); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	stale.refreshPeerHandles(srv.Client())
	fresh, _ = LoadConfig()
	if fresh.PublishedPeerTrust[address] != "verified_cached" {
		t.Fatal("failed clear consumed durable state")
	}
	fail.Store(false)
	block.Store(true)
	done := make(chan struct{})
	go func() { defer close(done); stale.refreshPeerHandles(srv.Client()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata request did not start")
	}
	// Re-add with changed verification while the old clear is in flight.
	if err := fresh.Update(func(c *Config) error {
		if c.Contacts == nil {
			c.Contacts = map[string]string{}
		}
		c.Contacts["bob"] = address
		c.VerifiedKeyEpochs[address] = 2
		// Another final-alias removal seeds a clear not in the in-flight payload.
		c.PublishedPeerTrust["other-removed-peer"] = "pending-clear"
		c.HandleRefreshAt = 0
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(release) })
	<-done
	block.Store(false)
	fresh, _ = LoadConfig()
	if fresh.PublishedPeerTrust["other-removed-peer"] != "pending-clear" {
		t.Fatal("ACK erased unrelated pending clear")
	}
	if fresh.HandleRefreshAt != 0 {
		t.Fatal("in-flight mutation acknowledged as current")
	}
	New(fresh).refreshPeerHandles(srv.Client())
	mu.Lock()
	defer mu.Unlock()
	if value, exists := pushes[len(pushes)-1]["other-removed-peer"]; !exists || value != "" {
		t.Fatal("unrelated clear not retried")
	}
	if pushes[len(pushes)-2][address] != "" || pushes[len(pushes)-1][address] != "stale" {
		t.Fatalf("no corrective push: %v", pushes)
	}
}

func TestDashboardDiscoveryRejectsUnauthenticatedEnvelope(t *testing.T) {
	cfg, cl := spamTestRecipient(t)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	forged := spamFixture(t, 77, id, cfg, "forged")
	forged["sig"] = "invalid"
	var pushed [][]byte
	srv := spamInboxServer(t, []map[string]any{forged}, &pushed)
	pointAtServer(t, cfg, srv)
	msgs, _, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatal("forged envelope delivered")
	}
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.PendingPeerDiscovery) != 0 {
		t.Fatal("forged sender persisted")
	}
}

func TestDashboardDiscoveryCachePersistenceFailureRetainsQueue(t *testing.T) {
	cfg := testConfig(t)
	cl := New(cfg)
	if err := cl.queuePeerDiscovery(cfg.Address); err != nil {
		t.Fatal(err)
	}
	p, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	backup := p + ".test-backup"
	var fail error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := os.Rename(p, backup); err != nil {
			fail = err
		} else {
			fail = os.Mkdir(p, 0700)
		}
		fmt.Fprint(w, `{"results":[]}`)
	}))
	defer srv.Close()
	cfg.RelayURL = srv.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl.refreshDashboardMetadata(context.Background(), map[string]time.Time{}, time.Now())
	if fail != nil {
		t.Fatal(fail)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, p); err != nil {
		t.Fatal(err)
	}
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.PendingPeerDiscovery[cfg.Address]; !ok {
		t.Fatal("failed cache save lost pending discovery")
	}
	if _, ok := fresh.HandleCache[cfg.Address]; ok {
		t.Fatal("failed cache save appeared successful")
	}
}

// Exercise the public contact lifecycle, including a dashboard populated by a
// pre-snapshot client. Every identity and verification here is a disposable fixture.
func TestDashboardTrustPublicContactLifecycle(t *testing.T) {
	for _, mode := range []string{"remove", "repoint", "upgrade-remove", "shared-alias"} {
		t.Run(mode, func(t *testing.T) {
			e := newAttachTestEnv(t)
			e.asSender()
			if err := e.sender.PublishKey(); err != nil {
				t.Fatal(err)
			}
			e.asRecipient()
			if err := e.recipCfg.AddContactAlias("bob", e.senderCfg.Address); err != nil {
				t.Fatal(err)
			}
			if err := e.recipient.VerifyContact("bob"); err != nil {
				t.Fatal(err)
			}
			if mode == "shared-alias" {
				if err := e.recipCfg.AddContactAlias("remaining", e.senderCfg.Address); err != nil {
					t.Fatal(err)
				}
				if err := e.recipient.VerifyContact("remaining"); err != nil {
					t.Fatal(err)
				}
			}
			var mu sync.Mutex
			badges := map[string]string{}
			var requests []map[string]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Verified map[string]string `json:"verified"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				mu.Lock()
				requests = append(requests, body.Verified)
				for address, status := range body.Verified {
					if status == "" {
						delete(badges, address)
					} else {
						badges[address] = status
					}
				}
				mu.Unlock()
				fmt.Fprint(w, `{"stored":0}`)
			}))
			defer srv.Close()
			if err := e.recipCfg.Update(func(c *Config) error { c.DashboardURL = srv.URL; return nil }); err != nil {
				t.Fatal(err)
			}
			e.recipient.refreshPeerHandles(srv.Client())
			mu.Lock()
			initial := badges[e.senderCfg.Address]
			mu.Unlock()
			if initial != "verified_cached" {
				t.Fatalf("verification not published: %q", initial)
			}
			if mode == "upgrade-remove" {
				if err := e.recipCfg.Update(func(c *Config) error { c.PublishedPeerTrust = nil; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "repoint" {
				if err := e.recipCfg.AddContactAlias("bob", e.snoopCfg.Address); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := e.recipCfg.RemoveContact("bob"); err != nil {
					t.Fatal(err)
				}
			}
			fresh, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if mode != "shared-alias" {
				if fresh.PublishedPeerTrust[e.senderCfg.Address] != "pending-clear" {
					t.Fatal("final identity removal did not persist a clear")
				}
				if fresh.HandleRefreshAt != 0 {
					t.Fatal("identity change did not request refresh")
				}
			}
			New(fresh).refreshPeerHandles(srv.Client())
			mu.Lock()
			defer mu.Unlock()
			if mode == "shared-alias" {
				if badges[e.senderCfg.Address] != "verified_cached" {
					t.Fatal("remaining verified alias lost badge")
				}
				if requests[len(requests)-1][e.senderCfg.Address] != "verified_cached" {
					t.Fatal("shared alias incorrectly cleared")
				}
			} else {
				if _, exists := badges[e.senderCfg.Address]; exists {
					t.Fatal("removed identity retained remote badge")
				}
				value, present := requests[len(requests)-1][e.senderCfg.Address]
				if !present || value != "" {
					t.Fatal("missing explicit clear")
				}
			}
		})
	}
}
