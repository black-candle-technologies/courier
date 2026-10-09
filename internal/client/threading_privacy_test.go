package client

import (
	"fmt"
	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func replyPrivacyHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestReplyPrivacyExpiry(t *testing.T) {
	replyPrivacyHome(t)
	const now int64 = 2000000000
	writeReplyCacheAt([]replyCacheEntry{{CourierID: 1, Snippet: "unique-expiring-plaintext", ExpiresAt: now + 1}, {CourierID: 2, Snippet: "legacy"}}, now)
	if q, ok := lookupReplyParentAt(1, now); !ok || q != "unique-expiring-plaintext" {
		t.Fatalf("live lookup: %q %v", q, ok)
	}
	if q, ok := lookupReplyParentAt(1, now+1); ok || q != "" {
		t.Fatalf("expired lookup: %q %v", q, ok)
	}
	p, _ := replyCachePath()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "unique-expiring-plaintext") {
		t.Fatal("expired plaintext persisted")
	}
	if got := readReplyCacheAt(now + 1); len(got) != 1 || got[0].Snippet != "legacy" {
		t.Fatalf("legacy record: %+v", got)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatal("cache is not private")
	}
	// An expired duplicate cannot overwrite a live record. No new entries are
	// needed to maintain future expiry after the last incoming message.
	writeReplyCacheAt([]replyCacheEntry{{CourierID: 2, Snippet: "expired-duplicate", ExpiresAt: now}}, now)
	if got := readReplyCacheAt(now); len(got) != 1 || got[0].Snippet != "legacy" {
		t.Fatalf("duplicate: %+v", got)
	}
	writeReplyCacheAt([]replyCacheEntry{{CourierID: 3, Snippet: "maintenance-secret", ExpiresAt: now + 2}}, now)
	writeReplyCacheAt(nil, now+2)
	raw, _ = os.ReadFile(p)
	if strings.Contains(string(raw), "maintenance-secret") {
		t.Fatal("nil maintenance did not prune")
	}
}

func TestReplyPrivacyLockFailureStillFilters(t *testing.T) {
	replyPrivacyHome(t)
	writeReplyCacheAt([]replyCacheEntry{{CourierID: 1, Snippet: "secret", ExpiresAt: 2}, {CourierID: 2, Snippet: "live"}}, 1)
	lock, _ := configLockPath()
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := readReplyCacheAt(2); len(got) != 1 || got[0].Snippet != "live" {
		t.Fatalf("lock failure exposed expiry: %+v", got)
	}
	if _, ok := lookupReplyParentAt(1, 2); ok {
		t.Fatal("lookup exposed expiry")
	}
}

func TestReplyPrivacyConcurrentPruneAppend(t *testing.T) {
	replyPrivacyHome(t)
	writeReplyCacheAt([]replyCacheEntry{{CourierID: 1, Snippet: "expired", ExpiresAt: 2}}, 1)
	var wg sync.WaitGroup
	for i := int64(2); i < 42; i++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			writeReplyCacheAt([]replyCacheEntry{{CourierID: id, Snippet: fmt.Sprint(id)}}, 2)
			readReplyCacheAt(2)
		}(i)
	}
	wg.Wait()
	if got := readReplyCacheAt(2); len(got) != 40 {
		t.Fatalf("lost concurrent records: %d", len(got))
	}
}

func TestReplyPrivacyHeldAndAccepted(t *testing.T) {
	for _, gate := range []string{"contact", "vhl"} {
		t.Run(gate, func(t *testing.T) {
			env := newReplyPrivacyEnv(t)
			recipient := func() { env.asRecipient(); t.Setenv("USERPROFILE", env.recipHome) }
			sender := func() { env.asSender(); t.Setenv("USERPROFILE", env.senderHome) }
			recipient()
			if err := env.recipient.PublishKey(); err != nil {
				t.Fatal(err)
			}
			if gate == "contact" {
				if err := env.recipCfg.Update(func(f *Config) error { f.DMPolicy = DMPolicyContacts; return nil }); err != nil {
					t.Fatal(err)
				}
			} else if err := env.recipient.VHLSetRequiredTier(2); err != nil {
				t.Fatal(err)
			}
			sender()
			id, err := env.sender.SendWithTTL(env.recipCfg.Address, "held-private-quote", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			recipient()
			msgs, _, _, _, err := env.recipient.Inbox(0, 50)
			if err != nil {
				t.Fatal(err)
			}
			if len(msgs) != 1 || !msgs[0].Request {
				t.Fatalf("not held: %+v", msgs)
			}
			if got := readReplyCache(); len(got) != 0 {
				t.Fatalf("held message cached: %+v", got)
			}
			if _, ok := LookupReplyParent(id); ok {
				t.Fatal("held lookup succeeded")
			}
			if gate == "contact" {
				if _, err := env.recipient.AcceptRequest(id, "sender"); err != nil {
					t.Fatal(err)
				}
			} else if err := env.recipient.VHLSetRequiredTier(0); err != nil {
				t.Fatal(err)
			}
			msgs, _, _, _, err = env.recipient.Inbox(0, 50)
			if err != nil {
				t.Fatal(err)
			}
			if len(msgs) != 1 || msgs[0].Request {
				t.Fatalf("not released: %+v", msgs)
			}
			got := readReplyCache()
			if len(got) != 1 || got[0].ExpiresAt != msgs[0].ExpiresAt || got[0].ExpiresAt == 0 {
				t.Fatalf("accepted live cache: %+v", got)
			}
			readReplyCacheAt(msgs[0].ExpiresAt)
			raw, err := os.ReadFile(filepath.Join(env.recipHome, ".courier", "thread_cache.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "held-private-quote") {
				t.Fatal("delivered TTL plaintext persisted after expiry")
			}
		})
	}
}

func newReplyPrivacyEnv(t *testing.T) *attachTestEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	t.Cleanup(srv.Close)
	env := &attachTestEnv{t: t, srv: srv, st: st, senderHome: t.TempDir(), recipHome: t.TempDir()}
	for _, entry := range []struct {
		home string
		cfg  **Config
	}{{env.senderHome, &env.senderCfg}, {env.recipHome, &env.recipCfg}} {
		t.Setenv("HOME", entry.home)
		t.Setenv("USERPROFILE", entry.home)
		cfg, err := NewIdentity(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}
		*entry.cfg = cfg
	}
	env.sender = New(env.senderCfg)
	env.recipient = New(env.recipCfg)
	return env
}

func TestReplyPrivacyPruneFailureStillFilters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission failure fixture")
	}
	replyPrivacyHome(t)
	writeReplyCacheAt([]replyCacheEntry{{CourierID: 1, Snippet: "secret", ExpiresAt: 2}, {CourierID: 2, Snippet: "live"}}, 1)
	p, _ := replyCachePath()
	dir := filepath.Dir(p)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		f.Close()
		os.Remove(f.Name())
		t.Skip("executor bypasses directory permissions")
	}
	if got := readReplyCacheAt(2); len(got) != 1 || got[0].Snippet != "live" {
		t.Fatalf("prune failure exposed expiry: %+v", got)
	}
	if _, ok := lookupReplyParentAt(1, 2); ok {
		t.Fatal("lookup exposed expiry")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "secret") {
		t.Fatal("fixture did not retain unprunable bytes")
	}
}

func TestReplyPrivacyMixedBatch(t *testing.T) {
	env := newReplyPrivacyEnv(t)
	home := func(h string) { t.Setenv("HOME", h); t.Setenv("USERPROFILE", h) }
	trustedHome := t.TempDir()
	home(trustedHome)
	trustedCfg, err := NewIdentity(env.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := trustedCfg.Save(); err != nil {
		t.Fatal(err)
	}
	trusted := New(trustedCfg)
	home(env.recipHome)
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	if err := env.recipCfg.AddContact("trusted", trustedCfg.Address); err != nil {
		t.Fatal(err)
	}
	if err := env.recipCfg.Update(func(f *Config) error { f.DMPolicy = DMPolicyContacts; return nil }); err != nil {
		t.Fatal(err)
	}
	home(env.senderHome)
	heldID, err := env.sender.Send(env.recipCfg.Address, "quarantined-unique-secret")
	if err != nil {
		t.Fatal(err)
	}
	home(trustedHome)
	liveID, err := trusted.Send(env.recipCfg.Address, "accepted-live-parent")
	if err != nil {
		t.Fatal(err)
	}
	replyIDs := make([]int64, 0, 2)
	for _, parent := range []int64{heldID, liveID} {
		raw, err := encodeReplyPayload("accepted reply", parent, "", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		id, err := trusted.sendProtocolDM(env.recipCfg.Address, string(raw))
		if err != nil {
			t.Fatal(err)
		}
		replyIDs = append(replyIDs, id)
	}
	home(env.recipHome)
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, m := range msgs {
		if m.ID == replyIDs[0] {
			found++
			if m.Request || m.ReplyQuote != "" {
				t.Errorf("held parent leaked to accepted reply: %+v", m)
			}
		}
		if m.ID == replyIDs[1] {
			found++
			if m.ReplyQuote != "accepted-live-parent" {
				t.Errorf("live parent not quoted: %+v", m)
			}
		}
	}
	if found != 2 {
		t.Fatalf("missing replies: %+v", msgs)
	}
	var pushed strings.Builder
	dash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		pushed.Write(raw)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer dash.Close()
	if err := env.recipCfg.Update(func(f *Config) error { f.DashboardURL = dash.URL; f.DashboardToken = "fixture"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := env.recipient.DashboardPush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pushed.String(), "quarantined-unique-secret") {
		t.Error("dashboard received held parent plaintext")
	}
	if !strings.Contains(pushed.String(), "accepted-live-parent") {
		t.Error("dashboard did not receive accepted parent")
	}
}
