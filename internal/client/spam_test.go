package client

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

// spamFixture builds one relay-style inbox message from sender to the
// owner of cfg, sealed to cfg's current encryption key and signed by
// the sender — the same shape the real relay serves.
func spamFixture(t *testing.T, id int64, sender *crypto.Identity, cfg *Config, body string) map[string]any {
	return spamFixtureWithFlags(t, id, sender, cfg, body, nil)
}

// spamFixtureWithFlags is spamFixture plus relay-attached
// sender-reputation flags ("rate_limited", "reported").
func spamFixtureWithFlags(t *testing.T, id int64, sender *crypto.Identity, cfg *Config, body string, senderFlags []string) map[string]any {
	t.Helper()
	toEd, err := crypto.ParseAddress(cfg.Address)
	if err != nil {
		t.Fatal(err)
	}
	xpubRaw, err := base64.RawURLEncoding.DecodeString(cfg.EncKeys[0].Pub)
	if err != nil {
		t.Fatal(err)
	}
	var toX [32]byte
	copy(toX[:], xpubRaw)
	eph, nonce, ct, err := crypto.Seal(&toX, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	sentAt := time.Now().Unix()
	sig := sender.Sign(envelope.Canonical(toEd[:], sender.EdPub[:], eph, nonce, sentAt, ct))
	b64 := base64.RawURLEncoding.EncodeToString
	return map[string]any{
		"id":           id,
		"from":         crypto.FormatAddress(sender.EdPub[:]),
		"eph":          b64(eph),
		"nonce":        b64(nonce),
		"ct":           b64(ct),
		"sent_at":      sentAt,
		"received_at":  sentAt,
		"sig":          b64(sig),
		"sender_flags": senderFlags,
	}
}

// spamInboxServer serves the given messages on /v1/inbox (plain http,
// so no certificate pinning) and records dashboard push bodies.
func spamInboxServer(t *testing.T, msgs []map[string]any, pushed *[][]byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/inbox", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": msgs})
	})
	mux.HandleFunc("/v1/dashboard/push", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Messages []json.RawMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		for _, m := range in.Messages {
			*pushed = append(*pushed, m)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stored":1}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func spamTestRecipient(t *testing.T) (*Config, *Client) {
	t.Helper()
	cfg := testConfig(t) // isolated HOME, real identity + encryption keys
	return cfg, New(cfg)
}

// pointAtServer persists the fake relay URL into cfg. A plain in-memory
// assignment is not enough: Config.Update re-syncs in-memory state from
// disk (F5), which would clobber it on the first inbox call.
func pointAtServer(t *testing.T, cfg *Config, srv *httptest.Server) {
	t.Helper()
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = srv.URL
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestContactsOnlyQuarantinesInsteadOfDropping(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 7, sender, cfg, "hello stranger")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = srv.URL
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The message is fetched and decrypted, but held — not delivered.
	msgs, lastID, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 fetched message, got %d", len(msgs))
	}
	if !msgs[0].Request {
		t.Fatal("unknown sender must be quarantined in contacts mode, not delivered")
	}
	if msgs[0].Body != "hello stranger" {
		t.Fatal("quarantined message must still decrypt (it is held, not corrupted)")
	}
	if lastID != 7 {
		t.Fatalf("cursor must advance past held messages (lastID=%d), or pagination wedges", lastID)
	}

	// Review re-derives it: held messages are never silently dropped.
	held, err := cl.InboxReview(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].Body != "hello stranger" {
		t.Fatal("quarantined message lost: InboxReview must re-derive held messages")
	}

	// Adding the sender to contacts delivers it normally next time.
	if err := cfg.AddContact("stranger", crypto.FormatAddress(sender.EdPub[:])); err != nil {
		t.Fatal(err)
	}
	msgs, _, _, _, err = cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Request {
		t.Fatal("after adding the sender to contacts, the message must be delivered normally")
	}
}

func TestOpenPolicyDeliversUnknownSenders(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 3, sender, cfg, "cold call")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv)
	// DMPolicy unset: the default is open, behavior unchanged.

	msgs, _, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Request {
		t.Fatal("default (open) policy must deliver messages from unknown senders")
	}
}

func TestDMPolicyEffectiveTriState(t *testing.T) {
	cfg := &Config{}
	if got := cfg.DMPolicyEffective(); got != DMPolicyOpen {
		t.Fatalf("unset dm_policy: got %q, want open", got)
	}
	cfg.DMPolicy = "bogus-value"
	if got := cfg.DMPolicyEffective(); got != DMPolicyOpen {
		t.Fatalf("unknown dm_policy: got %q, want open (fail safe)", got)
	}
	cfg.DMPolicy = DMPolicyContacts
	if got := cfg.DMPolicyEffective(); got != DMPolicyContacts {
		t.Fatalf("contacts dm_policy: got %q, want contacts", got)
	}
}

func TestBlocklistDropsAtReadTime(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	addr := crypto.FormatAddress(sender.EdPub[:])
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 11, sender, cfg, "you are blocked")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv)

	if err := cfg.Block(addr); err != nil {
		t.Fatal(err)
	}
	msgs, lastID, skipped, filtered, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatal("blocked sender's message must not be delivered")
	}
	if filtered != 1 {
		t.Fatalf("blocked message must be counted as filtered (recipient's choice), got %d", filtered)
	}
	if skipped != 0 {
		t.Fatalf("blocked message must not count as a corrupt/failed message, skipped=%d", skipped)
	}
	if lastID != 11 {
		t.Fatalf("cursor must advance past blocked messages (lastID=%d)", lastID)
	}
	if held, err := cl.InboxReview(50); err != nil || len(held) != 0 {
		t.Fatal("blocked messages must not appear in quarantine review either")
	}

	// Unblocking recovers the message: it was never marked seen and the
	// cursor only moved the fetch window, so --all re-derives it.
	cfg.Unblock(addr)
	msgs, _, _, _, err = cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Body != "you are blocked" {
		t.Fatal("unblocking must recover the message via inbox --all")
	}
}

func TestDashboardPushSkipsQuarantined(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 5, sender, cfg, "do not push me")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.DashboardURL = srv.URL
		fresh.DashboardToken = "test-token"
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := cl.DashboardPush(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range pushed {
		var m struct {
			Body string `json:"body"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m.Body == "do not push me" {
			t.Fatal("quarantined message must never be pushed to the dashboard")
		}
	}
}
