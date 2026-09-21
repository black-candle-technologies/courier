package client

import (
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// TestFirstContactFlagOnDelivered: in the default open policy, a
// message from an unknown sender is still delivered — but it carries
// the machine-readable first_contact flag.
func TestFirstContactFlagOnDelivered(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 3, sender, cfg, "cold call")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv)
	// DMPolicy unset: open is the default.

	msgs, _, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 delivered message, got %d", len(msgs))
	}
	if msgs[0].Request {
		t.Fatal("open policy must deliver first-contact messages, not hold them")
	}
	if !slices.Contains(msgs[0].Flags, "first_contact") {
		t.Fatalf("delivered first-contact message must carry the flag, got %v", msgs[0].Flags)
	}
}

// TestKnownSenderHasNoFirstContactFlag: contacts and self-messages are
// never flagged first_contact.
func TestKnownSenderHasNoFirstContactFlag(t *testing.T) {
	friend, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	friendAddr := crypto.FormatAddress(friend.EdPub[:])
	if err := cfg.AddContact("friend", friendAddr); err != nil {
		t.Fatal(err)
	}
	env := spamFixture(t, 4, friend, cfg, "hi from a friend")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv)

	msgs, _, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || slices.Contains(msgs[0].Flags, "first_contact") {
		t.Fatalf("contact's message must not be flagged first_contact: %+v", msgs)
	}
}

// TestReportedSenderHeldInOpenMode: when the relay reports a sender is
// currently throttled for spam, the message is held as a request even
// under the open policy — with both flags machine-readable.
func TestReportedSenderHeldInOpenMode(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixtureWithFlags(t, 9, sender, cfg, "spam?", []string{"reported", "rate_limited"})
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv)
	// Open policy: first_contact alone would deliver.

	msgs, _, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || !msgs[0].Request {
		t.Fatal("a sender flagged 'reported' must be held as a request even in open mode")
	}
	for _, f := range []string{"first_contact", "reported", "rate_limited"} {
		if !slices.Contains(msgs[0].Flags, f) {
			t.Fatalf("want flag %q, got %v", f, msgs[0].Flags)
		}
	}
	held, err := cl.InboxReview(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0].ID != 9 {
		t.Fatal("reported message must be re-derivable via InboxReview")
	}
}

// contactsModeRecipient is a test recipient with dm_policy=contacts
// persisted, pointed at a fake relay serving msgs.
func contactsModeRecipient(t *testing.T, msgs []map[string]any) (*Config, *Client, *httptest.Server) {
	t.Helper()
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	srv := spamInboxServer(t, msgs, &pushed)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = srv.URL
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return cfg, cl, srv
}

// TestRequestAcceptAddsFirstContactToContacts: accepting a
// first-contact request adds the sender to contacts (auto-named) and
// releases the held messages; later fetches deliver normally.
func TestRequestAcceptAddsFirstContactToContacts(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	senderAddrStr := crypto.FormatAddress(sender.EdPub[:])
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env1 := spamFixture(t, 21, sender, cfg, "hello? first")
	env2 := spamFixture(t, 22, sender, cfg, "hello? second")
	srv := spamInboxServer(t, []map[string]any{env1, env2}, &pushed)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = srv.URL
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	held, err := cl.InboxReview(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 2 {
		t.Fatalf("want 2 held requests, got %d", len(held))
	}
	for _, m := range held {
		for _, f := range []string{"first_contact", "quarantined_by_policy"} {
			if !slices.Contains(m.Flags, f) {
				t.Fatalf("held message #%d: want flag %q, got %v", m.ID, f, m.Flags)
			}
		}
	}

	released, err := cl.AcceptRequest(21, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(released) != 2 {
		t.Fatalf("accept must release all held messages from the sender, got %d", len(released))
	}
	for _, m := range released {
		if m.Request {
			t.Fatal("released messages must not be marked as requests")
		}
	}
	if got := senderAddr(cfg, senderAddrStr); got == "" {
		t.Fatal("accepting a first-contact request must add the sender to contacts")
	}

	// Future fetches deliver the sender's messages normally.
	msgs, _, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 delivered messages after accept, got %d", len(msgs))
	}
	for _, m := range msgs {
		if m.Request {
			t.Fatal("sender is now a contact: messages must be delivered, not held")
		}
	}
}

// TestRequestAcceptWithName: --as names the new contact.
func TestRequestAcceptWithName(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	senderAddrStr := crypto.FormatAddress(sender.EdPub[:])
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 31, sender, cfg, "hi, name me")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = srv.URL
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := cl.AcceptRequest(31, "penpal"); err != nil {
		t.Fatal(err)
	}
	if addr, err := cfg.LookupContact("penpal"); err != nil || addr != senderAddrStr {
		t.Fatalf("want contact penpal=%s, got %q, %v", senderAddrStr, addr, err)
	}
}

// TestRequestAcceptUnknownID errors instead of accepting nothing.
func TestRequestAcceptUnknownID(t *testing.T) {
	_, cl, _ := contactsModeRecipient(t, nil)
	if _, err := cl.AcceptRequest(999, ""); err == nil {
		t.Fatal("accepting an unknown request id must fail")
	}
}

// TestRequestDismissSuppresses: dismissing removes the request from
// review; the sender's messages no longer surface, are counted as
// filtered (the recipient's choice), and the dismissal is reversible.
func TestRequestDismissSuppresses(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	senderAddrStr := crypto.FormatAddress(sender.EdPub[:])
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 41, sender, cfg, "go away")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = srv.URL
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	from, err := cl.DismissRequest(41)
	if err != nil {
		t.Fatal(err)
	}
	if from != senderAddrStr {
		t.Fatalf("dismiss returned sender %q, want %q", from, senderAddrStr)
	}
	if !cfg.IsDismissed(senderAddrStr) {
		t.Fatal("dismissed sender must be in the dismissed set")
	}

	// No longer listed as a request...
	held, err := cl.InboxReview(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 0 {
		t.Fatal("dismissed sender's messages must not surface as requests")
	}
	// ...nor delivered: counted as filtered, never mixed into the inbox.
	msgs, _, skipped, filtered, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 || skipped != 0 || filtered != 1 {
		t.Fatalf("dismissed message: want 0 delivered/0 skipped/1 filtered, got %d/%d/%d",
			len(msgs), skipped, filtered)
	}

	// Reversible: undismiss surfaces the request again.
	if err := cfg.Update(func(fresh *Config) error {
		fresh.Undismiss(senderAddrStr)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	held, err = cl.InboxReview(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 {
		t.Fatal("undismiss must surface the request again")
	}
}
