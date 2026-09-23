package client

import (
	"bytes"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/bridge"
	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
)

// attachTestEnv is the shared harness for the attachment end-to-end
// tests: one relay, one HOME directory per identity, and asSender /
// asRecipient / asSnoop helpers to switch HOME around operations — the
// asAlice/asBob pattern from the group/FS harnesses.
//
// Separate HOMEs matter: identity configs are persisted (Save) and
// reloaded (Update) via read-modify-write against
// $HOME/.courier/config.json, so two identities sharing one HOME can
// clobber each other mid-test — e.g. recipient-key verification during
// SendWithAttachments calling senderCfg.Update, which reloads the one
// on-disk config and can turn the sender into the recipient, silently
// converting the test into a self-message exchange (issue #136 review).
// Every test below also asserts m.From == senderCfg.Address so this
// class of corruption is caught explicitly.
type attachTestEnv struct {
	t   *testing.T
	srv *httptest.Server
	st  *store.Store

	senderHome, recipHome, snoopHome string
	senderCfg, recipCfg, snoopCfg    *Config
	sender, recipient, snoop         *Client
}

func newAttachTestEnv(t *testing.T) *attachTestEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	t.Cleanup(srv.Close)

	env := &attachTestEnv{t: t, srv: srv, st: st}
	env.senderHome, env.recipHome, env.snoopHome = t.TempDir(), t.TempDir(), t.TempDir()
	// Each identity is created and persisted under its own HOME, so the
	// on-disk configs can never overwrite each other. Persisting also
	// makes replay-suppression bookkeeping (a read-modify-write against
	// the on-disk config) actually stick.
	identities := []struct {
		home string
		dst  **Config
	}{
		{env.senderHome, &env.senderCfg},
		{env.recipHome, &env.recipCfg},
		{env.snoopHome, &env.snoopCfg},
	}
	for _, id := range identities {
		t.Setenv("HOME", id.home)
		cfg, err := NewIdentity(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}
		*id.dst = cfg
	}
	env.sender = New(env.senderCfg)
	env.recipient = New(env.recipCfg)
	env.snoop = New(env.snoopCfg)
	return env
}

func (e *attachTestEnv) asSender()    { e.t.Setenv("HOME", e.senderHome) }
func (e *attachTestEnv) asRecipient() { e.t.Setenv("HOME", e.recipHome) }
func (e *attachTestEnv) asSnoop()     { e.t.Setenv("HOME", e.snoopHome) }

// TestAttachmentEndToEnd exercises the whole attachment flow against a
// live relay: sender encrypts, uploads blobs, and sends; the recipient
// reads the inbox, downloads the blob as the authorized recipient, and
// gets byte-identical plaintext back.
func TestAttachmentEndToEnd(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	// Publish the recipient's encryption key so the sender wraps the
	// data key for the key the recipient actually holds.
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}

	// A multi-chunk file plus a small one.
	big := make([]byte, 600*1024)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	small := []byte("hello attachment world")
	bigPath := filepath.Join(t.TempDir(), "big.bin")
	smallPath := filepath.Join(t.TempDir(), "small.txt")
	if err := os.WriteFile(bigPath, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(smallPath, small, 0o644); err != nil {
		t.Fatal(err)
	}

	env.asSender()
	if _, err := env.sender.SendWithAttachments(env.recipCfg.Address, "see attached", []string{bigPath, smallPath}); err != nil {
		t.Fatalf("send: %v", err)
	}

	env.asRecipient()
	msgs, _, skipped, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("inbox skipped %d messages", skipped)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.From != env.senderCfg.Address {
		t.Fatalf("From = %q, want sender %q", m.From, env.senderCfg.Address)
	}
	if m.Body != "see attached" {
		t.Fatalf("body = %q", m.Body)
	}
	if len(m.Attachments) != 2 {
		t.Fatalf("attachments = %d, want 2", len(m.Attachments))
	}
	want := map[string][]byte{"big.bin": big, "small.txt": small}
	for _, a := range m.Attachments {
		if a.KeyError != nil {
			t.Fatalf("%s: key error: %v", a.Manifest.Filename, a.KeyError)
		}
		data, err := env.recipient.DownloadAttachment(a)
		if err != nil {
			t.Fatalf("%s: download: %v", a.Manifest.Filename, err)
		}
		if !bytes.Equal(data, want[a.Manifest.Filename]) {
			t.Fatalf("%s: downloaded bytes differ", a.Manifest.Filename)
		}
	}
}

// TestAttachmentEndToEndPlaintextUnaffected verifies that messages
// without attachments still travel as raw text end to end.
func TestAttachmentEndToEndPlaintextUnaffected(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}

	env.asSender()
	if _, err := env.sender.Send(env.recipCfg.Address, "just words"); err != nil {
		t.Fatalf("send: %v", err)
	}
	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Body != "just words" || len(msgs[0].Attachments) != 0 {
		t.Fatalf("plain message mangled: %+v", msgs)
	}
	if msgs[0].From != env.senderCfg.Address {
		t.Fatalf("From = %q, want sender %q", msgs[0].From, env.senderCfg.Address)
	}
}

// TestAttachmentEndToEndNonRecipientBlocked verifies that a third party
// who receives the blob id cannot fetch or decrypt the attachment.
func TestAttachmentEndToEndNonRecipientBlocked(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	env.asSnoop()
	if err := env.snoop.PublishKey(); err != nil {
		t.Fatal(err)
	}

	fp := filepath.Join(t.TempDir(), "secret.bin")
	plain := []byte("top secret bytes")
	if err := os.WriteFile(fp, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	env.asSender()
	if _, err := env.sender.SendWithAttachments(env.recipCfg.Address, "for you", []string{fp}); err != nil {
		t.Fatalf("send: %v", err)
	}

	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil || len(msgs) != 1 || len(msgs[0].Attachments) != 1 {
		t.Fatalf("inbox: %v %+v", err, msgs)
	}
	if msgs[0].From != env.senderCfg.Address {
		t.Fatalf("From = %q, want sender %q", msgs[0].From, env.senderCfg.Address)
	}
	blobID := msgs[0].Attachments[0].Manifest.BlobID

	// The snooper is not the recipient: the relay refuses the download.
	env.asSnoop()
	if _, err := env.snoop.downloadBlob(blobID); err == nil {
		t.Fatal("non-recipient downloaded the blob")
	}
}

// TestFetchMessageRefetchEndToEnd reproduces issue #136: a message whose
// attachments were never downloaded — because the first `inbox` fetch
// did not pass --attachments-dir — is re-fetchable by id, and the blobs
// download byte-identical through the normal verified path.
func TestFetchMessageRefetchEndToEnd(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}

	small := []byte("hello attachment world")
	smallPath := filepath.Join(t.TempDir(), "small.txt")
	if err := os.WriteFile(smallPath, small, 0o644); err != nil {
		t.Fatal(err)
	}
	env.asSender()
	if _, err := env.sender.SendWithAttachments(env.recipCfg.Address, "see attached", []string{smallPath}); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Consume the message like the flag-less inbox poller: delivered,
	// replay-suppressed, attachments never downloaded.
	env.asRecipient()
	msgs, _, skipped, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("inbox skipped %d messages", skipped)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	if msgs[0].From != env.senderCfg.Address {
		t.Fatalf("From = %q, want sender %q", msgs[0].From, env.senderCfg.Address)
	}
	id := msgs[0].ID

	// The message is now invisible to the normal inbox: replay
	// suppression consumed it.
	again, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("second inbox: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second inbox: got %d messages, want 0 (replay suppression)", len(again))
	}

	// The explicit re-fetch bypasses suppression for this id only.
	m, err := env.recipient.FetchMessage(id)
	if err != nil {
		t.Fatalf("FetchMessage: %v", err)
	}
	if m.ID != id || m.Body != "see attached" {
		t.Fatalf("FetchMessage returned wrong message: %+v", m)
	}
	if m.From != env.senderCfg.Address {
		t.Fatalf("FetchMessage From = %q, want sender %q", m.From, env.senderCfg.Address)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("FetchMessage: got %d attachments, want 1", len(m.Attachments))
	}
	a := m.Attachments[0]
	if a.KeyError != nil {
		t.Fatalf("key error: %v", a.KeyError)
	}
	data, err := env.recipient.DownloadAttachment(a)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(data, small) {
		t.Fatal("downloaded bytes differ")
	}

	// The fetch is read-only and repeatable: a second re-fetch works,
	// and the normal inbox still suppresses the message afterwards.
	m2, err := env.recipient.FetchMessage(id)
	if err != nil {
		t.Fatalf("second FetchMessage: %v", err)
	}
	if m2.ID != id || len(m2.Attachments) != 1 {
		t.Fatalf("second FetchMessage wrong: %+v", m2)
	}
	third, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("third inbox: %v", err)
	}
	if len(third) != 0 {
		t.Fatalf("third inbox: got %d messages, want 0", len(third))
	}

	// Invalid and unknown ids fail closed.
	for _, bad := range []int64{0, -1, id + 1000} {
		if _, err := env.recipient.FetchMessage(bad); err == nil {
			t.Fatalf("FetchMessage(%d): want error, got nil", bad)
		}
	}
}

// TestFetchMessageDoesNotMarkSeen proves the replay-suppression bypass
// is scoped to the explicitly named envelope: re-fetching a message
// that was never delivered does not mark it seen, so the normal inbox
// still delivers it afterwards.
func TestFetchMessageDoesNotMarkSeen(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}

	env.asSender()
	sentID, err := env.sender.Send(env.recipCfg.Address, "never delivered, only re-fetched")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	env.asRecipient()
	m, err := env.recipient.FetchMessage(sentID)
	if err != nil {
		t.Fatalf("FetchMessage: %v", err)
	}
	if m.Body != "never delivered, only re-fetched" {
		t.Fatalf("wrong body: %q", m.Body)
	}
	if m.From != env.senderCfg.Address {
		t.Fatalf("FetchMessage From = %q, want sender %q", m.From, env.senderCfg.Address)
	}
	if len(m.Attachments) != 0 {
		t.Fatalf("got %d attachments, want 0", len(m.Attachments))
	}

	// The re-fetch marked nothing seen: the normal inbox still delivers
	// the message as new.
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 || msgs[0].ID != sentID {
		t.Fatalf("inbox after FetchMessage: got %+v, want the message delivered", msgs)
	}
}

// TestFetchMessageHeldForReviewContactsOnly (issue #136 review): the
// targeted re-fetch enforces the same request/quarantine policy as the
// inbox. A first-contact sender under the contacts-only policy is held,
// so FetchMessage refuses before decrypting — it must not materialize a
// quarantined sender's attachments without the recipient accepting the
// request first.
func TestFetchMessageHeldForReviewContactsOnly(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 21, sender, cfg, "quarantined hello")
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = srv.URL
		fresh.DMPolicy = DMPolicyContacts
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.FetchMessage(21); err == nil {
		t.Fatal("FetchMessage must refuse a held first-contact message")
	} else if !strings.Contains(err.Error(), "held for review") {
		t.Fatalf("wrong error: %v", err)
	}
}

// TestFetchMessageHeldForReviewReportedSender (issue #136 review): a
// relay-reported sender is held even under the open policy, and the
// targeted re-fetch refuses it exactly like the inbox does.
func TestFetchMessageHeldForReviewReportedSender(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixtureWithFlags(t, 22, sender, cfg, "spam?", []string{"reported"})
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv) // open policy is the default
	if _, err := cl.FetchMessage(22); err == nil {
		t.Fatal("FetchMessage must refuse a relay-reported sender")
	} else if !strings.Contains(err.Error(), "held for review") {
		t.Fatalf("wrong error: %v", err)
	}
}

// TestFetchMessageDerivesBridged (issue #136 review): the targeted
// re-fetch derives the Bridged bit exactly like the inbox does — here
// via the plaintext body banner layer, so no bridge gateway config is
// needed. The same envelope is then run through the inbox to prove the
// two paths cannot drift.
func TestFetchMessageDerivesBridged(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl := spamTestRecipient(t)
	env := spamFixture(t, 23, sender, cfg, bridge.WrapBody("hello via bridge"))
	srv := spamInboxServer(t, []map[string]any{env}, &pushed)
	pointAtServer(t, cfg, srv) // open policy is the default
	m, err := cl.FetchMessage(23)
	if err != nil {
		t.Fatalf("FetchMessage: %v", err)
	}
	if !m.Bridged {
		t.Fatal("FetchMessage must derive Bridged for a bannered body, like the inbox does")
	}
	// The re-fetch marks nothing seen, so the inbox still delivers the
	// same envelope — and must agree on the classification.
	msgs, _, _, _, err := cl.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 || !msgs[0].Bridged {
		t.Fatalf("inbox/FetchMessage bridged classification drifted: %+v", msgs)
	}
}
