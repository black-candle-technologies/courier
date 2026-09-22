package client

import (
	"bytes"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
)

// TestAttachmentEndToEnd exercises the whole attachment flow against a
// live relay: sender encrypts, uploads blobs, and sends; the recipient
// reads the inbox, downloads the blob as the authorized recipient, and
// gets byte-identical plaintext back.
func TestAttachmentEndToEnd(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // keep the sent log out of the real home
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()

	senderCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	recipCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sender := New(senderCfg)
	recipient := New(recipCfg)
	// Publish the recipient's encryption key so the sender wraps the
	// data key for the key the recipient actually holds.
	if err := recipient.PublishKey(); err != nil {
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

	if _, err := sender.SendWithAttachments(recipCfg.Address, "see attached", []string{bigPath, smallPath}); err != nil {
		t.Fatalf("send: %v", err)
	}

	msgs, _, skipped, _, err := recipient.Inbox(0, 50)
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
		data, err := recipient.DownloadAttachment(a)
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
	t.Setenv("HOME", t.TempDir())
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()

	senderCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	recipCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sender := New(senderCfg)
	recipient := New(recipCfg)
	if err := recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}

	if _, err := sender.Send(recipCfg.Address, "just words"); err != nil {
		t.Fatalf("send: %v", err)
	}
	msgs, _, _, _, err := recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Body != "just words" || len(msgs[0].Attachments) != 0 {
		t.Fatalf("plain message mangled: %+v", msgs)
	}
}

// TestAttachmentEndToEndNonRecipientBlocked verifies that a third party
// who receives the blob id cannot fetch or decrypt the attachment.
func TestAttachmentEndToEndNonRecipientBlocked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()

	senderCfg, _ := NewIdentity(srv.URL)
	recipCfg, _ := NewIdentity(srv.URL)
	snoopCfg, _ := NewIdentity(srv.URL)
	sender, recipient, snoop := New(senderCfg), New(recipCfg), New(snoopCfg)
	if err := recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	if err := snoop.PublishKey(); err != nil {
		t.Fatal(err)
	}

	fp := filepath.Join(t.TempDir(), "secret.bin")
	plain := []byte("top secret bytes")
	if err := os.WriteFile(fp, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.SendWithAttachments(recipCfg.Address, "for you", []string{fp}); err != nil {
		t.Fatalf("send: %v", err)
	}

	msgs, _, _, _, err := recipient.Inbox(0, 50)
	if err != nil || len(msgs) != 1 || len(msgs[0].Attachments) != 1 {
		t.Fatalf("inbox: %v %+v", err, msgs)
	}
	blobID := msgs[0].Attachments[0].Manifest.BlobID

	// The snooper is not the recipient: the relay refuses the download.
	if _, err := snoop.downloadBlob(blobID); err == nil {
		t.Fatal("non-recipient downloaded the blob")
	}
}

// TestFetchMessageRefetchEndToEnd reproduces issue #136: a message whose
// attachments were never downloaded — because the first `inbox` fetch
// did not pass --attachments-dir — is re-fetchable by id, and the blobs
// download byte-identical through the normal verified path.
func TestFetchMessageRefetchEndToEnd(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // keep the sent log out of the real home
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()

	senderCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	recipCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Persist the configs so replay-suppression bookkeeping (which is a
	// read-modify-write against the on-disk config) actually sticks.
	if err := senderCfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := recipCfg.Save(); err != nil {
		t.Fatal(err)
	}
	sender := New(senderCfg)
	recipient := New(recipCfg)
	if err := recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}

	small := []byte("hello attachment world")
	smallPath := filepath.Join(t.TempDir(), "small.txt")
	if err := os.WriteFile(smallPath, small, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.SendWithAttachments(recipCfg.Address, "see attached", []string{smallPath}); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Consume the message like the flag-less inbox poller: delivered,
	// replay-suppressed, attachments never downloaded.
	msgs, _, skipped, _, err := recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("inbox skipped %d messages", skipped)
	}
	if len(msgs) != 1 {
		t.Fatalf("inbox: got %d messages, want 1", len(msgs))
	}
	id := msgs[0].ID

	// The message is now invisible to the normal inbox: replay
	// suppression consumed it.
	again, _, _, _, err := recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("second inbox: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second inbox: got %d messages, want 0 (replay suppression)", len(again))
	}

	// The explicit re-fetch bypasses suppression for this id only.
	m, err := recipient.FetchMessage(id)
	if err != nil {
		t.Fatalf("FetchMessage: %v", err)
	}
	if m.ID != id || m.Body != "see attached" {
		t.Fatalf("FetchMessage returned wrong message: %+v", m)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("FetchMessage: got %d attachments, want 1", len(m.Attachments))
	}
	a := m.Attachments[0]
	if a.KeyError != nil {
		t.Fatalf("key error: %v", a.KeyError)
	}
	data, err := recipient.DownloadAttachment(a)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(data, small) {
		t.Fatal("downloaded bytes differ")
	}

	// The fetch is read-only and repeatable: a second re-fetch works,
	// and the normal inbox still suppresses the message afterwards.
	m2, err := recipient.FetchMessage(id)
	if err != nil {
		t.Fatalf("second FetchMessage: %v", err)
	}
	if m2.ID != id || len(m2.Attachments) != 1 {
		t.Fatalf("second FetchMessage wrong: %+v", m2)
	}
	third, _, _, _, err := recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("third inbox: %v", err)
	}
	if len(third) != 0 {
		t.Fatalf("third inbox: got %d messages, want 0", len(third))
	}

	// Invalid and unknown ids fail closed.
	for _, bad := range []int64{0, -1, id + 1000} {
		if _, err := recipient.FetchMessage(bad); err == nil {
			t.Fatalf("FetchMessage(%d): want error, got nil", bad)
		}
	}
}

// TestFetchMessageDoesNotMarkSeen proves the replay-suppression bypass
// is scoped to the explicitly named envelope: re-fetching a message
// that was never delivered does not mark it seen, so the normal inbox
// still delivers it afterwards.
func TestFetchMessageDoesNotMarkSeen(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	defer srv.Close()

	senderCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	recipCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Persist the configs so replay-suppression bookkeeping (which is a
	// read-modify-write against the on-disk config) actually sticks.
	if err := senderCfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := recipCfg.Save(); err != nil {
		t.Fatal(err)
	}
	sender := New(senderCfg)
	recipient := New(recipCfg)
	if err := recipient.PublishKey(); err != nil {
		t.Fatalf("publish key: %v", err)
	}

	sentID, err := sender.Send(recipCfg.Address, "never delivered, only re-fetched")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	m, err := recipient.FetchMessage(sentID)
	if err != nil {
		t.Fatalf("FetchMessage: %v", err)
	}
	if m.Body != "never delivered, only re-fetched" {
		t.Fatalf("wrong body: %q", m.Body)
	}
	if len(m.Attachments) != 0 {
		t.Fatalf("got %d attachments, want 0", len(m.Attachments))
	}

	// The re-fetch marked nothing seen: the normal inbox still delivers
	// the message as new.
	msgs, _, _, _, err := recipient.Inbox(0, 50)
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(msgs) != 1 || msgs[0].ID != sentID {
		t.Fatalf("inbox after FetchMessage: got %+v, want the message delivered", msgs)
	}
}
