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

	msgs, _, skipped, err := recipient.Inbox(0, 50)
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
	msgs, _, _, err := recipient.Inbox(0, 50)
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

	msgs, _, _, err := recipient.Inbox(0, 50)
	if err != nil || len(msgs) != 1 || len(msgs[0].Attachments) != 1 {
		t.Fatalf("inbox: %v %+v", err, msgs)
	}
	blobID := msgs[0].Attachments[0].Manifest.BlobID

	// The snooper is not the recipient: the relay refuses the download.
	if _, err := snoop.downloadBlob(blobID); err == nil {
		t.Fatal("non-recipient downloaded the blob")
	}
}
