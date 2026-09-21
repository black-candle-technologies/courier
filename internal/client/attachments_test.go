package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

// testRecipient builds a recipient identity: an address, its X25519
// keypair for wrapping data keys, and the private key for unwrapping.
func testRecipient(t *testing.T) (addr string, pub, priv [32]byte) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err = crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	return crypto.FormatAddress(id.EdPub[:]), pub, priv
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAttachmentRoundTrip(t *testing.T) {
	addr, pub, priv := testRecipient(t)
	for _, size := range []int{1, 100, 512, 300 * 1024, 600 * 1024} {
		plain := randomBytes(t, size)
		m, blob, err := EncryptAttachment(plain, "notes.bin", pub, addr)
		if err != nil {
			t.Fatalf("size %d: encrypt: %v", size, err)
		}
		if err := envelope.ValidateManifest(&m); err != nil {
			t.Fatalf("size %d: manifest invalid: %v", size, err)
		}
		if m.Chunks != envelope.ChunkCount(int64(size)) {
			t.Fatalf("size %d: wrong chunk count %d", size, m.Chunks)
		}
		dk, err := UnwrapDataKey(m.Keys[0], priv)
		if err != nil {
			t.Fatalf("size %d: unwrap: %v", size, err)
		}
		got, err := DecryptAttachment(blob, m, dk)
		if err != nil {
			t.Fatalf("size %d: decrypt: %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: round-trip mismatch", size)
		}
	}
}

func TestAttachmentRejectsEmpty(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	if _, _, err := EncryptAttachment(nil, "empty", pub, addr); err == nil {
		t.Fatal("expected error for empty attachment")
	}
}

func TestAttachmentRejectsOversized(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	big := make([]byte, envelope.MaxAttachmentBytes+1)
	if _, _, err := EncryptAttachment(big, "big.bin", pub, addr); err == nil {
		t.Fatal("expected error for oversized attachment")
	}
}

func TestAttachmentTamperedChunkRejected(t *testing.T) {
	addr, pub, priv := testRecipient(t)
	plain := randomBytes(t, 600*1024) // multi-chunk
	m, blob, err := EncryptAttachment(plain, "f.bin", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := UnwrapDataKey(m.Keys[0], priv)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle of the second chunk's ciphertext.
	tampered := bytes.Clone(blob)
	flipAt := len(tampered) / 2
	tampered[flipAt] ^= 0x01
	if _, err := DecryptAttachment(tampered, m, dk); err == nil {
		t.Fatal("expected error for tampered chunk")
	}
	// Corrupt the frame length prefix instead.
	tampered2 := bytes.Clone(blob)
	tampered2[0] ^= 0xff
	if _, err := DecryptAttachment(tampered2, m, dk); err == nil {
		t.Fatal("expected error for corrupted frame header")
	}
}

func TestAttachmentTruncatedRejected(t *testing.T) {
	addr, pub, priv := testRecipient(t)
	plain := randomBytes(t, 600*1024)
	m, blob, err := EncryptAttachment(plain, "f.bin", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := UnwrapDataKey(m.Keys[0], priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{1, 10, 1000, len(blob) / 2} {
		if _, err := DecryptAttachment(blob[:len(blob)-cut], m, dk); err == nil {
			t.Fatalf("expected error for blob truncated by %d bytes", cut)
		}
	}
}

func TestAttachmentHashMismatchRejected(t *testing.T) {
	addr, pub, priv := testRecipient(t)
	plain := randomBytes(t, 1024)
	m, blob, err := EncryptAttachment(plain, "f.bin", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := UnwrapDataKey(m.Keys[0], priv)
	if err != nil {
		t.Fatal(err)
	}
	// The chunk authenticates, but the manifest hash no longer matches a
	// spliced plaintext: simulate by lying in the manifest.
	m.SHA256 = strings.Repeat("0", 64)
	if _, err := DecryptAttachment(blob, m, dk); err == nil {
		t.Fatal("expected error for SHA256 mismatch")
	}
}

func TestAttachmentWrongDataKeyRejected(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	plain := randomBytes(t, 1024)
	m, blob, err := EncryptAttachment(plain, "f.bin", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	var wrongKey [32]byte
	if _, err := rand.Read(wrongKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptAttachment(blob, m, wrongKey); err == nil {
		t.Fatal("expected error for wrong data key")
	}
}

func TestAttachmentNonRecipientCannotUnwrap(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	_, _, strangerPriv := testRecipient(t)
	plain := randomBytes(t, 1024)
	m, _, err := EncryptAttachment(plain, "f.bin", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDataKey(m.Keys[0], strangerPriv); err == nil {
		t.Fatal("expected unwrap failure for non-recipient")
	}
}

func TestAttachmentFilenameSanitized(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	m, _, err := EncryptAttachment([]byte("x"), "/tmp/../evil.txt", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	if m.Filename != "evil.txt" {
		t.Fatalf("filename not sanitized: %q", m.Filename)
	}
	if err := envelope.ValidateManifest(&m); err != nil {
		t.Fatalf("sanitized manifest invalid: %v", err)
	}
}

func TestValidateManifestRejectsBad(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	m, _, err := EncryptAttachment([]byte("hello"), "f.txt", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*envelope.AttachmentManifest){
		"path separator": func(x *envelope.AttachmentManifest) { x.Filename = "a/b" },
		"empty filename": func(x *envelope.AttachmentManifest) { x.Filename = "" },
		"bad size":       func(x *envelope.AttachmentManifest) { x.Size = -1 },
		"bad chunks":     func(x *envelope.AttachmentManifest) { x.Chunks++ },
		"bad blob id":    func(x *envelope.AttachmentManifest) { x.BlobID = "nope" },
		"bad sha":        func(x *envelope.AttachmentManifest) { x.SHA256 = "zz" },
		"no keys":        func(x *envelope.AttachmentManifest) { x.Keys = nil },
	}
	for name, mutate := range cases {
		bad := m
		mutate(&bad)
		if err := envelope.ValidateManifest(&bad); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}

func TestMessagePayloadRoundTrip(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	m, _, err := EncryptAttachment([]byte("data"), "f.txt", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	body, manifests, rinfo, exp, _ := parseMessagePayload(mustMarshal(t, messagePayload{Version: 1, Body: "hi", Attachments: []envelope.AttachmentManifest{m}}))
	if body != "hi" || len(manifests) != 1 || manifests[0].Filename != "f.txt" || exp != 0 {
		t.Fatalf("payload not parsed: %q %+v exp=%d", body, manifests, exp)
	}
	if rinfo.To != 0 || rinfo.Quote != "" {
		t.Fatalf("v1 payload must not carry reply metadata: %+v", rinfo)
	}
	// Legacy raw text is untouched, even if it looks vaguely like JSON.
	for _, raw := range []string{"hello world", `{"v":1}`, `{"v":1,"body":"x"}`, "\x00\x01 binary"} {
		b, ms, r, exp, _ := parseMessagePayload([]byte(raw))
		if b != raw || len(ms) != 0 || r.To != 0 || exp != 0 {
			t.Fatalf("raw text %q misparsed", raw)
		}
	}
	// issue #53: a TTL-only payload (no attachments) parses the body
	// and expiry; old clients see this as raw JSON (message preserved).
	ttlBody, ttlMs, _, ttlExp, _ := parseMessagePayload(mustMarshal(t, messagePayload{Version: 1, Body: "vanish", ExpiresAt: 1893456000}))
	if ttlBody != "vanish" || len(ttlMs) != 0 || ttlExp != 1893456000 {
		t.Fatalf("ttl payload not parsed: %q %+v exp=%d", ttlBody, ttlMs, ttlExp)
	}
	// TTL composes with attachments.
	attBody, attMs, _, attExp, _ := parseMessagePayload(mustMarshal(t, messagePayload{Version: 1, Body: "hi", Attachments: []envelope.AttachmentManifest{m}, ExpiresAt: 42}))
	if attBody != "hi" || len(attMs) != 1 || attExp != 42 {
		t.Fatalf("ttl+attachment payload not parsed: %q %+v exp=%d", attBody, attMs, attExp)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
