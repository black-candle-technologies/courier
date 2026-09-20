package client

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/envelope"
)

// legacyParseMessagePayload is a frozen copy of the pre-#51
// parseMessagePayload (v0.10.0): anything that is not a v1 payload
// carrying attachments renders as raw text. It pins the old-client
// backward-compatibility contract: a v2 reply must never choke an old
// client, only degrade to JSON-as-text.
func legacyParseMessagePayload(plain []byte) (string, []envelope.AttachmentManifest) {
	var p messagePayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return string(plain), nil
	}
	if p.Version != 1 || len(p.Attachments) == 0 {
		return string(plain), nil
	}
	return p.Body, p.Attachments
}

func TestReplyPayloadRoundTrip(t *testing.T) {
	raw, err := encodeReplyPayload("yes, 3 works", 42, "want to sync at 3?", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, manifests, r := parseMessagePayload(raw)
	if body != "yes, 3 works" {
		t.Fatalf("body = %q", body)
	}
	if len(manifests) != 0 {
		t.Fatalf("manifests = %+v", manifests)
	}
	if r.To != 42 || r.Quote != "want to sync at 3?" {
		t.Fatalf("reply info = %+v", r)
	}
}

func TestReplyPayloadWithAttachments(t *testing.T) {
	addr, pub, _ := testRecipient(t)
	m, _, err := EncryptAttachment([]byte("data"), "f.txt", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeReplyPayload("see attached", 7, "send the report", []envelope.AttachmentManifest{m})
	if err != nil {
		t.Fatal(err)
	}
	body, manifests, r := parseMessagePayload(raw)
	if body != "see attached" || len(manifests) != 1 || manifests[0].Filename != "f.txt" {
		t.Fatalf("body/manifests not parsed: %q %+v", body, manifests)
	}
	if r.To != 7 || r.Quote != "send the report" {
		t.Fatalf("reply info = %+v", r)
	}
}

func TestReplyPayloadValidation(t *testing.T) {
	// Negative reply_to normalizes to "not a reply", never an error.
	raw, _ := encodeReplyPayload("hi", -3, "x", nil)
	if _, _, r := parseMessagePayload(raw); r.To != 0 {
		t.Fatalf("negative reply_to not normalized: %+v", r)
	}
	// Unknown versions fall back to raw text.
	for _, v := range []string{`{"v":99,"body":"hi","reply_to":1}`, `{"v":0}`, `not json`} {
		b, ms, r := parseMessagePayload([]byte(v))
		if b != v || len(ms) != 0 || r.To != 0 {
			t.Fatalf("payload %q misparsed: %q %+v %+v", v, b, ms, r)
		}
	}
	// v1 with a foreign reply_to field: v1 semantics frozen, ignored.
	b, ms, r := parseMessagePayload([]byte(`{"v":1,"body":"hi","reply_to":9,"attachments":[]}`))
	if b != `{"v":1,"body":"hi","reply_to":9,"attachments":[]}` || len(ms) != 0 || r.To != 0 {
		t.Fatalf("v1+reply_to not treated as raw text: %q %+v %+v", b, ms, r)
	}
}

func TestOldClientToleratesV2Reply(t *testing.T) {
	// The old (pre-#51) parser must never choke on a v2 reply: it
	// renders the JSON as chat text, preserving the message content.
	raw, err := encodeReplyPayload("yes, 3 works", 42, "want to sync at 3?", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, manifests := legacyParseMessagePayload(raw)
	if body != string(raw) {
		t.Fatalf("old client did not fall back to raw text: %q", body)
	}
	if len(manifests) != 0 {
		t.Fatalf("old client parsed manifests: %+v", manifests)
	}
	if !strings.Contains(body, "yes, 3 works") {
		t.Fatalf("old client lost the message body: %q", body)
	}
}

func TestEncodeMessageBodyWireChoice(t *testing.T) {
	// Plain message: legacy raw text, byte-identical.
	raw, err := encodeMessageBody("hello", nil, 0, "")
	if err != nil || string(raw) != "hello" {
		t.Fatalf("plain = %q, %v", raw, err)
	}
	// Attachment-only: legacy v1, byte-identical to the old marshal.
	addr, pub, _ := testRecipient(t)
	m, _, err := EncryptAttachment([]byte("data"), "f.txt", pub, addr)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = encodeMessageBody("hi", []envelope.AttachmentManifest{m}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Version int `json:"v"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Version != 1 {
		t.Fatalf("attachment-only must stay v1: %s", raw)
	}
	// Also parseable by the old client as a structured payload.
	if body, ms := legacyParseMessagePayload(raw); body != "hi" || len(ms) != 1 {
		t.Fatalf("old client misparsed v1 attachments: %q %+v", body, ms)
	}
	// Reply: v2.
	raw, err = encodeMessageBody("re: hi", nil, 42, "hi")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Version != 2 {
		t.Fatalf("reply must be v2: %s", raw)
	}
	// Reply with attachments: v2 carrying both.
	raw, err = encodeMessageBody("re: docs", []envelope.AttachmentManifest{m}, 42, "send docs")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Version != 2 {
		t.Fatalf("reply+attachments must be v2: %s", raw)
	}
	body, ms, r := parseMessagePayload(raw)
	if body != "re: docs" || len(ms) != 1 || r.To != 42 || r.Quote != "send docs" {
		t.Fatalf("v2 reply+attachments misparsed: %q %+v %+v", body, ms, r)
	}
}

func TestTruncateQuote(t *testing.T) {
	if q := truncateQuote("  hello\n  world  "); q != "hello world" {
		t.Fatalf("whitespace not collapsed: %q", q)
	}
	long := strings.Repeat("a", maxReplyQuoteLen+100)
	if q := truncateQuote(long); len(q) != maxReplyQuoteLen {
		t.Fatalf("long quote not bounded: len %d", len(q))
	}
	// Multibyte safety: no broken rune at the cut. "é" is 2 bytes, so
	// a 500-byte cap holds 250 of them, never a half-rune.
	uni := strings.Repeat("é", maxReplyQuoteLen+10)
	q = truncateQuote(uni)
	if q != strings.Repeat("é", maxReplyQuoteLen/2) {
		t.Fatalf("unicode quote mangled: %q", q)
	}
}

func TestReplyCacheRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeReplyCache([]replyCacheEntry{
		{CourierID: 1, From: "ed25519:a", Snippet: "one", SentAt: 10},
		{CourierID: 2, From: "ed25519:b", Snippet: "two", SentAt: 20},
	})
	got := readReplyCache()
	if len(got) != 2 || got[0].Snippet != "one" || got[1].Snippet != "two" {
		t.Fatalf("cache = %+v", got)
	}
	// Newest record wins on id collision.
	writeReplyCache([]replyCacheEntry{{CourierID: 1, From: "ed25519:a", Snippet: "one-updated", SentAt: 30}})
	got = readReplyCache()
	if len(got) != 2 {
		t.Fatalf("cache len = %d", len(got))
	}
	for _, e := range got {
		if e.CourierID == 1 && e.Snippet != "one-updated" {
			t.Fatalf("dedup failed: %+v", got)
		}
	}
}

func TestReplyCacheCap(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var entries []replyCacheEntry
	for i := int64(1); i <= maxReplyCache+50; i++ {
		entries = append(entries, replyCacheEntry{CourierID: i, From: "x", Snippet: "s", SentAt: i})
	}
	writeReplyCache(entries)
	if got := readReplyCache(); len(got) != maxReplyCache {
		t.Fatalf("cache len = %d, want %d", len(got), maxReplyCache)
	}
}

func TestLookupReplyParent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// Sent log first.
	if err := appendSentLog(SentEntry{CourierID: 100, To: "ed25519:b", Body: "my outbound parent", SentAt: 1}); err != nil {
		t.Fatal(err)
	}
	writeReplyCache([]replyCacheEntry{{CourierID: 200, From: "ed25519:c", Snippet: "inbound parent", SentAt: 2}})
	if q, ok := LookupReplyParent(100); !ok || q != "my outbound parent" {
		t.Fatalf("sent log lookup: %q %v", q, ok)
	}
	if q, ok := LookupReplyParent(200); !ok || q != "inbound parent" {
		t.Fatalf("cache lookup: %q %v", q, ok)
	}
	if _, ok := LookupReplyParent(999); ok {
		t.Fatal("unknown parent reported found")
	}
	if _, ok := LookupReplyParent(0); ok {
		t.Fatal("zero id reported found")
	}
	// Missing files: no error, just not found.
	t.Setenv("HOME", t.TempDir())
	if _, ok := LookupReplyParent(100); ok {
		t.Fatal("lookup succeeded with no state")
	}
}
