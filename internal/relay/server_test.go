package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

var b64 = base64.RawURLEncoding

func testServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st)
}

// makeEnvelope builds a correctly signed envelope from sender to recipient.
func makeEnvelope(t *testing.T, sender, recipient *crypto.Identity, body string) map[string]any {
	t.Helper()
	toEd := recipient.EdPub
	toX, err := crypto.Ed25519PubToX25519(toEd[:])
	if err != nil {
		t.Fatal(err)
	}
	eph, nonce, ct, err := crypto.Seal(&toX, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	sentAt := time.Now().Unix()
	sig := sender.Sign(envelope.Canonical(toEd[:], sender.EdPub[:], eph, nonce, sentAt, ct))
	return map[string]any{
		"to":      crypto.FormatAddress(toEd[:]),
		"from":    crypto.FormatAddress(sender.EdPub[:]),
		"eph":     b64.EncodeToString(eph),
		"nonce":   b64.EncodeToString(nonce),
		"ct":      b64.EncodeToString(ct),
		"sent_at": sentAt,
		"sig":     b64.EncodeToString(sig),
	}
}

func postSend(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/send", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestSendAndInboxRoundtrip(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	rec := postSend(t, srv, makeEnvelope(t, alice, bob, "hello bob"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d, body %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest("GET", signedInboxURL(t, bob, 0, 50), nil)
	inrec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(inrec, req)
	if inrec.Code != http.StatusOK {
		t.Fatalf("inbox: got %d", inrec.Code)
	}
	var out struct {
		Messages []struct {
			From string `json:"from"`
			Sig  string `json:"sig"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(inrec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 1 {
		t.Fatalf("want 1 message, got %d", len(out.Messages))
	}
	if out.Messages[0].From != crypto.FormatAddress(alice.EdPub[:]) {
		t.Fatal("wrong from")
	}
	if out.Messages[0].Sig == "" {
		t.Fatal("sig missing from inbox response")
	}
}

func TestRejectsTamperedSignature(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	env := makeEnvelope(t, alice, bob, "hello")
	sig, _ := b64.DecodeString(env["sig"].(string))
	sig[0] ^= 0xff // corrupt one byte
	env["sig"] = b64.EncodeToString(sig)

	rec := postSend(t, srv, env)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for tampered sig, got %d", rec.Code)
	}
}

func TestRejectsImpersonatedFrom(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	mallory, _ := crypto.GenerateIdentity()

	// Mallory signs correctly with HER key but claims to be Alice.
	env := makeEnvelope(t, mallory, bob, "i am alice, trust me")
	env["from"] = crypto.FormatAddress(alice.EdPub[:])

	rec := postSend(t, srv, env)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for impersonated from, got %d", rec.Code)
	}
}

func TestRejectsMissingSig(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	env := makeEnvelope(t, alice, bob, "hello")
	delete(env, "sig")

	rec := postSend(t, srv, env)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing sig, got %d", rec.Code)
	}
}

func TestRejectsLegacyAddress(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	env := makeEnvelope(t, alice, bob, "hello")
	// Strip the ed25519: prefix -> legacy-style bare key.
	env["to"] = env["to"].(string)[len(crypto.AddressPrefix):]

	rec := postSend(t, srv, env)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for legacy address, got %d", rec.Code)
	}
}

// ---- v0.5.0: key directory ----

func makeAnnouncement(t *testing.T, id *crypto.Identity, epoch int64) map[string]any {
	t.Helper()
	pub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	sig := id.Sign(envelope.KeyAnnounce(id.EdPub[:], pub[:], epoch))
	return map[string]any{
		"address":    crypto.FormatAddress(id.EdPub[:]),
		"x25519_pub": b64.EncodeToString(pub[:]),
		"epoch":      epoch,
		"sig":        b64.EncodeToString(sig),
	}
}

func postKeys(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/keys", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	return w
}

func TestKeyAnnounceRoundtrip(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	ann := makeAnnouncement(t, id, 1000)
	if w := postKeys(t, srv, ann); w.Code != http.StatusCreated {
		t.Fatalf("announce: got %d, body %s", w.Code, w.Body.String())
	}
	addr := crypto.FormatAddress(id.EdPub[:])
	req := httptest.NewRequest("GET", "/v1/keys/"+addr, nil)
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("lookup: got %d", w.Code)
	}
	var out struct {
		Address   string `json:"address"`
		X25519Pub string `json:"x25519_pub"`
		Epoch     int64  `json:"epoch"`
		Sig       string `json:"sig"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Address != addr || out.X25519Pub != ann["x25519_pub"] || out.Epoch != 1000 {
		t.Fatalf("lookup mismatch: %+v", out)
	}
	// F1: the signed announcement must round-trip so senders can verify it.
	if out.Sig != ann["sig"] {
		t.Fatalf("lookup did not return the announcement signature")
	}
}

func TestKeyAnnounceStaleEpochRejected(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	if w := postKeys(t, srv, makeAnnouncement(t, id, 2000)); w.Code != http.StatusCreated {
		t.Fatalf("first announce: got %d", w.Code)
	}
	// Older epoch must be rejected (replay protection).
	if w := postKeys(t, srv, makeAnnouncement(t, id, 1500)); w.Code != http.StatusConflict {
		t.Fatalf("stale announce: got %d, want 409", w.Code)
	}
	// Newer epoch replaces.
	if w := postKeys(t, srv, makeAnnouncement(t, id, 2001)); w.Code != http.StatusCreated {
		t.Fatalf("newer announce: got %d", w.Code)
	}
}

func TestKeyAnnounceBadSigRejected(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	other, _ := crypto.GenerateIdentity()
	ann := makeAnnouncement(t, id, 3000)
	// Re-sign with a different key: must fail verification.
	pub, _, _ := crypto.GenerateX25519Keypair()
	ann["sig"] = b64.EncodeToString(other.Sign(envelope.KeyAnnounce(id.EdPub[:], pub[:], 3000)))
	if w := postKeys(t, srv, ann); w.Code != http.StatusBadRequest {
		t.Fatalf("forged announce: got %d, want 400", w.Code)
	}
}

func TestKeyLookupMissing(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	addr := crypto.FormatAddress(id.EdPub[:])
	req := httptest.NewRequest("GET", "/v1/keys/"+addr, nil)
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing key: got %d, want 404", w.Code)
	}
}

func TestSendReplayIsIdempotent(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	body := makeEnvelope(t, alice, bob, "hello bob")

	first := postSend(t, srv, body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first send: got %d", first.Code)
	}
	var f struct {
		ID        int64 `json:"id"`
		Duplicate bool  `json:"duplicate"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f.Duplicate {
		t.Fatal("first send reported duplicate")
	}

	// Replaying the identical envelope must be acknowledged with the
	// original id, not stored twice.
	second := postSend(t, srv, body)
	if second.Code != http.StatusCreated {
		t.Fatalf("replay send: got %d", second.Code)
	}
	var s struct {
		ID        int64 `json:"id"`
		Duplicate bool  `json:"duplicate"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if !s.Duplicate || s.ID != f.ID {
		t.Fatalf("replay not idempotent: %+v vs %+v", s, f)
	}

	req := httptest.NewRequest("GET", signedInboxURL(t, bob, 0, 50), nil)
	inrec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(inrec, req)
	var out struct {
		Messages []struct {
			ID int64 `json:"id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(inrec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 1 || out.Messages[0].ID != f.ID {
		t.Fatalf("want exactly the original message, got %+v", out.Messages)
	}
}

func TestInboxPageBoundedByBytes(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	// Ten large envelopes (~190 KiB plaintext each, ~260 KiB encoded —
	// near the 256 KiB per-message cap, within the send body limit). A
	// count-bounded page of 200 such messages would far exceed the
	// client's 8 MiB read limit; the byte bound must split them across
	// pages.
	const n = 10
	bigBody := strings.Repeat("x", 190*1024)
	for i := 0; i < n; i++ {
		if rec := postSend(t, srv, makeEnvelope(t, alice, bob, bigBody)); rec.Code != http.StatusCreated {
			t.Fatalf("send %d: got %d", i, rec.Code)
		}
	}

	var total, pages int
	var after int64
	for {
		req := httptest.NewRequest("GET", signedInboxURL(t, bob, after, 200), nil)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("inbox: got %d", rec.Code)
		}
		if len(rec.Body.Bytes()) > MaxInboxPageBytes {
			t.Fatalf("page %d: %d bytes exceeds the %d-byte bound",
				pages, len(rec.Body.Bytes()), MaxInboxPageBytes)
		}
		var out struct {
			Messages []struct {
				ID int64 `json:"id"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Messages) == 0 {
			break
		}
		pages++
		total += len(out.Messages)
		after = out.Messages[len(out.Messages)-1].ID
		if pages > n+1 {
			t.Fatal("pagination did not terminate")
		}
	}
	if total != n {
		t.Fatalf("got %d messages across pages, want %d", total, n)
	}
	if pages < 2 {
		t.Fatalf("expected multiple pages for large envelopes, got %d", pages)
	}
}

// signedInboxURL builds a /v1/inbox URL carrying a valid recipient
// signature (v0.6.11 F10).
func signedInboxURL(t *testing.T, id *crypto.Identity, after int64, limit int) string {
	t.Helper()
	ts := time.Now().Unix()
	sig := id.Sign(envelope.InboxRequest(id.EdPub[:], after, int64(limit), ts))
	return fmt.Sprintf("/v1/inbox?to=%s&after=%d&limit=%d&ts=%d&sig=%s",
		crypto.FormatAddress(id.EdPub[:]), after, limit, ts, b64.EncodeToString(sig))
}

func inboxStatus(t *testing.T, srv *Server, rawURL string) int {
	t.Helper()
	req := httptest.NewRequest("GET", rawURL, nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec.Code
}

func TestInboxRejectsUnsigned(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	u := "/v1/inbox?to=" + crypto.FormatAddress(id.EdPub[:]) + "&after=0&limit=50"
	if code := inboxStatus(t, srv, u); code != http.StatusBadRequest {
		t.Fatalf("unsigned inbox request: got %d, want 400", code)
	}
}

func TestInboxRejectsForgedSignature(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	// Request for bob's inbox, signed by alice's key.
	ts := time.Now().Unix()
	sig := alice.Sign(envelope.InboxRequest(bob.EdPub[:], 0, 50, ts))
	u := fmt.Sprintf("/v1/inbox?to=%s&after=0&limit=50&ts=%d&sig=%s",
		crypto.FormatAddress(bob.EdPub[:]), ts, b64.EncodeToString(sig))
	if code := inboxStatus(t, srv, u); code != http.StatusUnauthorized {
		t.Fatalf("forged inbox signature: got %d, want 401", code)
	}
}

func TestInboxRejectsStaleTimestamp(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	ts := time.Now().Unix() - 600
	sig := id.Sign(envelope.InboxRequest(id.EdPub[:], 0, 50, ts))
	u := fmt.Sprintf("/v1/inbox?to=%s&after=0&limit=50&ts=%d&sig=%s",
		crypto.FormatAddress(id.EdPub[:]), ts, b64.EncodeToString(sig))
	if code := inboxStatus(t, srv, u); code != http.StatusBadRequest {
		t.Fatalf("stale inbox timestamp: got %d, want 400", code)
	}
}

func TestInboxRejectsFutureTimestamp(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	ts := time.Now().Unix() + 600
	sig := id.Sign(envelope.InboxRequest(id.EdPub[:], 0, 50, ts))
	u := fmt.Sprintf("/v1/inbox?to=%s&after=0&limit=50&ts=%d&sig=%s",
		crypto.FormatAddress(id.EdPub[:]), ts, b64.EncodeToString(sig))
	if code := inboxStatus(t, srv, u); code != http.StatusBadRequest {
		t.Fatalf("future inbox timestamp: got %d, want 400", code)
	}
}

func TestInboxRejectsTamperedCursor(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()
	ts := time.Now().Unix()
	// Signed for after=0, requested with after=5.
	sig := id.Sign(envelope.InboxRequest(id.EdPub[:], 0, 50, ts))
	u := fmt.Sprintf("/v1/inbox?to=%s&after=5&limit=50&ts=%d&sig=%s",
		crypto.FormatAddress(id.EdPub[:]), ts, b64.EncodeToString(sig))
	if code := inboxStatus(t, srv, u); code != http.StatusUnauthorized {
		t.Fatalf("tampered inbox cursor: got %d, want 401", code)
	}
}
