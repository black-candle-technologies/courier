package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	req := httptest.NewRequest("GET", "/v1/inbox?to="+crypto.FormatAddress(bob.EdPub[:]), nil)
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
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Address != addr || out.X25519Pub != ann["x25519_pub"] || out.Epoch != 1000 {
		t.Fatalf("lookup mismatch: %+v", out)
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
