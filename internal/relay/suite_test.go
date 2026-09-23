package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// Issue #138: the relay must fail closed on crypto-suite problems — an
// unknown suite or a suite that disagrees with the sender's address suite
// is a 400, never silent v1 handling.

func TestSendSuiteValidation(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	// Absent suite (older client): accepted as SuiteV1.
	env := makeEnvelope(t, alice, bob, "no suite field")
	if rec := postSend(t, srv, env); rec.Code != http.StatusCreated {
		t.Fatalf("absent suite: got %d, body %s", rec.Code, rec.Body.String())
	}

	// Explicit matching suite: accepted and persisted.
	env = makeEnvelope(t, alice, bob, "explicit v1")
	env["suite"] = string(crypto.SuiteV1)
	if rec := postSend(t, srv, env); rec.Code != http.StatusCreated {
		t.Fatalf("matching suite: got %d, body %s", rec.Code, rec.Body.String())
	}

	// Unknown suite: rejected before any address agreement is checked.
	env = makeEnvelope(t, alice, bob, "unknown suite")
	env["suite"] = "pq-hybrid-v1"
	rec := postSend(t, srv, env)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown suite: got %d, want 400", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "unknown crypto suite") {
		t.Fatalf("unknown suite: body %q does not name the failure", body)
	}

	// Address with an unknown suite prefix: rejected at address parse —
	// the relay never reaches suite agreement with an unparseable party.
	env = makeEnvelope(t, alice, bob, "bad prefix")
	env["from"] = "pq:" + env["from"].(string)[len("ed25519:"):]
	if rec := postSend(t, srv, env); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown address prefix: got %d, want 400", rec.Code)
	}

	// Note: the true suite/address mismatch branch — wire suite and
	// address suite both known but disagreeing — is inexpressible at
	// the relay level while only SuiteV1 is registered. It is covered
	// for real in internal/crypto's TestAgreeSuite, which registers a
	// second suite and asserts the loud "does not match" refusal.
}

func TestKeyAnnounceSuiteValidation(t *testing.T) {
	srv := testServer(t)
	id, _ := crypto.GenerateIdentity()

	// Absent suite: accepted as SuiteV1.
	if w := postKeys(t, srv, makeAnnouncement(t, id, 1000)); w.Code != http.StatusCreated {
		t.Fatalf("absent suite announce: got %d, body %s", w.Code, w.Body.String())
	}
	// Explicit SuiteV1: accepted.
	ann := makeAnnouncement(t, id, 1001)
	ann["suite"] = string(crypto.SuiteV1)
	if w := postKeys(t, srv, ann); w.Code != http.StatusCreated {
		t.Fatalf("v1 suite announce: got %d, body %s", w.Code, w.Body.String())
	}
	// Unknown suite: rejected.
	ann = makeAnnouncement(t, id, 1002)
	ann["suite"] = "pq-hybrid-v1"
	if w := postKeys(t, srv, ann); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown suite announce: got %d, want 400", w.Code)
	}

	// Lookup echoes the stored suite.
	addr := crypto.FormatAddress(id.EdPub[:])
	lreq := httptest.NewRequest("GET", "/v1/keys/"+addr, nil)
	lw := httptest.NewRecorder()
	srv.Routes().ServeHTTP(lw, lreq)
	if lw.Code != http.StatusOK {
		t.Fatalf("lookup: got %d", lw.Code)
	}
	var out struct {
		Suite string `json:"suite"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Suite != string(crypto.SuiteV1) {
		t.Fatalf("lookup suite = %q, want %q", out.Suite, crypto.SuiteV1)
	}
}
