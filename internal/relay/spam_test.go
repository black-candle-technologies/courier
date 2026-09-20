package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

// spamTestServer builds a server with custom abuse-control tuning.
func spamTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewWithConfig(st, cfg)
}

// generousSpamConfig removes rate limits so report-flow tests exercise
// only the reporter throttle.
func generousSpamConfig() Config {
	c := DefaultConfig()
	c.SendBurst = 100000
	c.SendRatePerSec = 100000
	return c
}

// postReport files a signed spam report and returns the response.
func postReport(t *testing.T, srv *Server, reporter *crypto.Identity, envelopeID int64) *httptest.ResponseRecorder {
	t.Helper()
	ts := time.Now().Unix()
	sig := reporter.Sign(envelope.SpamReport(reporter.EdPub[:], envelopeID, ts))
	return postReportRaw(t, srv, map[string]any{
		"reporter":    crypto.FormatAddress(reporter.EdPub[:]),
		"envelope_id": envelopeID,
		"ts":          ts,
		"sig":         b64.EncodeToString(sig),
	})
}

func postReportRaw(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/report", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func sendID(t *testing.T, srv *Server, from, to *crypto.Identity) int64 {
	t.Helper()
	rec := postSend(t, srv, makeEnvelope(t, from, to, "hello"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

func TestSendRateLimitEnforced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SendBurst = 2
	cfg.SendRatePerSec = 0 // no refill: deterministic
	srv := spamTestServer(t, cfg)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	for i := 0; i < 2; i++ {
		if rec := postSend(t, srv, makeEnvelope(t, alice, bob, "burst")); rec.Code != http.StatusCreated {
			t.Fatalf("burst send %d: got %d, want 201", i+1, rec.Code)
		}
	}
	rec := postSend(t, srv, makeEnvelope(t, alice, bob, "over the burst"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-burst send: got %d, want 429", rec.Code)
	}
	var er struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &er); err != nil || er.Error == "" {
		t.Fatal("429 response must carry a visible error message")
	}

	// Limits are per-sender: another sender is unaffected.
	carol, _ := crypto.GenerateIdentity()
	if rec := postSend(t, srv, makeEnvelope(t, carol, bob, "hi")); rec.Code != http.StatusCreated {
		t.Fatalf("other sender: got %d, want 201", rec.Code)
	}
}

func TestSpamReportFlowAndAuth(t *testing.T) {
	srv := spamTestServer(t, generousSpamConfig())
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	carol, _ := crypto.GenerateIdentity()

	id := sendID(t, srv, alice, bob)

	// The recipient can report.
	if rec := postReport(t, srv, bob, id); rec.Code != http.StatusOK {
		t.Fatalf("recipient report: got %d, body %s", rec.Code, rec.Body.String())
	}
	// A duplicate report is idempotent, not an error.
	if rec := postReport(t, srv, bob, id); rec.Code != http.StatusOK {
		t.Fatalf("duplicate report: got %d, want 200", rec.Code)
	}
	// A non-recipient cannot report someone else's message.
	if rec := postReport(t, srv, carol, id); rec.Code != http.StatusForbidden {
		t.Fatalf("non-recipient report: got %d, want 403", rec.Code)
	}
	// A forged signature is rejected.
	ts := time.Now().Unix()
	badSig := postReportRaw(t, srv, map[string]any{
		"reporter":    crypto.FormatAddress(bob.EdPub[:]),
		"envelope_id": id,
		"ts":          ts,
		"sig":         b64.EncodeToString(make([]byte, 64)),
	})
	if badSig.Code != http.StatusUnauthorized {
		t.Fatalf("forged report sig: got %d, want 401", badSig.Code)
	}
	// An unknown envelope id is a 404, not a report against nothing.
	if rec := postReport(t, srv, bob, 999999); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown envelope: got %d, want 404", rec.Code)
	}
	// A stale timestamp is rejected (replay protection).
	staleSig := bob.Sign(envelope.SpamReport(bob.EdPub[:], id, ts-3600))
	stale := postReportRaw(t, srv, map[string]any{
		"reporter":    crypto.FormatAddress(bob.EdPub[:]),
		"envelope_id": id,
		"ts":          ts - 3600,
		"sig":         b64.EncodeToString(staleSig),
	})
	if stale.Code != http.StatusBadRequest {
		t.Fatalf("stale report ts: got %d, want 400", stale.Code)
	}
}

func TestDistinctReporterThrottle(t *testing.T) {
	cfg := generousSpamConfig()
	cfg.SpamReportThreshold = 2
	cfg.SpamReportWindow = time.Hour
	srv := spamTestServer(t, cfg)
	alice, _ := crypto.GenerateIdentity() // the spammer
	bob, _ := crypto.GenerateIdentity()
	carol, _ := crypto.GenerateIdentity()
	dave, _ := crypto.GenerateIdentity()

	id1 := sendID(t, srv, alice, bob)
	id2 := sendID(t, srv, alice, carol)

	// One distinct reporter is below the threshold: sends still flow.
	if rec := postReport(t, srv, bob, id1); rec.Code != http.StatusOK {
		t.Fatalf("report 1: got %d", rec.Code)
	}
	if rec := postSend(t, srv, makeEnvelope(t, alice, dave, "still fine")); rec.Code != http.StatusCreated {
		t.Fatalf("one reporter: got %d, want 201", rec.Code)
	}

	// A second distinct reporter hits the threshold: throttled.
	if rec := postReport(t, srv, carol, id2); rec.Code != http.StatusOK {
		t.Fatalf("report 2: got %d", rec.Code)
	}
	rec := postSend(t, srv, makeEnvelope(t, alice, dave, "throttled"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("two distinct reporters: got %d, want 429", rec.Code)
	}

	// Throttling is per-sender: an innocent sender is unaffected.
	if rec := postSend(t, srv, makeEnvelope(t, bob, dave, "hi")); rec.Code != http.StatusCreated {
		t.Fatalf("innocent sender: got %d, want 201", rec.Code)
	}
}

// TestInboxSenderFlags: the inbox response carries machine-readable
// sender-reputation flags (metadata-only, advisory) so recipients can
// triage message requests.
func TestInboxSenderFlags(t *testing.T) {
	cfg := generousSpamConfig()
	cfg.SpamReportThreshold = 1
	cfg.SpamReportWindow = time.Hour
	cfg.SendBurst = 2
	cfg.SendRatePerSec = 0 // no refill: the bucket stays exhausted
	srv := spamTestServer(t, cfg)
	alice, _ := crypto.GenerateIdentity() // reported + rate-limited
	bob, _ := crypto.GenerateIdentity()
	carol, _ := crypto.GenerateIdentity()

	sendID(t, srv, alice, bob)
	idCarol := sendID(t, srv, alice, carol) // exhausts alice's burst of 2
	if rec := postReport(t, srv, carol, idCarol); rec.Code != http.StatusOK {
		t.Fatalf("report: got %d", rec.Code)
	}
	_ = idCarol // silence unused

	fetch := func(who *crypto.Identity) []struct {
		From        string   `json:"from"`
		SenderFlags []string `json:"sender_flags"`
	} {
		t.Helper()
		req := httptest.NewRequest("GET", signedInboxURL(t, who, 0, 50), nil)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("inbox: got %d", rec.Code)
		}
		var out struct {
			Messages []struct {
				From        string   `json:"from"`
				SenderFlags []string `json:"sender_flags"`
			} `json:"messages"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Messages
	}

	aliceAddr := crypto.FormatAddress(alice.EdPub[:])
	msgs := fetch(bob)
	if len(msgs) != 1 || msgs[0].From != aliceAddr {
		t.Fatalf("want alice's message in bob's inbox, got %+v", msgs)
	}
	has := func(flags []string, want string) bool {
		for _, f := range flags {
			if f == want {
				return true
			}
		}
		return false
	}
	if !has(msgs[0].SenderFlags, "reported") {
		t.Fatalf("want reported flag, got %v", msgs[0].SenderFlags)
	}
	if !has(msgs[0].SenderFlags, "rate_limited") {
		t.Fatalf("want rate_limited flag, got %v", msgs[0].SenderFlags)
	}

	// An innocent sender carries no flags.
	quiet, _ := crypto.GenerateIdentity()
	sendID(t, srv, quiet, bob)
	msgs = fetch(bob)
	for _, m := range msgs {
		if m.From == crypto.FormatAddress(quiet.EdPub[:]) && len(m.SenderFlags) != 0 {
			t.Fatalf("innocent sender must carry no flags, got %v", m.SenderFlags)
		}
	}
}
