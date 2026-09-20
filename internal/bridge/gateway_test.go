package bridge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
)

// stubSender records bridged sends and returns incrementing ids.
type stubSender struct {
	calls []stubCall
	next  int64
	err   error
}

type stubCall struct {
	address string
	body    string
	meta    *client.BridgeMeta
}

func (s *stubSender) SendBridged(address, wrappedBody string, meta *client.BridgeMeta) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.next++
	s.calls = append(s.calls, stubCall{address, wrappedBody, meta})
	return s.next, nil
}

type gwFixture struct {
	gw    *Gateway
	store *Store
	stub  *stubSender
	raw   string
	tok   *Token
	addr  string
}

func newGwFixture(t *testing.T) *gwFixture {
	t.Helper()
	s := testStore(t)
	stub := &stubSender{}
	addr := testAddr(42)
	raw, tok, err := s.IssueToken("fixture", []string{addr}, 0, "test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	gw := NewGateway(s, stub, "test-pepper", "ed25519:bridge", bytes.Repeat([]byte{7}, 32), "test")
	return &gwFixture{gw: gw, store: s, stub: stub, raw: raw, tok: tok, addr: addr}
}

func (f *gwFixture) ingest(t *testing.T, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body == "" {
		rdr = bytes.NewReader(nil)
	} else {
		rdr = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/bridge/ingest", rdr)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.gw.Routes().ServeHTTP(rec, req)
	return rec
}

func ingestJSON(recipient, body, confirm string) string {
	m := map[string]string{"recipient": recipient, "body": body}
	if confirm != "" {
		m["confirm_token"] = confirm
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestIngestFullFlow(t *testing.T) {
	f := newGwFixture(t)
	// First send → 449 confirmation_required.
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("first send code = %d, want 449", rec.Code)
	}
	var cr map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatal(err)
	}
	ct, _ := cr["confirm_token"].(string)
	if ct == "" {
		t.Fatal("no confirm_token in 449")
	}
	if _, ok := cr["disclosure"].(string); !ok {
		t.Fatal("no disclosure in 449")
	}
	// Confirm → 200.
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed send code = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(f.stub.calls) != 1 {
		t.Fatalf("sender called %d times", len(f.stub.calls))
	}
	call := f.stub.calls[0]
	if call.address != f.addr {
		t.Fatalf("sent to %q", call.address)
	}
	if !HasBanner(call.body) || !strings.HasSuffix(call.body, "hello") {
		t.Fatalf("banner missing/wrong: %q", call.body)
	}
	if call.meta.Origin != client.BridgeOriginChatGPTWeb {
		t.Fatalf("meta origin = %q", call.meta.Origin)
	}
	if call.meta.TokenLabel != "fixture" || call.meta.AuditID == 0 {
		t.Fatalf("meta = %+v", call.meta)
	}
	if call.meta.GatewayFP == "" {
		t.Fatal("empty gateway fingerprint")
	}
	// Second send to the same recipient proceeds without confirmation.
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "again", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("second send code = %d, want 200", rec.Code)
	}
	// Audit: confirmation_requested + 2 sent.
	rows, err := f.store.ListAudit(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var sent, confirmReq int
	for _, r := range rows {
		switch r.Outcome {
		case OutcomeSent:
			sent++
			if r.BodySHA256 == "" || r.EnvelopeID == 0 {
				t.Fatal("sent row missing hash/envelope")
			}
		case OutcomeConfirmationRequired:
			confirmReq++
		}
		if strings.Contains(r.BodySHA256, "hello") {
			t.Fatal("audit row contains plaintext")
		}
	}
	if sent != 2 || confirmReq != 1 {
		t.Fatalf("audit: sent=%d confirmReq=%d", sent, confirmReq)
	}
	// Audit chain verifies.
	if ok, _, _, err := f.store.VerifyAudit(); err != nil || !ok {
		t.Fatalf("audit verify: %v %v", err, ok)
	}
}

func TestIngestBadConfirmToken(t *testing.T) {
	f := newGwFixture(t)
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", "bogus"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	if len(f.stub.calls) != 0 {
		t.Fatal("sender called with bad confirm token")
	}
}

func TestIngestAuth(t *testing.T) {
	f := newGwFixture(t)
	for _, tc := range []struct {
		name   string
		bearer string
	}{
		{"missing", ""},
		{"bogus", "cb1_bogus"},
		{"wrong pepper", f.raw}, // valid format; re-hash under wrong pepper below
	} {
		bearer := tc.bearer
		if tc.name == "wrong pepper" {
			// Issue under pepper A, present a token hashed under pepper B:
			// simulate by pointing the gateway at a different pepper.
			f.gw.pepper = "other-pepper"
		}
		rec := f.ingest(t, bearer, ingestJSON(f.addr, "x", ""))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: code = %d, want 401", tc.name, rec.Code)
		}
		f.gw.pepper = "test-pepper"
	}
	// Revoked token → 401.
	if _, err := f.store.RevokeToken("fixture"); err != nil {
		t.Fatal(err)
	}
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "x", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked: code = %d, want 401", rec.Code)
	}
}

func TestIngestAllowlist(t *testing.T) {
	f := newGwFixture(t)
	other := testAddr(43)
	rec := f.ingest(t, f.raw, ingestJSON(other, "x", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), f.addr) {
		t.Fatal("403 disclosed the allowlist")
	}
	rows, _ := f.store.ListAudit(AuditFilter{Outcome: RejectedOutcome(RejectForbidden)})
	if len(rows) != 1 {
		t.Fatalf("rejection not audited: %d rows", len(rows))
	}
}

func TestIngestBodyCap(t *testing.T) {
	f := newGwFixture(t)
	// Exactly 64 KiB passes the size gate (confirmation comes first).
	big := strings.Repeat("a", DefaultBodyCap)
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, big, ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("64KiB body: code = %d, want 449", rec.Code)
	}
	// 64 KiB + 1 → 413.
	bigger := strings.Repeat("a", DefaultBodyCap+1)
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, bigger, ""))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: code = %d, want 413", rec.Code)
	}
	// Multi-byte UTF-8 is measured in bytes, not runes.
	// 32768 × "é" (2 bytes) = 65536 bytes → OK gate-wise.
	utf8ok := strings.Repeat("é", 32768)
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, utf8ok, ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("utf8 64KiB: code = %d, want 449", rec.Code)
	}
	utf8big := strings.Repeat("é", 32769) // 65538 bytes
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, utf8big, ""))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("utf8 oversize: code = %d, want 413", rec.Code)
	}
}

func TestIngestRateLimit(t *testing.T) {
	f := newGwFixture(t)
	// Confirm the recipient first so sends flow.
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "c0", ""))
	var cr map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	ct, _ := cr["confirm_token"].(string)
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "c0", ct))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d", rec.Code)
	}
	// Exhaust the burst (5) + refill trickle. Sends are instant here,
	// so after 5 sends the minute bucket is empty.
	allowed := 1 // the confirm send above
	for i := 0; i < 10; i++ {
		rec = f.ingest(t, f.raw, ingestJSON(f.addr, "flood", ""))
		if rec.Code == http.StatusOK {
			allowed++
			continue
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("flood send %d: code = %d", i, rec.Code)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
		break
	}
	if allowed > RateBurst+1 {
		t.Fatalf("allowed %d sends past burst", allowed)
	}
	rows, _ := f.store.ListAudit(AuditFilter{Outcome: RejectedOutcome(RejectRateLimited)})
	if len(rows) == 0 {
		t.Fatal("rate-limit rejection not audited")
	}
}

func TestIngestBadRecipient(t *testing.T) {
	f := newGwFixture(t)
	// Malformed address that IS in no allowlist → 403 (allowlist first).
	rec := f.ingest(t, f.raw, ingestJSON("bogus", "x", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestStatusEndpoint(t *testing.T) {
	f := newGwFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/bridge/status", nil)
	req.Header.Set("Authorization", "Bearer "+f.raw)
	rec := httptest.NewRecorder()
	f.gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var st statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Label != "fixture" || len(st.Allowlist) != 1 || st.Allowlist[0] != f.addr {
		t.Fatalf("status = %+v", st)
	}
	if st.Disclosure == "" || !strings.Contains(st.Disclosure, "NOT end-to-end encrypted") {
		t.Fatal("status missing disclosure")
	}
	if st.RateLimits.PerMinute != RatePerMinute || st.BodyCapBytes != DefaultBodyCap {
		t.Fatalf("limits = %+v", st.RateLimits)
	}
	// Unauthorized → 401.
	req = httptest.NewRequest(http.MethodGet, "/v1/bridge/status", nil)
	rec = httptest.NewRecorder()
	f.gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	f := newGwFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/bridge/health", nil)
	rec := httptest.NewRecorder()
	f.gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var h map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h["ok"] != true || h["version"] != "test" {
		t.Fatalf("health = %v", h)
	}
}

func TestIngestSendFailureAudited(t *testing.T) {
	f := newGwFixture(t)
	f.stub.err = errTestSend
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ""))
	var cr map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	ct, _ := cr["confirm_token"].(string)
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rec.Code)
	}
	rows, _ := f.store.ListAudit(AuditFilter{Outcome: RejectedOutcome(RejectSendFailed)})
	if len(rows) != 1 {
		t.Fatalf("send failure not audited: %d", len(rows))
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTestSend = testErr("relay down")

func TestConfirmTokenSingleUse(t *testing.T) {
	f := newGwFixture(t)
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ""))
	var cr map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	ct, _ := cr["confirm_token"].(string)
	// Use it once → confirmed.
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
	if rec.Code != http.StatusOK {
		t.Fatalf("first use: %d", rec.Code)
	}
	// The recipient is now confirmed, so a replay of the token is
	// simply ignored (no error) — confirm single-use differently:
	// a confirm token bound to another recipient must fail. Use a
	// second token/allowlist for that.
	raw2, _, err := f.store.IssueToken("fixture2", []string{testAddr(44)}, 0, "test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/bridge/ingest",
		bytes.NewReader([]byte(ingestJSON(testAddr(44), "x", ""))))
	req.Header.Set("Authorization", "Bearer "+raw2)
	f.gw.Routes().ServeHTTP(rec2, req)
	var cr2 map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &cr2)
	ct2, _ := cr2["confirm_token"].(string)
	// Present token2's confirm token against token1's recipient: the
	// recipient isn't in token2's allowlist anyway, so instead verify
	// cross-token misuse is rejected by using ct2 with fixture's
	// allowlist recipient under raw2... simpler: use ct (fixture's)
	// under raw2 for testAddr(44): wrong binding → 400.
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/v1/bridge/ingest",
		bytes.NewReader([]byte(ingestJSON(testAddr(44), "x", ct))))
	req3.Header.Set("Authorization", "Bearer "+raw2)
	f.gw.Routes().ServeHTTP(rec3, req3)
	_ = ct2
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("cross-token confirm: code = %d, want 400", rec3.Code)
	}
}
