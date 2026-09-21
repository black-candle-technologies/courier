package bridge

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestSetBodyCapOverridesDefault(t *testing.T) {
	f := newGwFixture(t)
	if f.gw.bodyCap != DefaultBodyCap {
		t.Fatalf("default bodyCap = %d, want %d", f.gw.bodyCap, DefaultBodyCap)
	}
	f.gw.SetBodyCap(128 * 1024)
	// A 96 KiB body now passes the size gate (confirmation comes first).
	big := strings.Repeat("a", 96*1024)
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, big, ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("96KiB body with raised cap: code = %d, want 449", rec.Code)
	}
	// Status reports the overridden cap.
	req := httptest.NewRequest(http.MethodGet, "/v1/bridge/status", nil)
	req.Header.Set("Authorization", "Bearer "+f.raw)
	srec := httptest.NewRecorder()
	f.gw.Routes().ServeHTTP(srec, req)
	var st struct {
		BodyCapBytes int `json:"body_cap_bytes"`
	}
	if err := json.Unmarshal(srec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.BodyCapBytes != 128*1024 {
		t.Fatalf("status body_cap_bytes = %d, want %d", st.BodyCapBytes, 128*1024)
	}
	// Non-positive values keep the existing cap.
	f.gw.SetBodyCap(0)
	f.gw.SetBodyCap(-5)
	if f.gw.bodyCap != 128*1024 {
		t.Fatalf("bodyCap after non-positive SetBodyCap = %d, want 131072", f.gw.bodyCap)
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

// TestConfirmTokenBoundToBody (F1): a confirm token is bound to the
// body it was issued for. Approving body A must not authorize sending
// body B.
func TestConfirmTokenBoundToBody(t *testing.T) {
	f := newGwFixture(t)
	// First send → 449 with a confirm token for body "hello".
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("first send code = %d, want 449", rec.Code)
	}
	var cr map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	ct, _ := cr["confirm_token"].(string)
	if ct == "" {
		t.Fatal("no confirm_token in 449")
	}
	// Replay the token with a DIFFERENT body → must be rejected, not sent.
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "evil", ct))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched-body confirm: code = %d, want 400", rec.Code)
	}
	if len(f.stub.calls) != 0 {
		t.Fatalf("sender called %d times; mismatched body must not send", len(f.stub.calls))
	}
	// The token was single-use: even the originally approved body now fails.
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reused confirm token: code = %d, want 400", rec.Code)
	}
	// And the recipient was never marked confirmed.
	confirmed, err := f.store.IsConfirmed(f.tok.ID, f.addr)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		t.Fatal("recipient marked confirmed after mismatched-body attempt")
	}
}

// TestUnauthenticatedFloodLimited (F4): unauthenticated attempts are
// audit-logged up to the pre-auth budget; beyond it they get 429 with
// no audit row.
func TestUnauthenticatedFloodLimited(t *testing.T) {
	f := newGwFixture(t)
	f.gw.preAuth = NewPreAuthLimiter(3)
	var codes []int
	for i := 0; i < 5; i++ {
		rec := f.ingest(t, "bad-token", ingestJSON(f.addr, "x", ""))
		codes = append(codes, rec.Code)
	}
	for i, c := range codes[:3] {
		if c != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d, want 401", i, c)
		}
	}
	for i, c := range codes[3:] {
		if c != http.StatusTooManyRequests {
			t.Fatalf("attempt %d: code = %d, want 429", i+3, c)
		}
	}
	rows, err := f.store.ListAudit(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	n401 := 0
	for _, r := range rows {
		if r.Outcome == RejectedOutcome(RejectUnauthorized) {
			n401++
		}
	}
	if n401 != 3 {
		t.Fatalf("unauthorized audit rows = %d, want 3 (429s must not write rows)", n401)
	}
}

// TestDisclosureMentionsAllPlaintextHops (F7): the short disclosure
// must name every plaintext hop, including the MCP server.
func TestDisclosureMentionsAllPlaintextHops(t *testing.T) {
	for _, hop := range []string{"MCP server", "bridge gateway", "OpenAI"} {
		if !strings.Contains(DisclosureText, hop) {
			t.Errorf("DisclosureText missing plaintext hop %q", hop)
		}
	}
}

// blockingSender is a Sender whose first two SendBridged calls block
// until both are in flight. That forces the exact interleaving that
// used to fork the audit chain under the old reserve-then-rewrite
// design: reserve A -> append B -> finalize A (issue #81).
type blockingSender struct {
	firstIn  chan struct{}
	secondIn chan struct{}
	release  chan struct{}
	once1    sync.Once
	once2    sync.Once
	mu       sync.Mutex
	calls    int
	next     int64
}

func (b *blockingSender) SendBridged(address, wrappedBody string, meta *client.BridgeMeta) (int64, error) {
	b.mu.Lock()
	b.calls++
	n := b.calls
	b.mu.Unlock()
	if n == 1 {
		b.once1.Do(func() { close(b.firstIn) })
	} else {
		b.once2.Do(func() { close(b.secondIn) })
	}
	<-b.release
	b.mu.Lock()
	b.next++
	id := b.next
	b.mu.Unlock()
	return id, nil
}

// TestIngestConcurrentSendsChainVerifies (issue #81): two concurrent
// confirmed sends interleave as reserve A -> reserve B -> finalize A ->
// finalize B in some order. The audit chain must still verify, and
// every send_reserved event must pair with exactly one completion
// event linked via SendRef.
func TestIngestConcurrentSendsChainVerifies(t *testing.T) {
	s := testStore(t)
	addr1, addr2 := testAddr(101), testAddr(102)
	raw, tok, err := s.IssueToken("fixture", []string{addr1, addr2}, 0, "test-pepper")
	if err != nil {
		t.Fatal(err)
	}
	bs := &blockingSender{
		firstIn:  make(chan struct{}),
		secondIn: make(chan struct{}),
		release:  make(chan struct{}),
	}
	gw := NewGateway(s, bs, "test-pepper", "ed25519:bridge", bytes.Repeat([]byte{7}, 32), "test")
	// Pre-confirm both recipients so the concurrent ingests go straight
	// to the send path (confirmation is orthogonal to this test).
	now := time.Now().Unix()
	for _, addr := range []string{addr1, addr2} {
		if err := s.MarkConfirmed(tok.ID, addr, now); err != nil {
			t.Fatal(err)
		}
	}
	recs := make([]*httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i, addr := range []string{addr1, addr2} {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/bridge/ingest",
				bytes.NewReader([]byte(ingestJSON(addr, "hello", ""))))
			req.Header.Set("Authorization", "Bearer "+raw)
			rec := httptest.NewRecorder()
			gw.Routes().ServeHTTP(rec, req)
			recs[i] = rec
		}(i, addr)
	}
	// Both sends are now in flight, which means both send_reserved rows
	// are appended. Release them so the completion events interleave.
	<-bs.firstIn
	<-bs.secondIn
	close(bs.release)
	wg.Wait()
	for i, rec := range recs {
		if rec == nil || rec.Code != http.StatusOK {
			t.Fatalf("ingest %d: code = %v, want 200", i, rec)
		}
	}
	ok, _, _, err := s.VerifyAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("audit chain forked under concurrent sends")
	}
	rows, err := s.ListAudit(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	reserved := map[int64]bool{}
	for _, r := range rows {
		if r.Outcome == OutcomeSendReserved {
			reserved[r.ID] = true
		}
	}
	var sent int
	for _, r := range rows {
		switch r.Outcome {
		case OutcomeSendReserved:
			// collected above
		case OutcomeSent:
			sent++
			if r.EnvelopeID == 0 {
				t.Fatal("sent row missing envelope id")
			}
			id, err := strconv.ParseInt(r.SendRef, 10, 64)
			if err != nil || !reserved[id] {
				t.Fatalf("sent row references unknown reserved row %q", r.SendRef)
			}
		default:
			t.Fatalf("unexpected outcome %q", r.Outcome)
		}
	}
	if len(reserved) != 2 || sent != 2 {
		t.Fatalf("reserved=%d sent=%d, want 2 and 2", len(reserved), sent)
	}
}

// TestConfirmTokenConcurrentConsumeSingleUse (issue #84): N concurrent
// ingests presenting the SAME confirm token must collapse to exactly
// one consuming send. Validation+consumption is a single atomic
// DELETE ... RETURNING, so exactly one ingest wins the token; the rest
// get 400 and nothing is sent twice.
func TestConfirmTokenConcurrentConsumeSingleUse(t *testing.T) {
	f := newGwFixture(t)
	// 449 round-trip to mint a confirm token for body "hello".
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("first send code = %d, want 449", rec.Code)
	}
	var cr map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	ct, _ := cr["confirm_token"].(string)
	if ct == "" {
		t.Fatal("no confirm_token in 449")
	}
	const n = 16
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
			codes[i] = r.Code
		}(i)
	}
	wg.Wait()
	var ok200, bad400 int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok200++
		case http.StatusBadRequest:
			bad400++
		default:
			t.Fatalf("unexpected code %d", c)
		}
	}
	if ok200 != 1 || bad400 != n-1 {
		t.Fatalf("ok200=%d bad400=%d, want 1 and %d", ok200, bad400, n-1)
	}
	if len(f.stub.calls) != 1 {
		t.Fatalf("sender called %d times, want exactly 1", len(f.stub.calls))
	}
}

// confirmTokenFor mints a confirm token for (addr, body) via the 449
// round-trip and returns it.
func confirmTokenFor(t *testing.T, f *gwFixture, addr, body string) string {
	t.Helper()
	rec := f.ingest(t, f.raw, ingestJSON(addr, body, ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("first send code = %d, want 449", rec.Code)
	}
	var cr map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &cr)
	ct, _ := cr["confirm_token"].(string)
	if ct == "" {
		t.Fatal("no confirm_token in 449")
	}
	return ct
}

// TestConfirmNotMarkedWhenSendFails (issue #83): a confirmed token
// whose approved first send FAILS must not leave the recipient
// confirmed — fail closed. A later different body must require a fresh
// confirmation (449), not sail through.
func TestConfirmNotMarkedWhenSendFails(t *testing.T) {
	f := newGwFixture(t)
	f.stub.err = errTestSend
	ct := confirmTokenFor(t, f, f.addr, "hello")
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("confirmed send code = %d, want 502", rec.Code)
	}
	confirmed, err := f.store.IsConfirmed(f.tok.ID, f.addr)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		t.Fatal("recipient marked confirmed although the approved first send failed")
	}
	// A different body still requires confirmation.
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "different body", ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("different body code = %d, want 449", rec.Code)
	}
}

// TestConfirmNotMarkedWhenRateLimited (issue #83): a confirmed token
// whose approved first send is RATE-LIMITED must not leave the
// recipient confirmed either. Draining the minute bucket forces the
// 429; the later different body must get 449.
func TestConfirmNotMarkedWhenRateLimited(t *testing.T) {
	f := newGwFixture(t)
	for i := 0; i < RateBurst; i++ {
		f.gw.limiter.Allow(f.tok.ID)
	}
	ct := confirmTokenFor(t, f, f.addr, "hello")
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("confirmed send code = %d, want 429", rec.Code)
	}
	confirmed, err := f.store.IsConfirmed(f.tok.ID, f.addr)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		t.Fatal("recipient marked confirmed although the approved first send was rate-limited")
	}
	rec = f.ingest(t, f.raw, ingestJSON(f.addr, "different body", ""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("different body code = %d, want 449", rec.Code)
	}
}

const errTestAudit = testErr("audit boom")

// TestSendAuditFailureSurfaced (issue #85): if the send-completion
// audit event cannot be appended, the failure must surface as a
// non-2xx (not a silent 200), and the failure is logged with the
// reserved audit id. The message WAS delivered — the sender stub must
// show exactly one call.
func TestSendAuditFailureSurfaced(t *testing.T) {
	f := newGwFixture(t)
	ct := confirmTokenFor(t, f, f.addr, "hello")
	f.store.appendAuditFail = func(e *AuditEntry) error {
		if e.Outcome == OutcomeSent {
			return errTestAudit
		}
		return nil
	}
	rec := f.ingest(t, f.raw, ingestJSON(f.addr, "hello", ct))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500 on audit failure", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "audit_failed") {
		t.Fatalf("body %q missing audit_failed", rec.Body.String())
	}
	if len(f.stub.calls) != 1 {
		t.Fatalf("sender called %d times, want 1 (message was delivered)", len(f.stub.calls))
	}
	// The rows that did land still form a valid chain.
	if ok, _, _, err := f.store.VerifyAudit(); err != nil || !ok {
		t.Fatalf("audit verify: %v %v", err, ok)
	}
}

// TestAuditHelperFailureDoesNotBreakResponse (issue #85): the audit()
// helper is best-effort, but its failures must be logged rather than
// silently discarded — and must not change the HTTP response. With
// every append failing, an unauthenticated ingest still gets its 401.
func TestAuditHelperFailureDoesNotBreakResponse(t *testing.T) {
	f := newGwFixture(t)
	f.store.appendAuditFail = func(e *AuditEntry) error { return errTestAudit }
	rec := f.ingest(t, "bogus", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

// TestIngestCallerRecordedInAudit (issue #94): the caller identity the
// MCP server asserts is recorded on every audit row of the ingest
// (confirmation, reserve, completion) and the chain still verifies.
func TestIngestCallerRecordedInAudit(t *testing.T) {
	f := newGwFixture(t)
	body := func(confirm string) string {
		m := map[string]string{"recipient": f.addr, "body": "hello", "caller": "someone@example.com"}
		if confirm != "" {
			m["confirm_token"] = confirm
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	rec := f.ingest(t, f.raw, body(""))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("first send code = %d, want 449", rec.Code)
	}
	var cr map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatal(err)
	}
	ct, _ := cr["confirm_token"].(string)
	rec = f.ingest(t, f.raw, body(ct))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed send code = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	rows, err := f.store.ListAudit(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("audit rows = %d, want 3 (confirmation_requested, send_reserved, sent)", len(rows))
	}
	for _, r := range rows {
		if r.Caller != "someone@example.com" {
			t.Fatalf("row %d (%s) caller = %q, want someone@example.com", r.ID, r.Outcome, r.Caller)
		}
	}
	if ok, _, _, err := f.store.VerifyAudit(); err != nil || !ok {
		t.Fatalf("audit verify: %v %v", err, ok)
	}
}

// TestIngestCallerSanitized: an overlong asserted caller is truncated,
// never stored unbounded, and a rejected ingest records the caller
// too.
func TestIngestCallerSanitized(t *testing.T) {
	f := newGwFixture(t)
	long := strings.Repeat("a", 300) + "@example.com"
	m := map[string]string{"recipient": f.addr, "body": "hello", "caller": long}
	b, _ := json.Marshal(m)
	rec := f.ingest(t, f.raw, string(b))
	if rec.Code != StatusConfirmationRequired {
		t.Fatalf("code = %d, want 449", rec.Code)
	}
	rows, err := f.store.ListAudit(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if len(rows[0].Caller) != maxAuditCallerLen {
		t.Fatalf("caller len = %d, want truncation to %d", len(rows[0].Caller), maxAuditCallerLen)
	}
	// Rejected ingests record the caller as well.
	rec = f.ingest(t, f.raw, ingestJSON("ed25519:unallowlisted", "hi", ""))
	_ = rec
	rows, err = f.store.ListAudit(AuditFilter{Outcome: "rejected:not_allowlisted"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rejected rows = %d, want 1", len(rows))
	}
	if rows[0].Caller != "" {
		t.Fatalf("rejected row caller = %q, want empty (no caller asserted)", rows[0].Caller)
	}
}

// TestAuditCallerMigration: a pre-#94 bridge.db without the caller
// column migrates on open, keeps verifying, and accepts new rows with
// callers.
func TestAuditCallerMigration(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bridge.db"
	// Build an old-schema database by hand: audit table without the
	// caller column, one pre-existing row.
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendAudit(&AuditEntry{Ts: 1, TokenID: "t", TokenLabel: "old", Outcome: OutcomeSent}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := removeAuditCallerColumn(path); err != nil {
		t.Fatal(err)
	}
	// Reopen: the migration must add the column back.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen after dropping caller column: %v", err)
	}
	defer s2.Close()
	if ok, checked, _, err := s2.VerifyAudit(); err != nil || !ok || checked != 1 {
		t.Fatalf("verify after migration: ok=%v checked=%d err=%v", ok, checked, err)
	}
	id, err := s2.AppendAudit(&AuditEntry{Ts: 2, TokenID: "t", TokenLabel: "new",
		Outcome: OutcomeSent, Caller: "someone@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s2.ListAudit(AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != id || rows[0].Caller != "someone@example.com" || rows[1].Caller != "" {
		t.Fatalf("bad rows after migration: %+v", rows)
	}
	if ok, _, _, err := s2.VerifyAudit(); err != nil || !ok {
		t.Fatalf("verify after new row: %v %v", err, ok)
	}
}

// removeAuditCallerColumn drops the caller column to simulate a
// pre-#94 database file.
func removeAuditCallerColumn(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`ALTER TABLE audit DROP COLUMN caller`)
	return err
}
