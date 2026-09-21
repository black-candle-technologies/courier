// Tests for the read-only admin audit API (issue #95).
package bridge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newAdminFixture(t *testing.T) *gwFixture {
	t.Helper()
	f := newGwFixture(t)
	f.gw.SetAdminToken("admin-secret-token")
	// Seed a couple of audit rows with distinct labels/outcomes.
	mustAppend := func(e *AuditEntry) {
		t.Helper()
		if _, err := f.store.AppendAudit(e); err != nil {
			t.Fatal(err)
		}
	}
	mustAppend(&AuditEntry{Ts: 1000, TokenID: "t1", TokenLabel: "lane-chatgpt", Recipient: f.addr,
		BodySHA256: "aa", BodySize: 12, Outcome: OutcomeSent, EnvelopeID: 7})
	mustAppend(&AuditEntry{Ts: 1001, TokenID: "t1", TokenLabel: "lane-chatgpt", Recipient: f.addr,
		BodySHA256: "bb", BodySize: 13, Outcome: RejectedOutcome(RejectRateLimited)})
	mustAppend(&AuditEntry{Ts: 1002, TokenID: "t2", TokenLabel: "other", Recipient: f.addr,
		BodySHA256: "cc", BodySize: 14, Outcome: OutcomeSent, EnvelopeID: 8})
	return f
}

func (f *gwFixture) auditGet(t *testing.T, bearer, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.gw.Routes().ServeHTTP(rec, req)
	return rec
}

func TestAuditAPIDormantWithoutToken(t *testing.T) {
	f := newGwFixture(t) // no SetAdminToken: API dormant
	for _, path := range []string{"/v1/bridge/audit", "/v1/bridge/audit/verify"} {
		rec := f.auditGet(t, "anything", path)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404 when admin token unconfigured", path, rec.Code)
		}
	}
}

func TestAuditAPIRequiresAuth(t *testing.T) {
	f := newAdminFixture(t)
	for _, bearer := range []string{"", "wrong-token"} {
		rec := f.auditGet(t, bearer, "/v1/bridge/audit")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bearer %q: got %d, want 401", bearer, rec.Code)
		}
		rec = f.auditGet(t, bearer, "/v1/bridge/audit/verify")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bearer %q (verify): got %d, want 401", bearer, rec.Code)
		}
	}
}

func TestAuditAPIList(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.auditGet(t, "admin-secret-token", "/v1/bridge/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		OK   bool            `json:"ok"`
		Rows []AuditAdminRow `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || len(out.Rows) != 3 {
		t.Fatalf("want 3 rows, got %+v", out.Rows)
	}
	// Newest first.
	if out.Rows[0].TokenLabel != "other" || out.Rows[2].TokenLabel != "lane-chatgpt" {
		t.Fatalf("wrong order: %+v", out.Rows)
	}
	// Metadata only: token secrets and chain internals are not in the
	// JSON shape at all.
	raw := rec.Body.String()
	for _, forbidden := range []string{"token_id", "prev_hash", "row_hash"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("response leaks %q: %s", forbidden, raw)
		}
	}
	if out.Rows[2].EnvelopeID != 7 || out.Rows[2].BodySHA256 != "aa" {
		t.Fatalf("row fields wrong: %+v", out.Rows[2])
	}
}

func TestAuditAPIFilters(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.auditGet(t, "admin-secret-token", "/v1/bridge/audit?token_label=lane-chatgpt")
	var out struct {
		Rows []AuditAdminRow `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rows) != 2 {
		t.Fatalf("label filter: want 2 rows, got %d", len(out.Rows))
	}
	rec = f.auditGet(t, "admin-secret-token", "/v1/bridge/audit?outcome="+RejectedOutcome(RejectRateLimited))
	out.Rows = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rows) != 1 || out.Rows[0].Outcome != RejectedOutcome(RejectRateLimited) {
		t.Fatalf("outcome filter wrong: %+v", out.Rows)
	}
	rec = f.auditGet(t, "admin-secret-token", "/v1/bridge/audit?limit=1")
	out.Rows = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rows) != 1 {
		t.Fatalf("limit=1: want 1 row, got %d", len(out.Rows))
	}
	// Bad limit is a 400, not a silent clamp to default.
	rec = f.auditGet(t, "admin-secret-token", "/v1/bridge/audit?limit=bogus")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad limit: got %d, want 400", rec.Code)
	}
}

func TestAuditAPIVerify(t *testing.T) {
	f := newAdminFixture(t)
	rec := f.auditGet(t, "admin-secret-token", "/v1/bridge/audit/verify")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	var out AuditAdminVerify
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || !out.ChainOK || out.Checked != 3 {
		t.Fatalf("verify wrong: %+v", out)
	}
}
