// Tests for the bridge audit admin view (issue #95).
package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/bridge"
	"github.com/black-candle-technologies/courier/internal/store"
)

// fakeGateway serves the gateway's read-only audit API with the
// expected bearer token, so the dashboard view can be tested without
// bridge.db.
func fakeGateway(t *testing.T, token string) *httptest.Server {
	t.Helper()
	rows := []bridge.AuditAdminRow{
		{ID: 2, Ts: 1700000001, TokenLabel: "lane-chatgpt", Recipient: "ed25519:recipient1",
			BodySHA256: "aabbccddeeff00112233", BodySize: 42, Outcome: bridge.OutcomeSent, EnvelopeID: 7},
		{ID: 1, Ts: 1700000000, TokenLabel: "lane-chatgpt", Recipient: "ed25519:recipient2",
			BodySHA256: "00112233445566778899", BodySize: 13, Outcome: bridge.RejectedOutcome(bridge.RejectRateLimited),
			Reason: "rate limit exceeded"},
	}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("/v1/bridge/audit", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "rows": rows})
	})
	mux.HandleFunc("/v1/bridge/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bridge.AuditAdminVerify{OK: true, ChainOK: true, Checked: 2, FirstID: 1})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// auditTestServer builds a dashboard server wired to a fake gateway,
// with one admin and one ordinary user, and returns their cookies.
func auditTestServer(t *testing.T, gwURL string) (*Server, *http.Cookie, *http.Cookie) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := NewFull(st, BCTOAuthConfig{}, DefaultAuthLimits(), BridgeAuditConfig{URL: gwURL, AdminToken: "gw-admin-token"})
	mkuser := func(username string, admin bool) *http.Cookie {
		t.Helper()
		id := testIdentity(t)
		register(t, srv, username, "a-temporary-password-1", id)
		if admin {
			ok, err := st.SetDashboardAdmin(username, true)
			if err != nil || !ok {
				t.Fatalf("set-admin: ok=%v err=%v", ok, err)
			}
		}
		// Complete the forced password change, then log in.
		c0 := login(t, srv, username, "a-temporary-password-1")
		form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}
		rec := postChangePassword(t, srv, c0, form)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("change-password: got %d: %s", rec.Code, rec.Body.String())
		}
		return loginFromRec(t, rec).session
	}
	return srv, mkuser("admin-user", true), mkuser("plain-user", false)
}

func TestBridgeAuditAdminOnly(t *testing.T) {
	gw := fakeGateway(t, "gw-admin-token")
	srv, adminCookie, plainCookie := auditTestServer(t, gw.URL)

	// Ordinary user: 403.
	rec := get(t, srv, "/admin/bridge/audit", plainCookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: got %d, want 403", rec.Code)
	}
	// Logged out: redirect to login.
	rec = get(t, srv, "/admin/bridge/audit", nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logged out: got %d, want 303", rec.Code)
	}
	// Admin: 200 with the rows and the verify banner.
	rec = get(t, srv, "/admin/bridge/audit", adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin: got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"lane-chatgpt",          // token label
		"aabbccddeeff",          // body sha prefix
		"rejected:rate_limited", // outcome
		"Audit chain verified",  // verify banner
		"rate limit exceeded",   // rejection reason
		"Metadata only",         // disclosure footer
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin page missing %q", want)
		}
	}
	// The audit view must not leak the gateway admin token into the page.
	if strings.Contains(body, "gw-admin-token") {
		t.Fatal("admin page leaks the gateway admin token")
	}
}

func TestBridgeAuditDormant(t *testing.T) {
	// No BridgeAuditConfig: the route must not be registered. The
	// app's catch-all "/" serves the login page instead (existing
	// behavior for unknown paths), never the audit view.
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st)
	rec := get(t, srv, "/admin/bridge/audit", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("dormant logged-out: got %d, want 200 (login page)", rec.Code)
	}
	for _, forbidden := range []string{"/v1/bridge/audit", "Audit chain verified"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("dormant page renders audit content: %q", forbidden)
		}
	}
	// Half-configured (URL without token): still dormant. A logged-in
	// admin gets the catch-all redirect to /app, never the audit view.
	srv = NewFull(st, BCTOAuthConfig{}, DefaultAuthLimits(), BridgeAuditConfig{URL: "http://127.0.0.1:8473"})
	// Reuse an admin login against the dormant server.
	id := testIdentity(t)
	register(t, srv, "ops2", "a-temporary-password-1", id)
	c0 := login(t, srv, "ops2", "a-temporary-password-1")
	form := url.Values{"password": {"a-new-password-123"}, "confirm": {"a-new-password-123"}}
	r2 := postChangePassword(t, srv, c0, form)
	cookie := loginFromRec(t, r2).session
	rec = get(t, srv, "/admin/bridge/audit", cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("dormant logged-in: got %d, want 303 to /app", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Bridge audit</h1>") {
		t.Fatal("dormant route rendered the audit view")
	}
}

func TestBridgeAuditGatewayDown(t *testing.T) {
	// Gateway unreachable: the admin gets an error page, not a crash.
	srv, adminCookie, _ := auditTestServer(t, "http://127.0.0.1:1")
	rec := get(t, srv, "/admin/bridge/audit", adminCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 with error banner", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Could not load audit rows") {
		t.Fatalf("missing gateway-error banner: %s", rec.Body.String())
	}
}

func TestBridgeAuditNavLink(t *testing.T) {
	gw := fakeGateway(t, "gw-admin-token")
	srv, adminCookie, plainCookie := auditTestServer(t, gw.URL)

	// Admin sees the Bridge audit link on /app.
	rec := get(t, srv, "/app", adminCookie)
	if !strings.Contains(rec.Body.String(), "/admin/bridge/audit") {
		t.Fatal("admin /app missing Bridge audit link")
	}
	// Ordinary user does not.
	rec = get(t, srv, "/app", plainCookie)
	if strings.Contains(rec.Body.String(), "/admin/bridge/audit") {
		t.Fatal("non-admin /app leaks the Bridge audit link")
	}
}

func TestSetDashboardAdmin(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// Unknown user: false, no error.
	ok, err := st.SetDashboardAdmin("nobody", true)
	if err != nil || ok {
		t.Fatalf("unknown user: ok=%v err=%v", ok, err)
	}
	// Register via the store directly.
	u, err := st.CreateDashboardUser("ops", "$2a$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"ed25519:x", "tokhash")
	if err != nil {
		t.Fatal(err)
	}
	if u.IsAdmin {
		t.Fatal("new user must not be admin by default")
	}
	ok, err = st.SetDashboardAdmin("ops", true)
	if err != nil || !ok {
		t.Fatalf("grant: ok=%v err=%v", ok, err)
	}
	got, err := st.DashboardUserByName("ops")
	if err != nil || !got.IsAdmin {
		t.Fatalf("grant not visible: %+v err=%v", got, err)
	}
	ok, err = st.SetDashboardAdmin("ops", false)
	if err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	got, err = st.DashboardUserByName("ops")
	if err != nil || got.IsAdmin {
		t.Fatalf("revoke not visible: %+v err=%v", got, err)
	}
}
