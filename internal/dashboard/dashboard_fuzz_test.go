package dashboard

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/store"
)

// FuzzLoginForm feeds arbitrary request bodies to the dashboard login
// form parser (POST /login -> handleLogin: r.ParseForm, CSRF/Origin
// gate, username / password extraction, user lookup, failed-login
// render). The login form is the dashboard's most exposed
// unauthenticated surface.
// Invariants: never panic; the handler always answers with a
// well-formed, non-empty response — 200 (login page re-render), 400
// (unparseable form), 403 (CSRF/Origin rejection, issue #111), or 429
// (rate limit, issue #108) — never a bare 500 or an empty reply — and
// handling is deterministic for the same body.
//
// Each request carries a valid double-submit CSRF pair (issue #111)
// so the fuzzer reaches the form parsing and credential-lookup paths
// instead of stopping at the CSRF gate.
//
// Note: with no registered users the lookup fails before bcrypt runs,
// so this stays fast; the bcrypt comparison path itself is covered by
// the existing login unit tests.
func FuzzLoginForm(f *testing.F) {
	f.Add([]byte(`username=alice&password=correct-horse-battery-staple`))
	f.Add([]byte(``)) // empty body
	f.Add([]byte(`username=`))
	f.Add([]byte(`password=only-password`))
	f.Add([]byte(`username=%zz&password=%zz`))              // bad percent-encoding
	f.Add([]byte("username=a\x00b&password=c"))             // NUL bytes
	f.Add([]byte(strings.Repeat("a", 100000)))              // large body
	f.Add([]byte(`username=alice&username=bob&password=x`)) // repeated keys
	f.Add([]byte("not a form at all {{{"))
	f.Fuzz(func(t *testing.T, body []byte) {
		st, err := store.Open(t.TempDir() + "/test.db")
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		srv := &Server{store: st}
		// Valid double-submit CSRF pair for this iteration: the form
		// field and the cookie must match (constant-time compare in
		// the handler). base64url is form-safe, so it can be appended
		// to any body.
		var rb [32]byte
		if _, err := rand.Read(rb[:]); err != nil {
			t.Fatal(err)
		}
		csrf := base64.RawURLEncoding.EncodeToString(rb[:])
		doPost := func(b []byte) *httptest.ResponseRecorder {
			full := make([]byte, 0, len(b)+len(csrf)+16)
			full = append(full, b...)
			full = append(full, '&')
			full = append(full, csrfField...)
			full = append(full, '=')
			full = append(full, csrf...)
			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(full))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: loginCSRFCookie, Value: csrf})
			rec := httptest.NewRecorder()
			srv.handleLogin(rec, req)
			return rec
		}
		rec := doPost(body)
		switch rec.Code {
		case http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests:
		default:
			t.Fatalf("handleLogin(%q): unexpected status %d", body, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("handleLogin(%q): empty response body", body)
		}
		if rec2 := doPost(body); rec2.Code != rec.Code {
			t.Fatalf("handleLogin(%q): non-deterministic status %d then %d", body, rec.Code, rec2.Code)
		}
	})
}
