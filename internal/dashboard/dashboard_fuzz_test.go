package dashboard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/store"
)

// FuzzLoginForm feeds arbitrary request bodies to the dashboard login
// form parser (POST /login -> handleLogin: r.ParseForm, username /
// password extraction, user lookup, failed-login render). The login
// form is the dashboard's most exposed unauthenticated surface.
// Invariants: never panic; the handler always answers 200 (login page
// re-render) or 400 (unparseable form) — never a bare 500 or an empty
// reply — and handling is deterministic for the same body.
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
		doPost := func(b []byte) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			srv.handleLogin(rec, req)
			return rec
		}
		rec := doPost(body)
		if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
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
