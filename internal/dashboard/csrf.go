package dashboard

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

// Synchronizer CSRF tokens for the dashboard's state-changing forms
// (issue #111).
//
// Two token flavors:
//  1. Session-bound tokens for authenticated forms (change password,
//     logout, unlink BCT): a random token is minted at session creation
//     and stored raw on the dashboard_sessions row. Templates render it
//     from the session row (looked up by the session cookie), and the
//     POST must submit the same value — compared in constant time.
//     There is no second cookie: the session cookie alone identifies
//     the session, and the token in the database is the single source
//     of truth. Sessions created before CSRF tokens existed have an
//     empty token: reads keep working, but state-changing POSTs fail
//     closed until the user logs in again.
//  2. Double-submit cookie for the pre-login form (POST /login): the
//     login page sets an HttpOnly cookie (courier_login_csrf) and
//     renders the same value into the form; the POST must carry both
//     and they must match. This closes login-CSRF without requiring a
//     server-side session before authentication.
//
// Origin/Referer validation runs as defense-in-depth on every
// state-changing POST: when the header is present it must be an
// http(s) URL whose host matches the request host; requests carrying
// neither header still pass (the token is the primary control).
//
// The OAuth BCT flow's single-use state parameter is a different
// control (it binds the provider redirect to the in-flight
// authorization) and is intentionally not conflated with these tokens.

const (
	// loginCSRFCookie is the pre-login double-submit CSRF cookie.
	loginCSRFCookie = "courier_login_csrf"
	// csrfField is the hidden form field name in every protected form.
	csrfField = "csrf_token"
)

// newCSRFToken generates a fresh random CSRF token: 32 bytes, unpadded
// base64url.
func newCSRFToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// ensureLoginCSRF returns the pre-login CSRF token for this browser,
// setting the cookie when it is missing or malformed.
func ensureLoginCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(loginCSRFCookie); err == nil && validTokenShape(c.Value) {
		return c.Value
	}
	token, err := newCSRFToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginCSRFCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // dashboard is TLS-only
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func clearLoginCSRF(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Path: "/", MaxAge: -1})
}

// validTokenShape is a cheap sanity check on token-shaped strings: 43
// chars of unpadded base64url (32 random bytes).
func validTokenShape(s string) bool {
	if len(s) != 43 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// checkLoginCSRF validates the double-submit token on POST /login: the
// form field and the cookie must both be present and equal.
func checkLoginCSRF(r *http.Request) bool {
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	submitted := r.FormValue(csrfField)
	if submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(c.Value)) == 1
}

// sessionTokenHash digests a raw session token the way the sessions
// table stores it.
func sessionTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// checkSessionCSRF validates the synchronizer token on an authenticated
// POST: the submitted token must match the token stored on the caller's
// session row, compared in constant time. A token minted for another
// session — or a session that predates CSRF tokens — fails closed.
func (s *Server) checkSessionCSRF(r *http.Request) bool {
	submitted := r.FormValue(csrfField)
	if submitted == "" || !validTokenShape(submitted) {
		return false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	want, err := s.store.SessionCSRFToken(sessionTokenHash(c.Value))
	if err != nil || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(want)) == 1
}

// checkOrigin validates Origin (falling back to Referer) as
// defense-in-depth: when either header is present it must be an http or
// https URL whose host matches the request host. Requests carrying
// neither header pass — the CSRF token remains the primary control,
// and some legitimate clients omit both.
func checkOrigin(r *http.Request) bool {
	raw := r.Header.Get("Origin")
	if raw == "" {
		raw = r.Header.Get("Referer")
	}
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// csrfTokenForSession returns the session-bound synchronizer token to
// render into a form, read from the caller's session row. Empty when
// the request carries no usable session (e.g. a session created before
// CSRF tokens existed): such sessions keep working for reads, but
// state-changing POSTs fail closed until the user re-authenticates.
func (s *Server) csrfTokenForSession(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return ""
	}
	token, err := s.store.SessionCSRFToken(sessionTokenHash(c.Value))
	if err != nil {
		return ""
	}
	return token
}
