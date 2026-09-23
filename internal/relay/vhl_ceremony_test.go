package relay

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

var vhlB64 = base64.RawURLEncoding

// vhlTestIdentity makes an identity and its address string.
func vhlTestIdentity(t *testing.T) (*crypto.Identity, string) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id, crypto.FormatAddress(id.EdPub[:])
}

// vhlTestServer builds a relay server for ceremony tests.
func vhlTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st)
}

// vhlCreateBody builds a signed ceremony creation request.
func vhlCreateBody(t *testing.T, id *crypto.Identity, address, ceremonyType, challengeB64, rpID string, ts int64) map[string]any {
	t.Helper()
	sig := id.Sign(envelope.VHLCeremonyCreate(id.EdPub[:], ceremonyType, challengeB64, ts))
	return map[string]any{
		"address":   address,
		"type":      ceremonyType,
		"challenge": challengeB64,
		"rp_id":     rpID,
		"ts":        ts,
		"sig":       vhlB64.EncodeToString(sig),
	}
}

// vhlResultURL builds the signed poll URL for a ceremony code.
func vhlResultURL(t *testing.T, srv *Server, id *crypto.Identity, address, code string, ts int64) string {
	t.Helper()
	sig := id.Sign(envelope.VHLCeremonyResult(id.EdPub[:], code, ts))
	return "/v1/vhl/ceremonies/" + code + "/result" +
		"?address=" + url.QueryEscape(address) +
		"&ts=" + fmt.Sprint(ts) +
		"&sig=" + url.QueryEscape(vhlB64.EncodeToString(sig))
}

func vhlDo(t *testing.T, srv *Server, method, target string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	return w
}

func vhlChallengeB64(t *testing.T) string {
	t.Helper()
	var chal [32]byte
	if _, err := rand.Read(chal[:]); err != nil {
		t.Fatal(err)
	}
	return vhlB64.EncodeToString(chal[:])
}

// vhlSessionCookie creates a dashboard user bound to address with a
// live session, returning the cookie the browser would present.
func vhlSessionCookie(t *testing.T, st *store.Store, username, address string) (*http.Cookie, string) {
	t.Helper()
	u, err := st.CreateDashboardUser(username, "hash", address, "apitoken-"+username)
	if err != nil {
		t.Fatal(err)
	}
	raw := "session-" + username
	sum := sha256.Sum256([]byte(raw))
	if err := st.CreateSession(hex.EncodeToString(sum[:]), u.ID, time.Hour, "csrf-"+username); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "courier_session", Value: raw}, "csrf-" + username
}

func TestVHLCeremonyCreatePollLifecycle(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	chal := vhlChallengeB64(t)

	// Create: signed agent request.
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, id, address, "mint", chal, "example.com", time.Now().Unix()), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d, body %s", w.Code, w.Body.String())
	}
	var created struct {
		Code         string `json:"code"`
		CeremonyPath string `json:"ceremony_path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Code) != 8 || !strings.HasPrefix(created.CeremonyPath, "/vhl/ceremony?code=") {
		t.Fatalf("bad create response: %+v", created)
	}

	// Poll before completion: pending.
	w = vhlDo(t, srv, "GET", vhlResultURL(t, srv, id, address, created.Code, time.Now().Unix()), nil, nil)
	var res struct {
		Status      string `json:"status"`
		Attestation string `json:"attestation"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending" {
		t.Fatalf("want pending, got %q", res.Status)
	}

	// Simulate the browser completing the ceremony.
	att := vhlB64.EncodeToString([]byte(`{"type":"public-key","id":"x","response":{"a":"b"}}`))
	if err := srv.ceremonies.complete(created.Code, att); err != nil {
		t.Fatal(err)
	}

	// Poll after completion: completed with the attestation.
	w = vhlDo(t, srv, "GET", vhlResultURL(t, srv, id, address, created.Code, time.Now().Unix()), nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "completed" || res.Attestation != att {
		t.Fatalf("want completed+attestation, got %+v", res)
	}

	// A different identity cannot poll the result.
	other, otherAddr := vhlTestIdentity(t)
	w = vhlDo(t, srv, "GET", vhlResultURL(t, srv, other, otherAddr, created.Code, time.Now().Unix()), nil, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-identity poll: got %d, want 403", w.Code)
	}
}

func TestVHLCeremonyCreateRejectsBadSignature(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	other, _ := vhlTestIdentity(t)
	chal := vhlChallengeB64(t)
	ts := time.Now().Unix()
	// Sign with the wrong key.
	sig := other.Sign(envelope.VHLCeremonyCreate(id.EdPub[:], "enroll", chal, ts))
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies", map[string]any{
		"address": address, "type": "enroll", "challenge": chal,
		"rp_id": "example.com", "ts": ts, "sig": vhlB64.EncodeToString(sig),
	}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad sig: got %d, want 401", w.Code)
	}
}

func TestVHLCeremonyCreateRejectsStaleTimestamp(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	chal := vhlChallengeB64(t)
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, id, address, "enroll", chal, "example.com", time.Now().Unix()-3600), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("stale ts: got %d, want 401", w.Code)
	}
}

func TestVHLCeremonyCreateRejectsBadTypeAndChallenge(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	ts := time.Now().Unix()
	// Bad type.
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, id, address, "bogus", vhlChallengeB64(t), "example.com", ts), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad type: got %d, want 400", w.Code)
	}
	// Short challenge.
	short := vhlB64.EncodeToString([]byte("short"))
	sig := id.Sign(envelope.VHLCeremonyCreate(id.EdPub[:], "enroll", short, ts))
	w = vhlDo(t, srv, "POST", "/v1/vhl/ceremonies", map[string]any{
		"address": address, "type": "enroll", "challenge": short,
		"rp_id": "example.com", "ts": ts, "sig": vhlB64.EncodeToString(sig),
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("short challenge: got %d, want 400", w.Code)
	}
}

func TestVHLCeremonyExpiry(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, id, address, "mint", vhlChallengeB64(t), "example.com", time.Now().Unix()), nil)
	var created struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	// Expire the record manually.
	srv.ceremonies.mu.Lock()
	srv.ceremonies.byCode[created.Code].ExpiresAt = time.Now().Add(-time.Second)
	srv.ceremonies.mu.Unlock()

	// The record is gone for browser and agent alike.
	if cer := srv.ceremonies.get(created.Code); cer != nil {
		t.Fatal("expired ceremony still retrievable")
	}
	w = vhlDo(t, srv, "GET", vhlResultURL(t, srv, id, address, created.Code, time.Now().Unix()), nil, nil)
	var res struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.Status != "expired" {
		t.Fatalf("want expired, got %q", res.Status)
	}
}

func TestVHLCeremonySingleUse(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, id, address, "enroll", vhlChallengeB64(t), "example.com", time.Now().Unix()), nil)
	var created struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	att := vhlB64.EncodeToString([]byte(`{"type":"public-key"}`))
	if err := srv.ceremonies.complete(created.Code, att); err != nil {
		t.Fatal(err)
	}
	if err := srv.ceremonies.complete(created.Code, att); err == nil {
		t.Fatal("double completion accepted")
	}
}

func TestVHLCeremonyBrowserGating(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, id, address, "enroll", vhlChallengeB64(t), "example.com", time.Now().Unix()), nil)
	var created struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	// No session anywhere on the browser surface.
	if w := vhlDo(t, srv, "GET", "/v1/vhl/ceremonies/"+created.Code, nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("details without login: got %d, want 401", w.Code)
	}
	if w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies/"+created.Code+"/attestation",
		map[string]any{"attestation": "e30", "csrf_token": "x"}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("attest without login: got %d, want 401", w.Code)
	}
	if w := vhlDo(t, srv, "GET", "/vhl/ceremony?code="+created.Code, nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("page without login: got %d, want 401", w.Code)
	}
}

func TestVHLCeremonyBrowserIdentityBinding(t *testing.T) {
	// The browser surface binds the logged-in dashboard user to the
	// ceremony's creator identity: a second human on a shared relay
	// must not complete (or read) someone else's ceremony. Sessions
	// live in the shared database, so this test uses a second store
	// handle for the session setup.
	st, err := store.Open(t.TempDir() + "/browser.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st)

	// Ceremony created by alice's identity.
	alice, aliceAddr := vhlTestIdentity(t)
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, alice, aliceAddr, "mint", vhlChallengeB64(t), "example.com", time.Now().Unix()), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d", w.Code)
	}
	var created struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	// Dashboard user bound to a DIFFERENT identity: forbidden.
	cookie, csrf := vhlSessionCookie(t, st, "mallory", "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	_ = csrf
	if w := vhlDo(t, srv, "GET", "/v1/vhl/ceremonies/"+created.Code, nil, []*http.Cookie{cookie}); w.Code != http.StatusForbidden {
		t.Fatalf("cross-identity details: got %d, want 403", w.Code)
	}

	// Dashboard user bound to the SAME identity: allowed.
	cookie2, _ := vhlSessionCookie(t, st, "alice", aliceAddr)
	w = vhlDo(t, srv, "GET", "/v1/vhl/ceremonies/"+created.Code, nil, []*http.Cookie{cookie2})
	if w.Code != http.StatusOK {
		t.Fatalf("same-identity details: got %d, body %s", w.Code, w.Body.String())
	}
	var details struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rp_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &details)
	if details.RPID != "example.com" || details.Challenge == "" {
		t.Fatalf("bad details: %+v", details)
	}

	// The ceremony page serves for a logged-in user.
	w = vhlDo(t, srv, "GET", "/vhl/ceremony?code="+created.Code, nil, []*http.Cookie{cookie2})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "navigator.credentials") {
		t.Fatalf("page: got %d, missing ceremony JS", w.Code)
	}
}

func TestVHLCeremonyAttestCSRFAndValidation(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/attest.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st)

	alice, aliceAddr := vhlTestIdentity(t)
	w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, alice, aliceAddr, "enroll", vhlChallengeB64(t), "example.com", time.Now().Unix()), nil)
	var created struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	cookie, csrf := vhlSessionCookie(t, st, "alice", aliceAddr)

	attest := func(csrfToken string) *httptest.ResponseRecorder {
		return vhlDo(t, srv, "POST", "/v1/vhl/ceremonies/"+created.Code+"/attestation",
			map[string]any{
				"attestation": vhlB64.EncodeToString([]byte(`{"type":"public-key","id":"x","response":{"a":"b"}}`)),
				"csrf_token":  csrfToken,
			}, []*http.Cookie{cookie})
	}

	// Wrong CSRF token: rejected.
	if w := attest("wrong"); w.Code != http.StatusForbidden {
		t.Fatalf("bad csrf: got %d, want 403", w.Code)
	}
	// Right CSRF token: accepted, single-use.
	if w := attest(csrf); w.Code != http.StatusOK {
		t.Fatalf("good csrf: got %d, body %s", w.Code, w.Body.String())
	}
	// Second submission: conflict.
	if w := attest(csrf); w.Code != http.StatusConflict {
		t.Fatalf("double attest: got %d, want 409", w.Code)
	}

	// Malformed attestation on a fresh ceremony: rejected.
	w = vhlDo(t, srv, "POST", "/v1/vhl/ceremonies",
		vhlCreateBody(t, alice, aliceAddr, "enroll", vhlChallengeB64(t), "example.com", time.Now().Unix()), nil)
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if w := vhlDo(t, srv, "POST", "/v1/vhl/ceremonies/"+created.Code+"/attestation",
		map[string]any{"attestation": vhlB64.EncodeToString([]byte("not json")), "csrf_token": csrf},
		[]*http.Cookie{cookie}); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed attestation: got %d, want 400", w.Code)
	}
}

// vhlEnrollBody builds a signed enrollment publication.
func vhlEnrollBody(t *testing.T, id *crypto.Identity, address, credID, credPub, rpID string, epoch int64) map[string]any {
	t.Helper()
	sig := id.Sign(envelope.VHLEnrollmentAnnounce(id.EdPub[:], credID, credPub, rpID, epoch))
	return map[string]any{
		"address": address, "credential_id": credID, "credential_pub": credPub,
		"rp_id": rpID, "aaguid": "1234", "epoch": epoch, "sig": vhlB64.EncodeToString(sig),
	}
}

func TestVHLEnrollmentPublishLookup(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	credID := vhlB64.EncodeToString([]byte("credential-id-1"))
	credPub := vhlB64.EncodeToString(make([]byte, 77)) // plausible COSE key size

	// Publish.
	w := vhlDo(t, srv, "POST", "/v1/vhl/enrollments",
		vhlEnrollBody(t, id, address, credID, credPub, "example.com", 1000), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("publish: got %d, body %s", w.Code, w.Body.String())
	}

	// Lookup round-trips.
	w = vhlDo(t, srv, "GET", "/v1/vhl/enrollments/"+url.PathEscape(address), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("lookup: got %d", w.Code)
	}
	var got struct {
		CredentialID string `json:"credential_id"`
		Epoch        int64  `json:"epoch"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.CredentialID != credID || got.Epoch != 1000 {
		t.Fatalf("bad lookup: %+v", got)
	}

	// Stale epoch: conflict, old value retained.
	w = vhlDo(t, srv, "POST", "/v1/vhl/enrollments",
		vhlEnrollBody(t, id, address, credID, credPub, "example.com", 999), nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale epoch: got %d, want 409", w.Code)
	}

	// Newer epoch replaces.
	credID2 := vhlB64.EncodeToString([]byte("credential-id-2"))
	w = vhlDo(t, srv, "POST", "/v1/vhl/enrollments",
		vhlEnrollBody(t, id, address, credID2, credPub, "example.com", 1001), nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("republish: got %d", w.Code)
	}
	w = vhlDo(t, srv, "GET", "/v1/vhl/enrollments/"+url.PathEscape(address), nil, nil)
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.CredentialID != credID2 {
		t.Fatalf("replacement not applied: %+v", got)
	}

	// Unknown address: 404.
	_, otherAddr := vhlTestIdentity(t)
	if w := vhlDo(t, srv, "GET", "/v1/vhl/enrollments/"+url.PathEscape(otherAddr), nil, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown lookup: got %d, want 404", w.Code)
	}
}

func TestVHLEnrollmentPublishRejectsBadSignature(t *testing.T) {
	srv := vhlTestServer(t)
	id, address := vhlTestIdentity(t)
	other, _ := vhlTestIdentity(t)
	credID := vhlB64.EncodeToString([]byte("cred"))
	credPub := vhlB64.EncodeToString(make([]byte, 77))
	sig := other.Sign(envelope.VHLEnrollmentAnnounce(id.EdPub[:], credID, credPub, "example.com", 1000))
	w := vhlDo(t, srv, "POST", "/v1/vhl/enrollments", map[string]any{
		"address": address, "credential_id": credID, "credential_pub": credPub,
		"rp_id": "example.com", "epoch": 1000, "sig": vhlB64.EncodeToString(sig),
	}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad sig: got %d, want 401", w.Code)
	}
}
