// Contact-discovery directory tests (issue #39).
package relay

import (
	"bytes"
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

// dirTestServer builds a relay server with default directory limits.
func dirTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st)
}

// dirAnnounce posts a key announcement so the identity passes the
// registration hurdle.
func dirAnnounce(t *testing.T, srv *Server, id *crypto.Identity) {
	t.Helper()
	if w := postKeys(t, srv, makeAnnouncement(t, id, time.Now().Unix())); w.Code != http.StatusCreated {
		t.Fatalf("announce: got %d, body %s", w.Code, w.Body.String())
	}
}

func dirRegisterBody(t *testing.T, id *crypto.Identity, handle string, epoch int64) map[string]any {
	t.Helper()
	h, err := envelope.NormalizeHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	sig := id.Sign(envelope.DirectoryRegister(h, id.EdPub[:], epoch, "public", "open", []string{"chat"}))
	return map[string]any{
		"handle": h, "address": crypto.FormatAddress(id.EdPub[:]),
		"capabilities": []string{"chat"}, "contact_policy": "open",
		"visibility": "public", "epoch": epoch,
		"sig": b64.EncodeToString(sig),
	}
}

func postDirectory(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v1/directory", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// signedDirURL builds a signed directory query URL (lookup/search/reverse).
func signedDirURL(t *testing.T, querier *crypto.Identity, op string, params map[string]string) string {
	t.Helper()
	ts := time.Now().Unix()
	query := params["q"]
	sig := querier.Sign(envelope.DirectoryQuery(querier.EdPub[:], op, query, ts))
	v := url.Values{}
	for k, val := range params {
		v.Set(k, val)
	}
	v.Set("querier", crypto.FormatAddress(querier.EdPub[:]))
	v.Set("ts", fmt.Sprintf("%d", ts))
	v.Set("sig", b64.EncodeToString(sig))
	return "/v1/directory/" + op + "?" + v.Encode()
}

func getDir(t *testing.T, srv *Server, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", url, nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestDirectoryRegisterLookupRoundtrip(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	rec := postDirectory(t, srv, dirRegisterBody(t, alice, "Alice_99", 1000))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d, body %s", rec.Code, rec.Body.String())
	}
	// Handle is normalized to lowercase.
	rec = getDir(t, srv, signedDirURL(t, alice, "lookup", map[string]string{"handle": "alice_99", "q": "alice_99"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup: got %d, body %s", rec.Code, rec.Body.String())
	}
	var p struct {
		Handle       string   `json:"handle"`
		Address      string   `json:"address"`
		Capabilities []string `json:"capabilities"`
		Visibility   string   `json:"visibility"`
		Epoch        int64    `json:"epoch"`
		Sig          string   `json:"sig"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Handle != "alice_99" || p.Address != crypto.FormatAddress(alice.EdPub[:]) {
		t.Fatalf("wrong profile: %+v", p)
	}
	if p.Epoch != 1000 || p.Sig == "" || p.Visibility != "public" {
		t.Fatalf("bad profile fields: %+v", p)
	}
	if len(p.Capabilities) != 1 || p.Capabilities[0] != "chat" {
		t.Fatalf("bad capabilities: %+v", p.Capabilities)
	}
}

func TestDirectorySquattingRejected(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	dirAnnounce(t, srv, bob)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "squatme", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("alice register: got %d", rec.Code)
	}
	// Bob (different identity) cannot take the handle, even with a
	// higher epoch: first-come-first-served.
	if rec := postDirectory(t, srv, dirRegisterBody(t, bob, "squatme", 2000)); rec.Code != http.StatusConflict {
		t.Fatalf("squat: got %d, want 409, body %s", rec.Code, rec.Body.String())
	}
}

func TestDirectoryStaleEpochRejected(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "epochy", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	// Same owner, stale epoch: rejected.
	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "epochy", 999)); rec.Code != http.StatusConflict {
		t.Fatalf("stale epoch: got %d, want 409", rec.Code)
	}
	// Same owner, higher epoch: accepted (update).
	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "epochy", 1001)); rec.Code != http.StatusOK {
		t.Fatalf("update: got %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestDirectoryRequiresKeyAnnouncement(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	// No announcement posted: the anti-parking hurdle rejects the write.
	rec := postDirectory(t, srv, dirRegisterBody(t, alice, "noannounce", 1000))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "key announcement") {
		t.Fatalf("hurdle error should mention key announcements: %s", rec.Body.String())
	}
}

func TestDirectoryQueryRequiresSignature(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "sigtest", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}

	// No signature at all (valid ts): 401.
	addr := url.QueryEscape(crypto.FormatAddress(alice.EdPub[:]))
	rec := getDir(t, srv, fmt.Sprintf("/v1/directory/lookup?handle=sigtest&querier=%s&ts=%d", addr, time.Now().Unix()))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: got %d, want 401", rec.Code)
	}
	// Missing ts: 400 (malformed query).
	rec = getDir(t, srv, "/v1/directory/lookup?handle=sigtest&querier="+addr)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing ts: got %d, want 400", rec.Code)
	}
	// Corrupt signature (well-formed 64 bytes, wrong value): 401.
	u := signedDirURL(t, alice, "lookup", map[string]string{"handle": "sigtest", "q": "sigtest"})
	uu, _ := url.Parse(u)
	qv := uu.Query()
	badSig := make([]byte, 64)
	copy(badSig, "corrupted-signature-not-the-real-one-0123456789abcdef")
	qv.Set("sig", b64.EncodeToString(badSig))
	uu.RawQuery = qv.Encode()
	if rec := getDir(t, srv, uu.String()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad sig: got %d, want 401", rec.Code)
	}
	// Stale timestamp: rejected before signature verification (400).
	ts := time.Now().Unix() - 3600
	sig := alice.Sign(envelope.DirectoryQuery(alice.EdPub[:], "lookup", "sigtest", ts))
	stale := fmt.Sprintf("/v1/directory/lookup?handle=sigtest&q=sigtest&querier=%s&ts=%d&sig=%s",
		url.QueryEscape(crypto.FormatAddress(alice.EdPub[:])), ts, b64.EncodeToString(sig))
	if rec := getDir(t, srv, stale); rec.Code != http.StatusBadRequest {
		t.Fatalf("stale ts: got %d, want 400", rec.Code)
	}
	// Search without signature is also rejected (valid ts, no sig).
	rec = getDir(t, srv, fmt.Sprintf("/v1/directory/search?q=si&querier=%s&ts=%d", addr, time.Now().Unix()))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned search: got %d, want 401", rec.Code)
	}
}

func TestDirectoryPrivateIndistinguishable(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	body := dirRegisterBody(t, alice, "secretagent", 1000)
	// Re-sign as private.
	sig := alice.Sign(envelope.DirectoryRegister("secretagent", alice.EdPub[:], 1000, "private", "open", []string{"chat"}))
	body["visibility"] = "private"
	body["sig"] = b64.EncodeToString(sig)
	if rec := postDirectory(t, srv, body); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d, body %s", rec.Code, rec.Body.String())
	}

	priv := getDir(t, srv, signedDirURL(t, alice, "lookup", map[string]string{"handle": "secretagent", "q": "secretagent"}))
	unknown := getDir(t, srv, signedDirURL(t, alice, "lookup", map[string]string{"handle": "nosuchhandle", "q": "nosuchhandle"}))
	if priv.Code != http.StatusNotFound || unknown.Code != http.StatusNotFound {
		t.Fatalf("private=%d unknown=%d, both must be 404", priv.Code, unknown.Code)
	}
	// Reverse lookup also excludes private handles.
	rev := getDir(t, srv, signedDirURL(t, alice, "reverse",
		map[string]string{"address": crypto.FormatAddress(alice.EdPub[:]), "q": crypto.FormatAddress(alice.EdPub[:])}))
	var out struct {
		Results []any `json:"results"`
	}
	_ = json.Unmarshal(rev.Body.Bytes(), &out)
	if len(out.Results) != 0 {
		t.Fatalf("private handle leaked via reverse: %v", out.Results)
	}
}

func TestDirectorySearchPublicOnly(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	mk := func(handle, vis string, epoch int64) {
		sig := alice.Sign(envelope.DirectoryRegister(handle, alice.EdPub[:], epoch, vis, "open", []string{"chat"}))
		rec := postDirectory(t, srv, map[string]any{
			"handle": handle, "address": crypto.FormatAddress(alice.EdPub[:]),
			"capabilities": []string{"chat"}, "contact_policy": "open",
			"visibility": vis, "epoch": epoch, "sig": b64.EncodeToString(sig),
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %s: got %d, body %s", handle, rec.Code, rec.Body.String())
		}
	}
	mk("zpubone", "public", 1000)
	mk("zpubtwo", "public", 1001)
	mk("zunlisted", "unlisted", 1002)
	mk("zprivate", "private", 1003)

	rec := getDir(t, srv, signedDirURL(t, alice, "search", map[string]string{"q": "zp"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("search: got %d, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Results []struct {
			Handle string `json:"handle"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("want 2 public results, got %+v", out.Results)
	}
	// Prefix shorter than 2 chars is rejected (no list-all oracle).
	rec = getDir(t, srv, signedDirURL(t, alice, "search", map[string]string{"q": "z"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short prefix: got %d, want 400", rec.Code)
	}
}

// TestDirectorySearchResultsVerifiable is the regression test for the
// v0.8.1 relay hotfix: search results must carry every field the
// registration signature covers (notably contact_policy), so a client
// can verify the binding exactly as it does for lookup results.
func TestDirectorySearchResultsVerifiable(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	addr := crypto.FormatAddress(alice.EdPub[:])
	sig := alice.Sign(envelope.DirectoryRegister("zverify", alice.EdPub[:], 1001, "public", "contacts", []string{"chat"}))
	rec := postDirectory(t, srv, map[string]any{
		"handle": "zverify", "address": addr,
		"capabilities": []string{"chat"}, "contact_policy": "contacts",
		"visibility": "public", "epoch": 1001, "sig": b64.EncodeToString(sig),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d, body %s", rec.Code, rec.Body.String())
	}

	rec = getDir(t, srv, signedDirURL(t, alice, "search", map[string]string{"q": "zver"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("search: got %d, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Results []struct {
			Handle        string   `json:"handle"`
			Address       string   `json:"address"`
			Capabilities  []string `json:"capabilities"`
			ContactPolicy string   `json:"contact_policy"`
			Visibility    string   `json:"visibility"`
			Epoch         int64    `json:"epoch"`
			Sig           string   `json:"sig"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(out.Results))
	}
	r := out.Results[0]
	if r.ContactPolicy == "" {
		t.Fatal("search result omits contact_policy: clients cannot verify the binding")
	}
	rawSig, err := b64.DecodeString(r.Sig)
	if err != nil {
		t.Fatal(err)
	}
	canon := envelope.DirectoryRegister(r.Handle, alice.EdPub[:], r.Epoch,
		r.Visibility, r.ContactPolicy, r.Capabilities)
	if !crypto.Verify(alice.EdPub[:], canon, rawSig) {
		t.Fatal("search result signature does not verify with the served fields")
	}
}

func TestDirectoryTombstone(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	dirAnnounce(t, srv, bob)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "takedownme", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	ok, err := srv.TombstoneHandle("takedownme", "spam")
	if err != nil || !ok {
		t.Fatalf("tombstone: ok=%v err=%v", ok, err)
	}
	// Lookup returns 410 with the published reason: visible, not silent.
	rec := getDir(t, srv, signedDirURL(t, alice, "lookup", map[string]string{"handle": "takedownme", "q": "takedownme"}))
	if rec.Code != http.StatusGone {
		t.Fatalf("lookup tombstoned: got %d, want 410", rec.Code)
	}
	var tomb struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tomb)
	if tomb.Reason != "spam" {
		t.Fatalf("tombstone reason not published: %q", rec.Body.String())
	}
	// The handle cannot be re-registered while tombstoned.
	if rec := postDirectory(t, srv, dirRegisterBody(t, bob, "takedownme", 2000)); rec.Code != http.StatusConflict {
		t.Fatalf("re-register tombstoned: got %d, want 409", rec.Code)
	}
	// Reversal restores the entry.
	ok, err = srv.UntombstoneHandle("takedownme")
	if err != nil || !ok {
		t.Fatalf("untombstone: ok=%v err=%v", ok, err)
	}
	rec = getDir(t, srv, signedDirURL(t, alice, "lookup", map[string]string{"handle": "takedownme", "q": "takedownme"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup after reversal: got %d", rec.Code)
	}
}

func TestDirectoryTransfer(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	dirAnnounce(t, srv, bob)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "passing", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	// Alice transfers to Bob, signed by Alice (current holder).
	sig := alice.Sign(envelope.DirectoryTransfer("passing", bob.EdPub[:], 1001))
	raw, _ := json.Marshal(map[string]any{
		"handle": "passing", "to_address": crypto.FormatAddress(bob.EdPub[:]),
		"epoch": 1001, "sig": b64.EncodeToString(sig),
	})
	req := httptest.NewRequest("POST", "/v1/directory/transfer", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("transfer: got %d, body %s", rec.Code, rec.Body.String())
	}
	// Lookup now shows Bob's address.
	lrec := getDir(t, srv, signedDirURL(t, bob, "lookup", map[string]string{"handle": "passing", "q": "passing"}))
	var p struct {
		Address string `json:"address"`
		Epoch   int64  `json:"epoch"`
	}
	_ = json.Unmarshal(lrec.Body.Bytes(), &p)
	if p.Address != crypto.FormatAddress(bob.EdPub[:]) || p.Epoch != 1001 {
		t.Fatalf("wrong owner after transfer: %+v", p)
	}
	// Bob can update (higher epoch, owner-signed).
	bsig := bob.Sign(envelope.DirectoryRegister("passing", bob.EdPub[:], 1002, "public", "open", []string{"chat"}))
	upd := map[string]any{
		"handle": "passing", "address": crypto.FormatAddress(bob.EdPub[:]),
		"capabilities": []string{"chat"}, "contact_policy": "open",
		"visibility": "public", "epoch": 1002, "sig": b64.EncodeToString(bsig),
	}
	if rec := postDirectory(t, srv, upd); rec.Code != http.StatusOK {
		t.Fatalf("bob update: got %d, body %s", rec.Code, rec.Body.String())
	}
	// Alice can no longer touch it.
	asig := alice.Sign(envelope.DirectoryRegister("passing", alice.EdPub[:], 1003, "public", "open", []string{"chat"}))
	steal := map[string]any{
		"handle": "passing", "address": crypto.FormatAddress(alice.EdPub[:]),
		"capabilities": []string{"chat"}, "contact_policy": "open",
		"visibility": "public", "epoch": 1003, "sig": b64.EncodeToString(asig),
	}
	if rec := postDirectory(t, srv, steal); rec.Code != http.StatusConflict {
		t.Fatalf("alice post-transfer write: got %d, want 409", rec.Code)
	}
	// A transfer not signed by the current holder is rejected: Alice
	// signs, but Bob is the holder, so verification fails.
	badSig := alice.Sign(envelope.DirectoryTransfer("passing", alice.EdPub[:], 1004))
	raw, _ = json.Marshal(map[string]any{
		"handle": "passing", "to_address": crypto.FormatAddress(alice.EdPub[:]),
		"epoch": 1004, "sig": b64.EncodeToString(badSig),
	})
	req = httptest.NewRequest("POST", "/v1/directory/transfer", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict && rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-holder transfer: got %d, want 4xx", rec.Code)
	}
}

func TestDirectoryDeregister(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	dirAnnounce(t, srv, bob)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "tempname", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	// Deregistration must be signed by the holder (distinct domain).
	sig := alice.Sign(envelope.DirectoryDeregister("tempname", alice.EdPub[:], 1001))
	raw, _ := json.Marshal(map[string]any{
		"handle": "tempname", "address": crypto.FormatAddress(alice.EdPub[:]),
		"epoch": 1001, "deregister": true, "sig": b64.EncodeToString(sig),
	})
	req := httptest.NewRequest("POST", "/v1/directory", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deregister: got %d, body %s", rec.Code, rec.Body.String())
	}
	// Gone — and the handle is free for someone else (unlike tombstone).
	lrec := getDir(t, srv, signedDirURL(t, alice, "lookup", map[string]string{"handle": "tempname", "q": "tempname"}))
	if lrec.Code != http.StatusNotFound {
		t.Fatalf("lookup after deregister: got %d, want 404", lrec.Code)
	}
	if rec := postDirectory(t, srv, dirRegisterBody(t, bob, "tempname", 2000)); rec.Code != http.StatusCreated {
		t.Fatalf("re-register after deregister: got %d, body %s", rec.Code, rec.Body.String())
	}
	// Bob cannot deregister Alice's... (sanity: a non-holder deregister
	// attempt fails signature binding).
	badSig := bob.Sign(envelope.DirectoryDeregister("tempname", bob.EdPub[:], 2001))
	raw, _ = json.Marshal(map[string]any{
		"handle": "tempname", "address": crypto.FormatAddress(alice.EdPub[:]),
		"epoch": 2001, "deregister": true, "sig": b64.EncodeToString(badSig),
	})
	req = httptest.NewRequest("POST", "/v1/directory", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("non-holder deregister succeeded")
	}
}

func TestDirectoryReservedHandles(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := NewWithConfig(st, Config{ReservedHandles: []string{"courier", "admin"}})
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "courier", 1000)); rec.Code != http.StatusForbidden {
		t.Fatalf("reserved: got %d, want 403, body %s", rec.Code, rec.Body.String())
	}
	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "ADMIN", 1000)); rec.Code != http.StatusForbidden {
		t.Fatalf("reserved (case): got %d, want 403", rec.Code)
	}
	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "notreserved", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("normal: got %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestDirectoryRejectsUnknownFields(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	body := dirRegisterBody(t, alice, "noprofile", 1000)
	body["display_name"] = "Alice" // PII-ish profile field: must be rejected
	body["bio"] = "hello"
	if rec := postDirectory(t, srv, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown fields: got %d, want 400, body %s", rec.Code, rec.Body.String())
	}
	// And the handle was not registered.
	lrec := getDir(t, srv, signedDirURL(t, alice, "lookup", map[string]string{"handle": "noprofile", "q": "noprofile"}))
	if lrec.Code != http.StatusNotFound {
		t.Fatalf("rejected registration leaked: %d", lrec.Code)
	}
}

func TestDirectoryReverse(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	mk := func(handle, vis string, epoch int64) {
		sig := alice.Sign(envelope.DirectoryRegister(handle, alice.EdPub[:], epoch, vis, "open", []string{"chat"}))
		rec := postDirectory(t, srv, map[string]any{
			"handle": handle, "address": crypto.FormatAddress(alice.EdPub[:]),
			"capabilities": []string{"chat"}, "contact_policy": "open",
			"visibility": vis, "epoch": epoch, "sig": b64.EncodeToString(sig),
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %s: got %d", handle, rec.Code)
		}
	}
	mk("revpub", "public", 1000)
	// Second handle for the same address must use a higher epoch.
	mk("revunlisted", "unlisted", 1001)
	mk("revprivate", "private", 1002)

	addr := crypto.FormatAddress(alice.EdPub[:])
	rec := getDir(t, srv, signedDirURL(t, alice, "reverse", map[string]string{"address": addr, "q": addr}))
	if rec.Code != http.StatusOK {
		t.Fatalf("reverse: got %d, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Results []struct {
			Handle     string `json:"handle"`
			Visibility string `json:"visibility"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("want 2 listed handles, got %+v", out.Results)
	}
	for _, r := range out.Results {
		if r.Visibility == "private" {
			t.Fatalf("private handle in reverse results: %+v", r)
		}
	}
}

func TestDirectoryWriteRateLimit(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := NewWithConfig(st, Config{DirWriteBurst: 1, DirWriteRatePerSec: 0.0001})
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "ratel1", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("first write: got %d", rec.Code)
	}
	// Burst of 1: the immediate second write is rejected, not queued.
	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "ratel2", 1001)); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second write: got %d, want 429", rec.Code)
	}
}

func TestDirectoryHandleValidation(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)

	// Raw invalid handles are rejected (never normalized into something
	// registrable).
	for _, bad := range []string{"ab", "UPPER", "has space", "dot.name", "toolongtoolongtoolongtoolongtoolong"} {
		sig := alice.Sign(envelope.DirectoryRegister(bad, alice.EdPub[:], 1000, "public", "open", nil))
		rec := postDirectory(t, srv, map[string]any{
			"handle": bad, "address": crypto.FormatAddress(alice.EdPub[:]),
			"contact_policy": "open", "visibility": "public",
			"epoch": 1000, "sig": b64.EncodeToString(sig),
		})
		if rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
			t.Fatalf("invalid handle %q accepted: %d", bad, rec.Code)
		}
	}
}

// TestDirectoryLimiterRateDefaults: a config with a custom burst but no
// rate still refills at the default rate (the CLI sets bursts via flags
// and leaves rates zero). Without this, the bucket would never refill
// and the endpoint would block forever after the burst is spent.
func TestDirectoryLimiterRateDefaults(t *testing.T) {
	openStore := func(t *testing.T) *store.Store {
		t.Helper()
		st, err := store.Open(t.TempDir() + "/test.db")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		return st
	}
	cfg := DefaultConfig()
	cfg.DirWriteBurst = 5 // custom burst, rate left at zero
	srv := NewWithConfig(openStore(t), cfg)
	if srv.cfg.DirWriteRatePerSec != DefaultConfig().DirWriteRatePerSec {
		t.Fatalf("write rate = %v, want default %v",
			srv.cfg.DirWriteRatePerSec, DefaultConfig().DirWriteRatePerSec)
	}
	if srv.cfg.DirWriteBurst != 5 {
		t.Fatalf("write burst = %v, want 5 (custom value kept)", srv.cfg.DirWriteBurst)
	}
	// Zero-value directory config still inherits all defaults.
	srv2 := NewWithConfig(openStore(t), Config{SendBurst: 1, SendRatePerSec: 1})
	def := DefaultConfig()
	if srv2.cfg.DirWriteBurst != def.DirWriteBurst ||
		srv2.cfg.DirLookupBurst != def.DirLookupBurst ||
		srv2.cfg.DirSearchBurst != def.DirSearchBurst {
		t.Fatal("zero directory fields did not inherit defaults")
	}
}

// TestDirectoryTransferProof: after a transfer, lookup serves the
// previous holder's address as transfer_from alongside the transfer
// signature, and a fresh register/update by the new owner clears it.
func TestDirectoryTransferProof(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	dirAnnounce(t, srv, bob)

	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "passing2", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	// Before transfer: no transfer_from.
	lrec := getDir(t, srv, signedDirURL(t, bob, "lookup", map[string]string{"handle": "passing2", "q": "passing2"}))
	var before struct {
		Sig          string `json:"sig"`
		TransferFrom string `json:"transfer_from"`
	}
	_ = json.Unmarshal(lrec.Body.Bytes(), &before)
	if before.TransferFrom != "" {
		t.Fatalf("fresh registration has transfer_from = %q", before.TransferFrom)
	}

	// Transfer Alice -> Bob.
	sig := alice.Sign(envelope.DirectoryTransfer("passing2", bob.EdPub[:], 1001))
	raw, _ := json.Marshal(map[string]any{
		"handle": "passing2", "to_address": crypto.FormatAddress(bob.EdPub[:]),
		"epoch": 1001, "sig": b64.EncodeToString(sig),
	})
	req := httptest.NewRequest("POST", "/v1/directory/transfer", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("transfer: got %d", rec.Code)
	}

	// Lookup serves the transfer proof.
	lrec = getDir(t, srv, signedDirURL(t, bob, "lookup", map[string]string{"handle": "passing2", "q": "passing2"}))
	var p struct {
		Handle       string `json:"handle"`
		Address      string `json:"address"`
		Epoch        int64  `json:"epoch"`
		Sig          string `json:"sig"`
		TransferFrom string `json:"transfer_from"`
	}
	_ = json.Unmarshal(lrec.Body.Bytes(), &p)
	if p.TransferFrom != crypto.FormatAddress(alice.EdPub[:]) {
		t.Fatalf("transfer_from = %q, want alice", p.TransferFrom)
	}
	// The transfer signature verifies against the previous holder.
	psig, _ := b64.DecodeString(p.Sig)
	prevEd, _ := crypto.ParseAddress(p.TransferFrom)
	newEd, _ := crypto.ParseAddress(p.Address)
	tcanon := envelope.DirectoryTransfer("passing2", newEd[:], 1001)
	if !crypto.Verify(prevEd[:], tcanon, psig) {
		t.Fatal("transfer signature does not verify against transfer_from")
	}
	// ...and NOT as a registration signature by the new owner.
	rcanon := envelope.DirectoryRegister("passing2", newEd[:], 1001, "public", "open", nil)
	if crypto.Verify(newEd[:], rcanon, psig) {
		t.Fatal("transfer signature must not verify as a registration")
	}

	// Bob's own update replaces the sig with a registration signature
	// and clears the transfer proof.
	bsig := bob.Sign(envelope.DirectoryRegister("passing2", bob.EdPub[:], 1002, "public", "open", []string{"chat"}))
	upd := map[string]any{
		"handle": "passing2", "address": crypto.FormatAddress(bob.EdPub[:]),
		"capabilities": []string{"chat"}, "contact_policy": "open",
		"visibility": "public", "epoch": 1002, "sig": b64.EncodeToString(bsig),
	}
	if rec := postDirectory(t, srv, upd); rec.Code != http.StatusOK {
		t.Fatalf("bob update: got %d", rec.Code)
	}
	lrec = getDir(t, srv, signedDirURL(t, bob, "lookup", map[string]string{"handle": "passing2", "q": "passing2"}))
	var after struct {
		Handle       string `json:"handle"`
		Address      string `json:"address"`
		Epoch        int64  `json:"epoch"`
		Sig          string `json:"sig"`
		TransferFrom string `json:"transfer_from"`
	}
	_ = json.Unmarshal(lrec.Body.Bytes(), &after)
	if after.TransferFrom != "" {
		t.Fatalf("update did not clear transfer_from: %q", after.TransferFrom)
	}
	usig, _ := b64.DecodeString(after.Sig)
	ucanon := envelope.DirectoryRegister("passing2", newEd[:], 1002, "public", "open", []string{"chat"})
	if !crypto.Verify(newEd[:], ucanon, usig) {
		t.Fatal("post-update signature does not verify as registration by bob")
	}
}

// TestDirectoryTombstonePrivateStaysHidden: a tombstoned private handle
// still returns 404 — the takedown must not create an existence oracle
// for handles whose owner chose privacy. The tombstone still blocks
// re-registration.
func TestDirectoryTombstonePrivateStaysHidden(t *testing.T) {
	srv := dirTestServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	dirAnnounce(t, srv, bob)

	sig := alice.Sign(envelope.DirectoryRegister("shh", alice.EdPub[:], 1000, "private", "open", []string{"chat"}))
	body := map[string]any{
		"handle": "shh", "address": crypto.FormatAddress(alice.EdPub[:]),
		"capabilities": []string{"chat"}, "contact_policy": "open",
		"visibility": "private", "epoch": 1000, "sig": b64.EncodeToString(sig),
	}
	if rec := postDirectory(t, srv, body); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	ok, err := srv.TombstoneHandle("shh", "abuse")
	if err != nil || !ok {
		t.Fatalf("tombstone: ok=%v err=%v", ok, err)
	}
	// Still 404: indistinguishable from never-registered.
	rec := getDir(t, srv, signedDirURL(t, bob, "lookup", map[string]string{"handle": "shh", "q": "shh"}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("tombstoned private lookup: got %d, want 404", rec.Code)
	}
	// But re-registration is still blocked.
	if rec := postDirectory(t, srv, dirRegisterBody(t, bob, "shh", 2000)); rec.Code != http.StatusConflict {
		t.Fatalf("re-register tombstoned private: got %d, want 409", rec.Code)
	}
}

// TestDirectoryQueryRateLimits: lookup and search have their own
// per-identity buckets; exhausting one does not affect the other, and
// the tight search budget (anti-enumeration) trips first.
func TestDirectoryQueryRateLimits(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := NewWithConfig(st, Config{
		DirLookupBurst: 2, DirLookupRatePerSec: 0.0001,
		DirSearchBurst: 1, DirSearchRatePerSec: 0.0001,
	})
	alice, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, alice)
	if rec := postDirectory(t, srv, dirRegisterBody(t, alice, "queryme", 1000)); rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}

	lookup := func() int {
		return getDir(t, srv, signedDirURL(t, alice, "lookup",
			map[string]string{"handle": "queryme", "q": "queryme"})).Code
	}
	if c := lookup(); c != http.StatusOK {
		t.Fatalf("lookup 1: got %d", c)
	}
	if c := lookup(); c != http.StatusOK {
		t.Fatalf("lookup 2: got %d", c)
	}
	if c := lookup(); c != http.StatusTooManyRequests {
		t.Fatalf("lookup 3: got %d, want 429", c)
	}

	search := func() int {
		return getDir(t, srv, signedDirURL(t, alice, "search",
			map[string]string{"q": "qu"})).Code
	}
	if c := search(); c != http.StatusOK {
		t.Fatalf("search 1: got %d", c)
	}
	if c := search(); c != http.StatusTooManyRequests {
		t.Fatalf("search 2: got %d, want 429", c)
	}
	// Lookup and search buckets are independent: a different identity
	// still has its full budget.
	bob, _ := crypto.GenerateIdentity()
	dirAnnounce(t, srv, bob)
	if c := getDir(t, srv, signedDirURL(t, bob, "lookup",
		map[string]string{"handle": "queryme", "q": "queryme"})).Code; c != http.StatusOK {
		t.Fatalf("other identity lookup: got %d, want 200", c)
	}
}
