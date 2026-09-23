// Introduction protocol tests (issue #39).
package client

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

// introIdentities returns three identities: alice (requester), carol
// (the test client / introducer), bob (target).
func introIdentities(t *testing.T) (alice, carolID, bob *crypto.Identity) {
	t.Helper()
	var err error
	if alice, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	if carolID, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	if bob, err = crypto.GenerateIdentity(); err != nil {
		t.Fatal(err)
	}
	return alice, carolID, bob
}

func addrOf(id *crypto.Identity) string { return crypto.FormatAddress(id.EdPub[:]) }

// introClient builds a Client for the given identity with HOME isolated
// and the given contacts.
func introClient(t *testing.T, id *crypto.Identity, contacts map[string]string) *Client {
	t.Helper()
	cfg := testConfig(t)
	// Replace the generated identity with the fixed one.
	seedB64 := base64.RawURLEncoding.EncodeToString(id.Seed[:])
	cfg.Seed = seedB64
	cfg.Address = addrOf(id)
	cfg.Contacts = contacts
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	return New(cfg)
}

// signRequest builds a signed introduction-request payload from
// requester to introducer for handle.
func signRequest(t *testing.T, requester, introducer *crypto.Identity, handle, note string) []byte {
	t.Helper()
	ts := time.Now().Unix()
	canon := envelope.IntroductionRequest(requester.EdPub[:], introducer.EdPub[:], handle, ts)
	sig := requester.Sign(canon)
	raw, err := json.Marshal(introductionPayload{
		Magic: introductionMagic, Type: "request",
		Handle: handle, Note: note, Ts: ts,
		Sig: base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signIntroduction builds a signed introduction payload from introducer
// introducing subject to recipient.
func signIntroduction(t *testing.T, introducer, subject, recipient *crypto.Identity, subjectHandle, note string) []byte {
	t.Helper()
	ts := time.Now().Unix()
	canon := envelope.Introduction(introducer.EdPub[:], subject.EdPub[:], recipient.EdPub[:], ts)
	sig := introducer.Sign(canon)
	raw, err := json.Marshal(introductionPayload{
		Magic: introductionMagic, Type: "introduction",
		Subject: addrOf(subject), SubjectHandle: subjectHandle,
		Note: note, Ts: ts,
		Sig: base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIntroductionRequestRecorded(t *testing.T) {
	alice, carolID, _ := introIdentities(t)
	carol := introClient(t, carolID, map[string]string{"alice": addrOf(alice)})

	raw := signRequest(t, alice, carolID, "bobhandle", "we worked together")
	p, ok := parseIntroductionPayload(raw)
	if !ok {
		t.Fatal("valid request payload not recognized")
	}
	disp, rec := carol.recordIntroduction(addrOf(alice), 42, p)
	if !rec {
		t.Fatal("valid request not recorded")
	}
	if disp == "" {
		t.Fatal("no display body")
	}
	pending := carol.PendingIntroductions()
	if len(pending) != 1 {
		t.Fatalf("want 1 pending, got %d", len(pending))
	}
	pi := pending[0]
	if pi.Kind != "request" || pi.Handle != "bobhandle" || pi.From != addrOf(alice) {
		t.Fatalf("wrong pending entry: %+v", pi)
	}
	if pi.Note != "we worked together" || pi.EnvelopeID != 42 {
		t.Fatalf("wrong pending details: %+v", pi)
	}
}

func TestIntroductionRequestRequiresKnownRequester(t *testing.T) {
	alice, carolID, _ := introIdentities(t)
	// Alice is NOT in Carol's contacts: the request is not recorded as
	// an introduction (message still delivered as ordinary JSON).
	carol := introClient(t, carolID, map[string]string{})
	raw := signRequest(t, alice, carolID, "bobhandle", "")
	p, _ := parseIntroductionPayload(raw)
	if _, rec := carol.recordIntroduction(addrOf(alice), 1, p); rec {
		t.Fatal("request from stranger was recorded")
	}
	if len(carol.PendingIntroductions()) != 0 {
		t.Fatal("pending list should be empty")
	}
}

func TestIntroductionRequestBadSignature(t *testing.T) {
	alice, carolID, bob := introIdentities(t)
	carol := introClient(t, carolID, map[string]string{"alice": addrOf(alice)})
	// Signed by Bob but claiming to be from Alice.
	raw := signRequest(t, bob, carolID, "bobhandle", "")
	var p introductionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if _, rec := carol.recordIntroduction(addrOf(alice), 1, p); rec {
		t.Fatal("forged request was recorded")
	}
}

func TestIntroductionRecorded(t *testing.T) {
	alice, carolID, bob := introIdentities(t)
	bobClient := introClient(t, bob, map[string]string{"carol": addrOf(carolID)})

	raw := signIntroduction(t, carolID, alice, bob, "alice", "say hi")
	p, ok := parseIntroductionPayload(raw)
	if !ok {
		t.Fatal("valid introduction payload not recognized")
	}
	disp, rec := bobClient.recordIntroduction(addrOf(carolID), 7, p)
	if !rec || disp == "" {
		t.Fatal("valid introduction not recorded")
	}
	pending := bobClient.PendingIntroductions()
	if len(pending) != 1 {
		t.Fatalf("want 1 pending, got %d", len(pending))
	}
	pi := pending[0]
	if pi.Kind != "introduction" || pi.Subject != addrOf(alice) || pi.SubjectHandle != "alice" {
		t.Fatalf("wrong pending entry: %+v", pi)
	}
}

func TestIntroductionRequiresMutualContact(t *testing.T) {
	alice, carolID, bob := introIdentities(t)
	// Carol is NOT in Bob's contacts: untrusted introducer.
	bobClient := introClient(t, bob, map[string]string{})
	raw := signIntroduction(t, carolID, alice, bob, "alice", "")
	p, _ := parseIntroductionPayload(raw)
	if _, rec := bobClient.recordIntroduction(addrOf(carolID), 1, p); rec {
		t.Fatal("introduction from non-contact was recorded")
	}
}

func TestIntroductionStaleTimestamp(t *testing.T) {
	alice, carolID, _ := introIdentities(t)
	carol := introClient(t, carolID, map[string]string{"alice": addrOf(alice)})
	ts := time.Now().Unix() - 30*24*3600
	canon := envelope.IntroductionRequest(alice.EdPub[:], carolID.EdPub[:], "bobhandle", ts)
	sig := alice.Sign(canon)
	raw, _ := json.Marshal(introductionPayload{
		Magic: introductionMagic, Type: "request",
		Handle: "bobhandle", Ts: ts,
		Sig: base64.RawURLEncoding.EncodeToString(sig),
	})
	p, ok := parseIntroductionPayload(raw)
	if !ok {
		t.Fatal("payload should parse (validation happens in record)")
	}
	if _, rec := carol.recordIntroduction(addrOf(alice), 1, p); rec {
		t.Fatal("stale introduction was recorded")
	}
}

func TestParseIntroductionPayloadRejects(t *testing.T) {
	cases := []string{
		`{"not": "json`,
		`{"ci": 2, "t": "request", "h": "x", "ts": 1, "sig": "a"}`,
		`{"ci": 1, "t": "bogus", "ts": 1, "sig": "a"}`,
		`{"ci": 1, "t": "request", "ts": 1, "sig": "a"}`,
		`{"ci": 1, "t": "introduction", "ts": 1, "sig": "a"}`,
		`{"ci": 1, "t": "request", "h": "x", "sig": "a"}`,
		`{"cg": 1, "t": "key", "g": "abc"}`,
		`hello world`,
	}
	for _, c := range cases {
		if _, ok := parseIntroductionPayload([]byte(c)); ok {
			t.Fatalf("payload should not parse: %s", c)
		}
	}
}

func TestDismissIntroduction(t *testing.T) {
	alice, carolID, _ := introIdentities(t)
	carol := introClient(t, carolID, map[string]string{"alice": addrOf(alice)})
	raw := signRequest(t, alice, carolID, "bobhandle", "")
	p, _ := parseIntroductionPayload(raw)
	if _, rec := carol.recordIntroduction(addrOf(alice), 1, p); !rec {
		t.Fatal("setup: request not recorded")
	}
	pending := carol.PendingIntroductions()
	if len(pending) != 1 {
		t.Fatalf("setup: want 1 pending, got %d", len(pending))
	}
	// Dismiss by ID prefix.
	if err := carol.DismissIntroduction(pending[0].ID[:8]); err != nil {
		t.Fatal(err)
	}
	if len(carol.PendingIntroductions()) != 0 {
		t.Fatal("dismissed introduction still pending")
	}
	if err := carol.DismissIntroduction("nonexistent"); err == nil {
		t.Fatal("dismissing unknown id should fail")
	}
}

func TestAcceptIntroductionAddsContact(t *testing.T) {
	alice, carolID, bob := introIdentities(t)
	// Fake relay: key lookup 404 (derived-key fallback), send 201.
	var sentTo, sentFrom string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/v1/send", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			To   string `json:"to"`
			From string `json:"from"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		sentTo, sentFrom = req.To, req.From
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 999}`))
	})
	// Directory reverse: alice has public handle "alice".
	mux.HandleFunc("/v1/directory/reverse", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results": []}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	bobClient := introClient(t, bob, map[string]string{"carol": addrOf(carolID)})

	raw := signIntroduction(t, carolID, alice, bob, "alice", "say hi")
	p, _ := parseIntroductionPayload(raw)
	if _, rec := bobClient.recordIntroduction(addrOf(carolID), 7, p); !rec {
		t.Fatal("setup: introduction not recorded")
	}
	// Point at the fake relay after recordIntroduction: the config
	// Update inside recordIntroduction reloads from disk (F5).
	bobClient.cfg.RelayURL = ts.URL
	pending := bobClient.PendingIntroductions()
	if len(pending) != 1 {
		t.Fatalf("setup: want 1 pending, got %d", len(pending))
	}
	if err := bobClient.AcceptIntroduction(pending[0].ID, ""); err != nil {
		t.Fatalf("accept: %v", err)
	}
	// Alice joined contacts under her handle name.
	if got := bobClient.cfg.Contacts["alice"]; got != addrOf(alice) {
		t.Fatalf("contact not added: %v", bobClient.cfg.Contacts)
	}
	// Greeting DM sent to Alice, from Bob.
	if sentTo != addrOf(alice) {
		t.Fatalf("greeting sent to %q, want alice", sentTo)
	}
	if sentFrom != addrOf(bob) {
		t.Fatalf("greeting from %q, want bob", sentFrom)
	}
	// No longer pending.
	if len(bobClient.PendingIntroductions()) != 0 {
		t.Fatal("accepted introduction still pending")
	}
}

func TestAcceptIntroductionRequiresContact(t *testing.T) {
	alice, carolID, bob := introIdentities(t)
	bobClient := introClient(t, bob, map[string]string{"carol": addrOf(carolID)})
	raw := signIntroduction(t, carolID, alice, bob, "alice", "")
	p, _ := parseIntroductionPayload(raw)
	if _, rec := bobClient.recordIntroduction(addrOf(carolID), 7, p); !rec {
		t.Fatal("setup failed")
	}
	// Carol leaves Bob's contacts before accept.
	delete(bobClient.cfg.Contacts, "carol")
	pending := bobClient.PendingIntroductions()
	if err := bobClient.AcceptIntroduction(pending[0].ID, ""); err == nil {
		t.Fatal("accept with untrusted introducer should fail")
	}
}

func TestForwardIntroductionRequest(t *testing.T) {
	alice, carolID, bob := introIdentities(t)
	// Fake relay: keys 404, send 201, directory lookup resolves bob's
	// handle to his address.
	var sentEnv map[string]string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/v1/send", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			To    string `json:"to"`
			From  string `json:"from"`
			Eph   string `json:"eph"`
			Nonce string `json:"nonce"`
			Ct    string `json:"ct"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		sentEnv = map[string]string{
			"to": req.To, "from": req.From,
			"eph": req.Eph, "nonce": req.Nonce, "ct": req.Ct,
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 1000}`))
	})
	mux.HandleFunc("/v1/directory/lookup", func(w http.ResponseWriter, r *http.Request) {
		// Serve a genuinely signed profile: the client verifies the
		// binding before trusting the address.
		canon := envelope.DirectoryRegister("bobhandle", bob.EdPub[:], 1, "public", "open", []string{})
		sig := b64enc(bob.Sign(canon))
		w.Write([]byte(`{"handle":"bobhandle","address":"` + addrOf(bob) + `","capabilities":[],"contact_policy":"open","visibility":"public","epoch":1,"sig":"` + sig + `","registered_at":1}`))
	})
	mux.HandleFunc("/v1/directory/reverse", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results": []}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Carol knows Alice (requester) and Bob (target, as contact "bob").
	carol := introClient(t, carolID, map[string]string{
		"alice": addrOf(alice),
		"bob":   addrOf(bob),
	})

	raw := signRequest(t, alice, carolID, "bobhandle", "old friends")
	p, _ := parseIntroductionPayload(raw)
	if _, rec := carol.recordIntroduction(addrOf(alice), 3, p); !rec {
		t.Fatal("setup: request not recorded")
	}
	// Point at the fake relay after recordIntroduction: the config
	// Update inside recordIntroduction reloads from disk (F5).
	carol.cfg.RelayURL = ts.URL
	pending := carol.PendingIntroductions()
	if len(pending) != 1 {
		t.Fatalf("setup: want 1 pending, got %d", len(pending))
	}
	if err := carol.AcceptIntroductionRequest(pending[0].ID, "vouching for alice"); err != nil {
		t.Fatalf("forward: %v", err)
	}
	// Introduction DM sent to Bob; decrypt and verify the payload.
	if sentEnv["to"] != addrOf(bob) {
		t.Fatalf("introduction sent to %q, want bob", sentEnv["to"])
	}
	if sentEnv["from"] != addrOf(carolID) {
		t.Fatalf("introduction from %q, want carol", sentEnv["from"])
	}
	eph, _ := base64.RawURLEncoding.DecodeString(sentEnv["eph"])
	nonce, _ := base64.RawURLEncoding.DecodeString(sentEnv["nonce"])
	ct, _ := base64.RawURLEncoding.DecodeString(sentEnv["ct"])
	plain, err := crypto.Open(bob.XPriv[:], eph, nonce, ct)
	if err != nil {
		t.Fatalf("cannot decrypt forwarded introduction: %v", err)
	}
	var ip introductionPayload
	if err := json.Unmarshal(plain, &ip); err != nil {
		t.Fatalf("sent body is not an introduction payload: %v", err)
	}
	if ip.Type != "introduction" || ip.Subject != addrOf(alice) {
		t.Fatalf("wrong forwarded payload: %+v", ip)
	}
	// Verify the forwarded signature under Carol's key.
	sig, _ := base64.RawURLEncoding.DecodeString(ip.Sig)
	canon := envelope.Introduction(carolID.EdPub[:], alice.EdPub[:], bob.EdPub[:], ip.Ts)
	if !crypto.Verify(carolID.EdPub[:], canon, sig) {
		t.Fatal("forwarded introduction signature invalid")
	}
	if len(carol.PendingIntroductions()) != 0 {
		t.Fatal("forwarded request still pending")
	}
}

func TestPeerHandleCache(t *testing.T) {
	_, carolID, _ := introIdentities(t)
	carol := introClient(t, carolID, map[string]string{})
	// No relay: reverse fails, PeerHandle returns "" and caches it.
	if h := carol.PeerHandle("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); h != "" {
		t.Fatalf("want empty handle, got %q", h)
	}
	if carol.cfg.HandleCache == nil {
		t.Fatal("cache not populated")
	}
}

func TestResolveHandleTarget(t *testing.T) {
	_, carolID, _ := introIdentities(t)
	carol := introClient(t, carolID, map[string]string{})
	// Non-handle inputs pass through untouched.
	addr, p, isHandle, err := carol.ResolveHandleTarget("ed25519:abc")
	if err != nil || isHandle || addr != "" || p != nil {
		t.Fatalf("non-handle mangled: %v %v %v %v", addr, p, isHandle, err)
	}
	_, _, isHandle, err = carol.ResolveHandleTarget("somecontact")
	if err != nil || isHandle {
		t.Fatalf("contact name treated as handle: %v %v", isHandle, err)
	}
	// Handle forms attempt a lookup (fails: no relay) — but are
	// recognized as handles.
	_, _, isHandle, _ = carol.ResolveHandleTarget("@alice")
	if !isHandle {
		t.Fatal("@alice not recognized as handle")
	}
	_, _, isHandle, _ = carol.ResolveHandleTarget("handle:alice")
	if !isHandle {
		t.Fatal("handle:alice not recognized as handle")
	}
}

// TestVerifyDirectoryProfile: the client accepts register-signed and
// transfer-signed profiles and rejects forged ones (issue #39).
func TestVerifyDirectoryProfile(t *testing.T) {
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	epoch := int64(1000)

	// Fresh registration: sig by the profile address over the register form.
	caps := []string{"chat"}
	canon := envelope.DirectoryRegister("alice", alice.EdPub[:], epoch, "public", "open", caps)
	regProfile := &DirectoryProfile{
		Handle: "alice", Address: addrOf(alice), Capabilities: caps,
		ContactPolicy: "open", Visibility: "public", Epoch: epoch,
		Sig: b64enc(alice.Sign(canon)),
	}
	if err := verifyDirectoryProfile(regProfile); err != nil {
		t.Fatalf("valid registration profile rejected: %v", err)
	}

	// Tampered address: the signature no longer matches.
	tampered := *regProfile
	tampered.Address = addrOf(bob)
	if err := verifyDirectoryProfile(&tampered); err == nil {
		t.Fatal("profile with swapped address accepted")
	}

	// Garbage signature rejected.
	badsig := *regProfile
	badsig.Sig = b64enc([]byte("not a signature, not 64 bytes...................."))
	if err := verifyDirectoryProfile(&badsig); err == nil {
		t.Fatal("profile with bad signature accepted")
	}

	// Transferred handle: sig is the previous holder's transfer
	// signature; transfer_from names the verifying key.
	tcanon := envelope.DirectoryTransfer("alice", bob.EdPub[:], epoch+1)
	xferProfile := &DirectoryProfile{
		Handle: "alice", Address: addrOf(bob), Epoch: epoch + 1,
		ContactPolicy: "open", Visibility: "public",
		Sig:          b64enc(alice.Sign(tcanon)),
		TransferFrom: addrOf(alice),
	}
	if err := verifyDirectoryProfile(xferProfile); err != nil {
		t.Fatalf("valid transfer profile rejected: %v", err)
	}

	// Transfer profile without transfer_from is unverifiable: the sig
	// is not a registration signature by the new owner.
	noProof := *xferProfile
	noProof.TransferFrom = ""
	if err := verifyDirectoryProfile(&noProof); err == nil {
		t.Fatal("transfer profile without transfer_from accepted")
	}

	// Wrong transfer signer rejected.
	wrongSigner := *xferProfile
	wrongSigner.TransferFrom = addrOf(bob)
	if err := verifyDirectoryProfile(&wrongSigner); err == nil {
		t.Fatal("transfer profile with wrong signer accepted")
	}
}

func b64enc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// seedHandleCache stores a fresh directory-handle cache entry, so tests
// can exercise handle-dependent behavior without a relay.
func seedHandleCache(t *testing.T, cfg *Config, address, handle string) {
	t.Helper()
	if err := cfg.Update(func(fresh *Config) error {
		if fresh.HandleCache == nil {
			fresh.HandleCache = map[string]HandleCacheEntry{}
		}
		fresh.HandleCache[address] = HandleCacheEntry{Handle: handle, At: time.Now().Unix()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestContactDisplayName: #146 — the display name defaults to the
// known directory handle; the local alias is the optional override.
func TestContactDisplayName(t *testing.T) {
	_, carolID, bob := introIdentities(t)
	bobAddr := addrOf(bob)

	// Explicit alias wins over a cached handle.
	aliased := introClient(t, carolID, map[string]string{"bobby": bobAddr})
	seedHandleCache(t, aliased.cfg, bobAddr, "bob")
	if got := aliased.ContactDisplayName(bobAddr); got != "bobby" {
		t.Fatalf("alias must win over handle: got %q", got)
	}

	// No contact: the cached directory handle.
	plain := introClient(t, carolID, map[string]string{})
	seedHandleCache(t, plain.cfg, bobAddr, "bob")
	if got := plain.ContactDisplayName(bobAddr); got != "bob" {
		t.Fatalf("want cached handle, got %q", got)
	}

	// Contact named after the handle displays the handle.
	named := introClient(t, carolID, map[string]string{"bob": bobAddr})
	if got := named.ContactDisplayName(bobAddr); got != "bob" {
		t.Fatalf("handle-as-name: got %q", got)
	}

	// Nothing known: truncated address (no relay — reverse fails fast).
	unknown := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if got := plain.ContactDisplayName(unknown); got != shortAddr(unknown) {
		t.Fatalf("want truncated address, got %q", got)
	}
}
