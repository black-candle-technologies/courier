package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

func testTLSServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)
	sum := sha256.Sum256(ts.Certificate().Raw)
	return ts, hex.EncodeToString(sum[:])
}

func TestPinnedTransportAcceptsCorrectPin(t *testing.T) {
	ts, fp := testTLSServer(t)
	c := New(&Config{RelayURL: ts.URL, RelayFingerprint: fp})
	hc, err := c.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Get(ts.URL)
	if err != nil {
		t.Fatalf("request with correct pin failed: %v", err)
	}
	resp.Body.Close()
}

func TestPinnedTransportRejectsWrongPin(t *testing.T) {
	ts, _ := testTLSServer(t)
	wrong := strings.Repeat("0", 64)
	c := New(&Config{RelayURL: ts.URL, RelayFingerprint: wrong})
	hc, err := c.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = hc.Get(ts.URL)
	if err == nil {
		t.Fatal("request with wrong pin succeeded")
	}
	if !strings.Contains(err.Error(), "certificate mismatch") {
		t.Fatalf("want certificate mismatch error, got: %v", err)
	}
}

func TestPinnedTransportRequiresPin(t *testing.T) {
	ts, _ := testTLSServer(t)
	c := New(&Config{RelayURL: ts.URL})
	_, err := c.httpClient()
	if err == nil {
		t.Fatal("expected error when no fingerprint is pinned")
	}
	if !strings.Contains(err.Error(), "no pinned certificate") {
		t.Fatalf("want no-pinned-certificate error, got: %v", err)
	}
}

func TestHTTPTransportSkipsPinning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	c := New(&Config{RelayURL: ts.URL})
	if _, err := c.httpClient(); err != nil {
		t.Fatalf("plain http should not require pinning: %v", err)
	}
	if fp, err := FetchRelayFingerprint(ts.URL); err != nil || fp != "" {
		t.Fatalf("FetchRelayFingerprint(http) = %q, %v; want empty", fp, err)
	}
}

// ---- v0.5.0: contacts ----

func testConfig(t *testing.T) *Config {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestContactsAddResolve(t *testing.T) {
	cfg := testConfig(t)
	alice, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddContact("alice", alice.Address); err != nil {
		t.Fatal(err)
	}
	got, err := cfg.LookupContact("alice")
	if err != nil || got != alice.Address {
		t.Fatalf("lookup: got %q, %v", got, err)
	}
	// ResolveRecipient: name and raw address both work.
	if r, err := cfg.ResolveRecipient("alice"); err != nil || r != alice.Address {
		t.Fatalf("resolve name: got %q, %v", r, err)
	}
	if r, err := cfg.ResolveRecipient(alice.Address); err != nil || r != alice.Address {
		t.Fatalf("resolve address: got %q, %v", r, err)
	}
	if _, err := cfg.ResolveRecipient("nobody"); err == nil {
		t.Fatal("expected error for unknown contact")
	}
	if err := cfg.RemoveContact("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.LookupContact("alice"); err == nil {
		t.Fatal("expected error after remove")
	}
}

func TestContactsValidation(t *testing.T) {
	cfg := testConfig(t)
	alice, _ := NewIdentity("")
	for _, bad := range []string{"", "Alice", "a b", "a/b", strings.Repeat("x", 33)} {
		if err := cfg.AddContact(bad, alice.Address); err == nil {
			t.Fatalf("bad name %q accepted", bad)
		}
	}
	if err := cfg.AddContact("bob", "not-an-address"); err == nil {
		t.Fatal("bad address accepted")
	}
	if err := cfg.AddContact("bob", "ed25519:!!!"); err == nil {
		t.Fatal("malformed address accepted")
	}
}

// ---- v0.5.0: rotation ----

// fakeAnn is one canned key-directory announcement served by keyDirServer.
// When sig is empty and signer is set, the server signs the announcement
// properly; noSig forces an unsigned (legacy/malicious) response.
type fakeAnn struct {
	pub    string
	epoch  int64
	signer *crypto.Identity
	sig    string
	noSig  bool
}

// keyDirServer is a fake relay implementing only the key directory.
func keyDirServer(t *testing.T, store map[string]fakeAnn) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("GET /v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		addr := strings.TrimPrefix(r.URL.Path, "/v1/keys/")
		a, ok := store[addr]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sig := a.sig
		if sig == "" && !a.noSig && a.signer != nil {
			toEd, err := crypto.ParseAddress(addr)
			if err != nil {
				t.Errorf("bad canned address: %v", err)
				http.NotFound(w, r)
				return
			}
			pubRaw, err := base64.RawURLEncoding.DecodeString(a.pub)
			if err != nil {
				t.Errorf("bad canned pub: %v", err)
				http.NotFound(w, r)
				return
			}
			sig = base64.RawURLEncoding.EncodeToString(
				a.signer.Sign(envelope.KeyAnnounce(toEd[:], pubRaw, a.epoch)))
		}
		fmt.Fprintf(w, `{"address":%q,"x25519_pub":%q,"epoch":%d,"sig":%q}`,
			addr, a.pub, a.epoch, sig)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestRotatePublishesAndTrialDecrypt(t *testing.T) {
	cfg := testConfig(t)
	oldPub := cfg.EncKeys[0].Pub
	ts := keyDirServer(t, map[string]fakeAnn{})
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	published, err := cl.RotateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("expected published=true")
	}
	if cfg.EncKeys[0].Pub == oldPub {
		t.Fatal("current key did not change after rotation")
	}
	if len(cfg.EncKeys) != 2 {
		t.Fatalf("expected 2 retained keys, got %d", len(cfg.EncKeys))
	}

	// A message sealed to the RETIRED key must still decrypt (trial).
	var oldPubArr [32]byte
	raw, _ := base64.RawURLEncoding.DecodeString(oldPub)
	copy(oldPubArr[:], raw)
	eph, nonce, ct, err := crypto.Seal(&oldPubArr, []byte("hello retired key"))
	if err != nil {
		t.Fatal(err)
	}
	var plain []byte
	for _, xp := range cfg.encryptionPrivKeys() {
		if p, err := crypto.Open(xp[:], eph, nonce, ct); err == nil {
			plain = p
			break
		}
	}
	if string(plain) != "hello retired key" {
		t.Fatalf("trial decryption failed: %q", plain)
	}
}

func TestRecipientKeyFallbackToDerived(t *testing.T) {
	cfg := testConfig(t)
	ts := keyDirServer(t, map[string]fakeAnn{}) // empty: 404s
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	peer, _ := NewIdentity("")
	got, err := cl.recipientKey(peer.Address)
	if err != nil {
		t.Fatal(err)
	}
	// No announcement: must equal the address-derived key.
	toEd, err := crypto.ParseAddress(peer.Address)
	if err != nil {
		t.Fatal(err)
	}
	want, err := crypto.Ed25519PubToX25519(toEd[:])
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("fallback did not return the address-derived key")
	}
}

func TestRecipientKeyUsesAnnouncement(t *testing.T) {
	cfg := testConfig(t)
	peer, _ := NewIdentity("")
	announcedPub := peer.EncKeys[0].Pub
	// The peer signs its own announcement, as the real relay requires.
	peerID, err := peer.Identity()
	if err != nil {
		t.Fatal(err)
	}
	ts := keyDirServer(t, map[string]fakeAnn{
		peer.Address: {pub: announcedPub, epoch: 7, signer: peerID},
	})
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	got, err := cl.recipientKey(peer.Address)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(announcedPub)
	var want [32]byte
	copy(want[:], raw)
	if got != want {
		t.Fatal("did not use the announced key")
	}
	// The verified epoch is recorded for rollback detection.
	if cfg.VerifiedKeyEpochs[peer.Address] != 7 {
		t.Fatalf("verified epoch not recorded: %+v", cfg.VerifiedKeyEpochs)
	}
}

func TestRecipientKeyRejectsUnsignedAnnouncement(t *testing.T) {
	cfg := testConfig(t)
	peer, _ := NewIdentity("")
	ts := keyDirServer(t, map[string]fakeAnn{
		peer.Address: {pub: peer.EncKeys[0].Pub, epoch: 1, noSig: true},
	})
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	if _, err := cl.recipientKey(peer.Address); err == nil {
		t.Fatal("unsigned announcement was accepted; want rejection")
	}
}

func TestRecipientKeyRejectsForgedAnnouncement(t *testing.T) {
	cfg := testConfig(t)
	peer, _ := NewIdentity("")
	attacker, _ := NewIdentity("")
	attackerID, err := attacker.Identity()
	if err != nil {
		t.Fatal(err)
	}
	// Announcement for peer.Address, but signed by the attacker's key:
	// exactly what a malicious relay would serve.
	ts := keyDirServer(t, map[string]fakeAnn{
		peer.Address: {pub: peer.EncKeys[0].Pub, epoch: 1, signer: attackerID},
	})
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	if _, err := cl.recipientKey(peer.Address); err == nil {
		t.Fatal("forged announcement was accepted; want rejection")
	}
}

func TestRecipientKeyRejectsRollback(t *testing.T) {
	cfg := testConfig(t)
	peer, _ := NewIdentity("")
	peerID, err := peer.Identity()
	if err != nil {
		t.Fatal(err)
	}
	announcedPub := peer.EncKeys[0].Pub
	ts := keyDirServer(t, map[string]fakeAnn{
		peer.Address: {pub: announcedPub, epoch: 9, signer: peerID},
	})
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	if _, err := cl.recipientKey(peer.Address); err != nil {
		t.Fatal(err)
	}
	// A validly signed but older announcement must be rejected.
	if _, err := cl.verifyKeyAnnouncement(peer.Address, announcedPub, 4,
		signAnn(t, peerID, peer.Address, announcedPub, 4)); err == nil {
		t.Fatal("rollback to older epoch was accepted; want rejection")
	}
	// Same epoch (re-announcement) is fine.
	if _, err := cl.verifyKeyAnnouncement(peer.Address, announcedPub, 9,
		signAnn(t, peerID, peer.Address, announcedPub, 9)); err != nil {
		t.Fatalf("same-epoch re-announcement rejected: %v", err)
	}
}

// signAnn builds a valid announcement signature for tests.
func signAnn(t *testing.T, id *crypto.Identity, address, pub string, epoch int64) string {
	t.Helper()
	toEd, err := crypto.ParseAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(
		id.Sign(envelope.KeyAnnounce(toEd[:], raw, epoch)))
}


func TestExpectedDashboardFingerprint(t *testing.T) {
	newCfg := func(relay, dash, pin string) *Config {
		return &Config{RelayURL: relay, DashboardURL: dash, RelayFingerprint: pin}
	}
	pin := strings.Repeat("ab", 32)
	// Same host: the relay pin applies.
	c := New(newCfg("https://relay.example:8470", "https://relay.example:8471", pin))
	if got := c.expectedDashboardFingerprint(""); got != pin {
		t.Fatalf("same host: got %q, want relay pin", got)
	}
	// Explicit fingerprint always wins.
	if got := c.expectedDashboardFingerprint("cc"); got != "cc" {
		t.Fatalf("explicit: got %q, want cc", got)
	}
	// Different host: TOFU.
	c = New(newCfg("https://relay.example:8470", "https://dash.example:8471", pin))
	if got := c.expectedDashboardFingerprint(""); got != "" {
		t.Fatalf("different host: got %q, want TOFU", got)
	}
	// No relay pin: TOFU.
	c = New(newCfg("https://relay.example:8470", "https://relay.example:8471", ""))
	if got := c.expectedDashboardFingerprint(""); got != "" {
		t.Fatalf("no pin: got %q, want TOFU", got)
	}
}

func TestDashboardSetupRejectsPinMismatch(t *testing.T) {
	cfg := testConfig(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/dashboard/register" {
			t.Error("registration must not be attempted after a pin mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	cfg.DashboardURL = ts.URL
	// Same host as the relay (127.0.0.1), but a wrong pinned relay
	// fingerprint: the setup must fail closed before registering.
	u, _ := url.Parse(ts.URL)
	cfg.RelayURL = "https://" + u.Hostname() + ":8470"
	cfg.RelayFingerprint = strings.Repeat("00", 32)

	_, err := New(cfg).DashboardSetup("someuser", "")
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("got %v, want a certificate mismatch error", err)
	}
}

// cannedInboxServer serves one fixed /v1/inbox response.
func cannedInboxServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func cannedMessage(from, eph, nonce, ct, sig string, sentAt int64) string {
	return fmt.Sprintf(`{"messages":[{"id":42,"from":%q,"eph":%q,"nonce":%q,"ct":%q,"sent_at":%d,"received_at":%d,"sig":%q}]}`,
		from, eph, nonce, ct, sentAt, sentAt, sig)
}

func TestInboxSuppressesReplayedEnvelopes(t *testing.T) {
	cfg := testConfig(t)
	const sentAt = 1700000000
	ts := cannedInboxServer(t, cannedMessage("ed25519:from", "eph", "nonce", "ct", "sig", sentAt))
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	// Pretend this envelope was already delivered: it must be
	// suppressed even though the relay served it again.
	h := envelope.DedupHash(cfg.Address, "ed25519:from", "eph", "nonce", sentAt, "ct", "sig")
	cfg.SeenEnvelopeHashes = []string{h}

	msgs, _, skipped, err := cl.Inbox(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 || skipped != 1 {
		t.Fatalf("replay not suppressed: msgs=%d skipped=%d", len(msgs), skipped)
	}
}

func TestInboxDoesNotMarkUndeliveredSeen(t *testing.T) {
	cfg := testConfig(t)
	const sentAt = 1700000000
	ts := cannedInboxServer(t, cannedMessage("ed25519:from", "eph", "nonce", "ct", "sig", sentAt))
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	// The canned message fails address parsing, so it is dropped — and
	// must NOT be recorded as seen (it may become readable later).
	msgs, _, skipped, err := cl.Inbox(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 || skipped != 1 {
		t.Fatalf("msgs=%d skipped=%d, want 0/1", len(msgs), skipped)
	}
	if len(cfg.SeenEnvelopeHashes) != 0 {
		t.Fatalf("undelivered message was marked seen: %v", cfg.SeenEnvelopeHashes)
	}
}

func TestRecordSeenEnvelopesBounded(t *testing.T) {
	cfg := testConfig(t)
	cl := New(cfg)
	var hashes []string
	for i := 0; i < maxSeenEnvelopeHashes+10; i++ {
		hashes = append(hashes, fmt.Sprintf("hash-%d", i))
	}
	cl.recordSeenEnvelopes(hashes)
	if len(cfg.SeenEnvelopeHashes) != maxSeenEnvelopeHashes {
		t.Fatalf("want %d hashes, got %d", maxSeenEnvelopeHashes, len(cfg.SeenEnvelopeHashes))
	}
	// Oldest dropped, newest retained.
	if cfg.SeenEnvelopeHashes[0] != "hash-10" {
		t.Fatalf("oldest not dropped: %s", cfg.SeenEnvelopeHashes[0])
	}
	// Re-recording is idempotent.
	cl.recordSeenEnvelopes([]string{"hash-10"})
	if len(cfg.SeenEnvelopeHashes) != maxSeenEnvelopeHashes {
		t.Fatalf("duplicate grew the set: %d", len(cfg.SeenEnvelopeHashes))
	}
}

func TestInboxAdvancesPastUndecryptable(t *testing.T) {
	cfg := testConfig(t)
	// Two undecryptable messages (bad from address): nothing decrypts,
	// but the cursor must still advance past both (F4).
	two := `{"messages":[` +
		`{"id":7,"from":"ed25519:bad1","eph":"e","nonce":"n","ct":"c","sent_at":1700000000,"received_at":1700000000,"sig":"s"},` +
		`{"id":9,"from":"ed25519:bad2","eph":"e","nonce":"n","ct":"c","sent_at":1700000000,"received_at":1700000000,"sig":"s"}]}`

	ts := cannedInboxServer(t, two)
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	msgs, lastID, skipped, err := cl.Inbox(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("want 0 messages, got %d", len(msgs))
	}
	if skipped != 2 {
		t.Fatalf("want 2 skipped, got %d", skipped)
	}
	if lastID != 9 {
		t.Fatalf("lastID = %d, want 9 (highest inspected envelope)", lastID)
	}
}

func TestInboxSendsSignedRequest(t *testing.T) {
	cfg := testConfig(t)
	var gotQ url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQ = r.URL.Query()
		w.Write([]byte(`{"messages":[]}`))
	}))
	t.Cleanup(ts.Close)
	cfg.RelayURL = ts.URL
	cl := New(cfg)

	if _, _, _, err := cl.Inbox(7, 25); err != nil {
		t.Fatal(err)
	}
	if gotQ.Get("to") != cfg.Address || gotQ.Get("after") != "7" || gotQ.Get("limit") != "25" {
		t.Fatalf("bad query params: %v", gotQ)
	}
	toEd, err := crypto.ParseAddress(cfg.Address)
	if err != nil {
		t.Fatal(err)
	}
	var ts64 int64
	if _, err := fmt.Sscanf(gotQ.Get("ts"), "%d", &ts64); err != nil {
		t.Fatalf("bad ts param: %v", gotQ.Get("ts"))
	}
	if now := time.Now().Unix(); ts64 < now-10 || ts64 > now+10 {
		t.Fatalf("ts not fresh: %d", ts64)
	}
	sig, err := base64.RawURLEncoding.DecodeString(gotQ.Get("sig"))
	if err != nil || len(sig) != 64 {
		t.Fatalf("bad sig param: %q", gotQ.Get("sig"))
	}
	// The signature must verify against the client's own address key
	// over the exact requested parameters.
	canon := envelope.InboxRequest(toEd[:], 7, 25, ts64)
	if !crypto.Verify(toEd[:], canon, sig) {
		t.Fatal("client inbox signature does not verify")
	}
}

// TestNewIdentityInitialKeyIsRandom (F13): fresh identities must get an
// independent random initial encryption key, not one derived from the
// permanent identity seed.
func TestNewIdentityInitialKeyIsRandom(t *testing.T) {
	a, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.EncKeys) == 0 || len(b.EncKeys) == 0 {
		t.Fatal("new identity has no encryption keys")
	}
	if a.EncKeys[0].Pub == b.EncKeys[0].Pub {
		t.Fatal("two new identities share the same initial encryption key")
	}
	// The initial key must not be regenerable from the seed.
	idA, err := a.Identity()
	if err != nil {
		t.Fatal(err)
	}
	seedDerived := base64.RawURLEncoding.EncodeToString(idA.XPub[:])
	if a.EncKeys[0].Pub == seedDerived {
		t.Fatal("initial encryption key is still derived from the identity seed")
	}
	// The relay requires a positive announcement epoch.
	if a.EncKeys[0].Epoch <= 0 {
		t.Fatalf("initial epoch = %d, want positive", a.EncKeys[0].Epoch)
	}
}

// TestNewIdentityAnnouncementVerifies (F13): the initial key's signed
// announcement (as PublishKey builds it at init) must verify against the
// identity address.
func TestNewIdentityAnnouncementVerifies(t *testing.T) {
	cfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	id, err := cfg.Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, epoch, err := cfg.currentEncKey()
	if err != nil {
		t.Fatal(err)
	}
	canon := envelope.KeyAnnounce(id.EdPub[:], pub[:], epoch)
	sig := id.Sign(canon)
	toEd, err := crypto.ParseAddress(cfg.Address)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.Verify(toEd[:], canon, sig) {
		t.Fatal("initial key announcement does not verify against the identity address")
	}
}
