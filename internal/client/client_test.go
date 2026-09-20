package client

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

	msgs, _, skipped, _, err := cl.Inbox(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	// v0.9.1: replays are routine dedup, not failures — suppressed
	// silently so poll-based wake scripts keep their "no new messages."
	// sentinel instead of tripping the corruption warning.
	if len(msgs) != 0 || skipped != 0 {
		t.Fatalf("replay not suppressed silently: msgs=%d skipped=%d", len(msgs), skipped)
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
	msgs, _, skipped, _, err := cl.Inbox(0, 100)
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

	msgs, lastID, skipped, _, err := cl.Inbox(0, 100)
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

	if _, _, _, _, err := cl.Inbox(7, 25); err != nil {
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

// ---- F11: size/count-bounded dashboard push batches ----

// pushTestEnvelope builds a real sealed+signed envelope addressed to cfg
// with the given relay id, for feeding a fake relay inbox.
func pushTestEnvelope(t *testing.T, sender *crypto.Identity, cfg *Config, id int64, body string) map[string]any {
	t.Helper()
	toEd, err := crypto.ParseAddress(cfg.Address)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, err := cfg.currentEncKey()
	if err != nil {
		t.Fatal(err)
	}
	eph, nonce, ct, err := crypto.Seal(&pub, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	sentAt := int64(1700000000) + id
	sig := sender.Sign(envelope.Canonical(toEd[:], sender.EdPub[:], eph, nonce, sentAt, ct))
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{
		"id": id, "from": crypto.FormatAddress(sender.EdPub[:]),
		"eph": enc(eph), "nonce": enc(nonce), "ct": enc(ct),
		"sent_at": sentAt, "received_at": sentAt, "sig": enc(sig),
	}
}

// pushCapture is a fake dashboard /v1/dashboard/push endpoint that
// records each batch's message count and encoded byte size, and can be
// told to fail every batch after the first N successes.
type pushCapture struct {
	batchSizes  []int
	batchCounts []int
	batches     int
	failAfter   int
}

func (pc *pushCapture) handler(envs []map[string]any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/inbox":
			// Honor the client's `after` cursor and `limit` like the
			// real relay.
			after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			var out []map[string]any
			for _, e := range envs {
				if e["id"].(int64) > after {
					out = append(out, e)
				}
			}
			if limit > 0 && len(out) > limit {
				out = out[:limit]
			}
			raw, _ := json.Marshal(map[string]any{"messages": out})
			w.Write(raw)
		case "/v1/dashboard/push":
			raw, _ := io.ReadAll(r.Body)
			pc.batches++
			if pc.failAfter > 0 && pc.batches > pc.failAfter {
				http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
				return
			}
			var req struct {
				Messages []json.RawMessage `json:"messages"`
			}
			_ = json.Unmarshal(raw, &req)
			pc.batchSizes = append(pc.batchSizes, len(raw))
			pc.batchCounts = append(pc.batchCounts, len(req.Messages))
			fmt.Fprintf(w, `{"stored":%d}`, len(req.Messages))
		default:
			http.NotFound(w, r)
		}
	})
}

func TestSplitPushBatchesBounds(t *testing.T) {
	var items []pushItem
	// 450 small messages: forces a count split (200/200/50).
	for i := 0; i < 450; i++ {
		items = append(items, pushItem{msg: pushMsg{CourierID: int64(i + 1), From: "a", Body: "x"}})
	}
	// 100 messages with 10 KiB bodies: forces byte-size splits.
	for i := 0; i < 100; i++ {
		items = append(items, pushItem{sent: true, msg: pushMsg{
			CourierID: int64(1000 + i), From: "a", To: "b",
			Body: strings.Repeat("y", 10<<10),
		}})
	}
	batches := splitPushBatches(items)
	total := 0
	var lastID int64
	for bi, b := range batches {
		if len(b) == 0 {
			t.Fatalf("batch %d is empty", bi)
		}
		if len(b) > maxPushBatchMessages {
			t.Fatalf("batch %d has %d messages, want <= %d", bi, len(b), maxPushBatchMessages)
		}
		msgs := make([]pushMsg, 0, len(b))
		for _, it := range b {
			msgs = append(msgs, it.msg)
			if it.msg.CourierID <= lastID {
				t.Fatalf("batch %d breaks ordering at id %d", bi, it.msg.CourierID)
			}
			lastID = it.msg.CourierID
		}
		raw, _ := json.Marshal(map[string]any{"messages": msgs})
		if len(raw) > maxPushBatchBytes {
			t.Fatalf("batch %d encodes to %d bytes, want <= %d", bi, len(raw), maxPushBatchBytes)
		}
		total += len(b)
	}
	if total != len(items) {
		t.Fatalf("batches cover %d of %d messages", total, len(items))
	}
	if len(batches) < 4 { // 3 count batches + several byte batches
		t.Fatalf("expected several batches, got %d", len(batches))
	}

	// A single message larger than the byte bound still makes progress.
	huge := []pushItem{{msg: pushMsg{CourierID: 1, From: "a", Body: strings.Repeat("z", maxPushBatchBytes)}}}
	if got := splitPushBatches(huge); len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("oversized single message produced %d batches", len(got))
	}
}

func TestDashboardPushBatchesLargeBacklog(t *testing.T) {
	cfg := testConfig(t)
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// 200 inbox messages (a full relay page) with small bodies.
	var envs []map[string]any
	for i := int64(1); i <= 200; i++ {
		envs = append(envs, pushTestEnvelope(t, sender, cfg, i, fmt.Sprintf("hello %d", i)))
	}
	// 150 sent messages with 8 KiB bodies: combined with the inbox
	// page this would be a ~1.4 MiB single request without batching.
	for i := int64(1); i <= 150; i++ {
		if err := appendSentLog(SentEntry{
			CourierID: i, To: "ed25519:peer",
			Body: strings.Repeat("s", 8<<10), SentAt: 1700000000 + i,
		}); err != nil {
			t.Fatal(err)
		}
	}

	pc := &pushCapture{}
	ts := httptest.NewServer(pc.handler(envs))
	t.Cleanup(ts.Close)
	cfg.RelayURL = ts.URL
	cfg.DashboardURL = ts.URL
	cfg.DashboardToken = "test-token"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)

	pushed, err := cl.DashboardPush()
	if err != nil {
		t.Fatal(err)
	}
	if pushed != 350 {
		t.Fatalf("pushed = %d, want 350", pushed)
	}
	if len(pc.batchCounts) < 2 {
		t.Fatalf("expected multiple batches, got %d", len(pc.batchCounts))
	}
	total := 0
	for i, n := range pc.batchCounts {
		if n > maxPushBatchMessages {
			t.Fatalf("batch %d has %d messages, want <= %d", i, n, maxPushBatchMessages)
		}
		if pc.batchSizes[i] > maxPushBatchBytes {
			t.Fatalf("batch %d is %d bytes, want <= %d", i, pc.batchSizes[i], maxPushBatchBytes)
		}
		total += n
	}
	if total != 350 {
		t.Fatalf("batches covered %d messages, want 350", total)
	}
	if cfg.DashboardCursor != 200 {
		t.Fatalf("DashboardCursor = %d, want 200", cfg.DashboardCursor)
	}
	if cfg.DashboardSentCursor != 150 {
		t.Fatalf("DashboardSentCursor = %d, want 150", cfg.DashboardSentCursor)
	}
}

func TestDashboardPushFailedBatchKeepsAckedCursors(t *testing.T) {
	cfg := testConfig(t)
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// 200 inbox messages with 2 KiB bodies: the byte bound splits the
	// relay page into two batches within a single push call.
	var envs []map[string]any
	for i := int64(1); i <= 200; i++ {
		envs = append(envs, pushTestEnvelope(t, sender, cfg, i, strings.Repeat("m", 2<<10)))
	}

	pc := &pushCapture{failAfter: 1} // second batch fails
	ts := httptest.NewServer(pc.handler(envs))
	t.Cleanup(ts.Close)
	cfg.RelayURL = ts.URL
	cfg.DashboardURL = ts.URL
	cfg.DashboardToken = "test-token"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)

	pushed, err := cl.DashboardPush()
	if err == nil {
		t.Fatal("expected an error from the failed batch")
	}
	if pc.batches != 2 {
		t.Fatalf("expected 2 batch attempts, got %d", pc.batches)
	}
	if len(pc.batchCounts) != 1 {
		t.Fatalf("expected 1 acknowledged batch, got %d", len(pc.batchCounts))
	}
	first := pc.batchCounts[0]
	if pushed != first {
		t.Fatalf("pushed = %d, want %d (first batch only)", pushed, first)
	}
	if cfg.DashboardCursor != int64(first) {
		t.Fatalf("DashboardCursor = %d, want %d after partial failure", cfg.DashboardCursor, first)
	}

	// Server recovers: the retry re-fetches the failed batch (its
	// envelopes were never marked seen) and completes the backlog.
	pc.failAfter = 0
	pushed, err = cl.DashboardPush()
	if err != nil {
		t.Fatal(err)
	}
	if pushed != 200-first {
		t.Fatalf("pushed = %d, want %d (remainder only)", pushed, 200-first)
	}
	if cfg.DashboardCursor != 200 {
		t.Fatalf("DashboardCursor = %d, want 200", cfg.DashboardCursor)
	}
}
