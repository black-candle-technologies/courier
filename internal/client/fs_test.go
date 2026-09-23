// Forward-secrecy regression tests (issue #50).
package client

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
)

// fsHarness is two clients with isolated HOME dirs (separate fs.json,
// sent logs, and config locks) against a live test relay.
type fsHarness struct {
	t         *testing.T
	srv       *httptest.Server
	alice     *Client
	bob       *Client
	aliceCfg  *Config
	bobCfg    *Config
	aliceHome string
	bobHome   string
}

func newFSHarness(t *testing.T) *fsHarness {
	t.Helper()
	origHome, _ := os.LookupEnv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(relay.New(st).Routes())
	t.Cleanup(srv.Close)

	aliceHome := t.TempDir()
	bobHome := t.TempDir()
	os.Setenv("HOME", aliceHome)
	aliceCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceCfg.Save(); err != nil {
		t.Fatal(err)
	}
	os.Setenv("HOME", bobHome)
	bobCfg, err := NewIdentity(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := bobCfg.Save(); err != nil {
		t.Fatal(err)
	}
	// Publish both encryption keys so sealed DMs use the keys the
	// recipients actually hold (NewIdentity generates random keys;
	// without this the relay 404s and senders fall back to the
	// address-derived key nobody holds).
	os.Setenv("HOME", aliceHome)
	if err := New(aliceCfg).PublishKey(); err != nil {
		t.Fatal(err)
	}
	os.Setenv("HOME", bobHome)
	if err := New(bobCfg).PublishKey(); err != nil {
		t.Fatal(err)
	}
	os.Setenv("HOME", origHome)
	return &fsHarness{
		t: t, srv: srv,
		alice: New(aliceCfg), bob: New(bobCfg),
		aliceCfg: aliceCfg, bobCfg: bobCfg,
		aliceHome: aliceHome, bobHome: bobHome,
	}
}

// asAlice / asBob run fn with HOME pointed at that client's dir, so
// fs.json, the sent log, and the config lock resolve to the right place.
func (h *fsHarness) asAlice(fn func()) {
	h.t.Helper()
	prev, _ := os.LookupEnv("HOME")
	os.Setenv("HOME", h.aliceHome)
	defer os.Setenv("HOME", prev)
	fn()
}

func (h *fsHarness) asBob(fn func()) {
	h.t.Helper()
	prev, _ := os.LookupEnv("HOME")
	os.Setenv("HOME", h.bobHome)
	defer os.Setenv("HOME", prev)
	fn()
}

func (h *fsHarness) aliceInbox(t *testing.T) []Message {
	t.Helper()
	var msgs []Message
	h.asAlice(func() {
		var err error
		var skipped int
		msgs, _, skipped, _, err = h.alice.Inbox(0, 50)
		if err != nil {
			t.Fatalf("alice inbox: %v", err)
		}
		if skipped != 0 {
			t.Fatalf("alice inbox skipped %d", skipped)
		}
	})
	return msgs
}

func (h *fsHarness) bobInbox(t *testing.T) []Message {
	t.Helper()
	var msgs []Message
	h.asBob(func() {
		var err error
		var skipped int
		msgs, _, skipped, _, err = h.bob.Inbox(0, 50)
		if err != nil {
			t.Fatalf("bob inbox: %v", err)
		}
		if skipped != 0 {
			t.Fatalf("bob inbox skipped %d", skipped)
		}
	})
	return msgs
}

// doHandshake runs the full init/accept exchange and asserts both sides
// end up with an established session.
func (h *fsHarness) doHandshake(t *testing.T) {
	t.Helper()
	h.asAlice(func() {
		if err := h.alice.FSSetPeerMode(h.bobCfg.Address, "on"); err != nil {
			t.Fatalf("alice fs on: %v", err)
		}
	})
	// Bob's inbox consumes the init and sends the accept (silently).
	if msgs := h.bobInbox(t); len(msgs) != 0 {
		t.Fatalf("bob inbox: got %d chat messages, want 0 (handshake is silent)", len(msgs))
	}
	// Alice's inbox consumes the accept (silently).
	if msgs := h.aliceInbox(t); len(msgs) != 0 {
		t.Fatalf("alice inbox: got %d chat messages, want 0 (handshake is silent)", len(msgs))
	}
	h.asAlice(func() {
		infos, err := h.alice.FSStatus(h.bobCfg.Address)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || !infos[0].Established {
			t.Fatalf("alice session not established: %+v", infos)
		}
	})
	h.asBob(func() {
		infos, err := h.bob.FSStatus(h.aliceCfg.Address)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || !infos[0].Established {
			t.Fatalf("bob session not established: %+v", infos)
		}
	})
}

func TestFSHandshakeAndMessaging(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)

	// Alice -> Bob over FS.
	h.asAlice(func() {
		if _, err := h.alice.Send(h.bobCfg.Address, "hello fs"); err != nil {
			t.Fatalf("alice send: %v", err)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "hello fs" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
	// Bob -> Alice over FS (exercises the DH ratchet on reply).
	h.asBob(func() {
		if _, err := h.bob.Send(h.aliceCfg.Address, "hi back"); err != nil {
			t.Fatalf("bob send: %v", err)
		}
	})
	msgs = h.aliceInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "hi back" {
		t.Fatalf("alice inbox: %+v", msgs)
	}
	// A few more rounds to exercise chain + DH ratchet advancement.
	for i := 0; i < 5; i++ {
		h.asAlice(func() {
			if _, err := h.alice.Send(h.bobCfg.Address, "ping"); err != nil {
				t.Fatalf("alice send: %v", err)
			}
		})
	}
	msgs = h.bobInbox(t)
	if len(msgs) != 5 {
		t.Fatalf("bob inbox: got %d messages, want 5", len(msgs))
	}
	h.asBob(func() {
		infos, _ := h.bob.FSStatus(h.aliceCfg.Address)
		if len(infos) != 1 || infos[0].MsgsRecvd != 6 {
			t.Fatalf("bob msgs received: %+v", infos)
		}
	})
}

// TestFSOutOfOrder decrypts FS messages out of order at the session
// level, exercising the skipped-key window.
func TestFSOutOfOrder(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)

	// Alice seals three messages; capture the raw frames.
	var frames [][]byte
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess := ff.session(h.bobCfg.Address)
		if sess == nil || !sess.Established {
			t.Fatal("no established session")
		}
		for _, body := range []string{"m0", "m1", "m2"} {
			var updErr error
			var out *fsSendOutput
			updErr = updateFS(func(ff *fsFile) error {
				var err error
				out, err = fsAdvanceSendLocked(ff.session(h.bobCfg.Address))
				return err
			})
			if updErr != nil {
				t.Fatal(updErr)
			}
			raw, err := fsSealMessage(out, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			frames = append(frames, raw)
		}
	})
	// Bob decrypts out of order: 2, 0, 1.
	var got []string
	h.asBob(func() {
		for _, idx := range []int{2, 0, 1} {
			var p fsPayload
			if err := json.Unmarshal(frames[idx], &p); err != nil {
				t.Fatal(err)
			}
			plain, wk, err := h.bob.fsDecryptMessage(h.aliceCfg.Address, p)
			if err != nil {
				t.Fatalf("decrypt frame %d: %v", idx, err)
			}
			if wk != nil {
				crypto.Zero(wk[:])
			}
			got = append(got, string(plain))
		}
	})
	if len(got) != 3 || got[0] != "m2" || got[1] != "m0" || got[2] != "m1" {
		t.Fatalf("out-of-order decrypt: %q", got)
	}
	// Replaying frame 0 must now fail.
	h.asBob(func() {
		var p fsPayload
		if err := json.Unmarshal(frames[0], &p); err != nil {
			t.Fatal(err)
		}
		if _, _, err := h.bob.fsDecryptMessage(h.aliceCfg.Address, p); err == nil {
			t.Fatal("replay of consumed frame succeeded, want failure")
		}
	})
}

// TestFSLegacyFallback: with no capability knowledge, DMs stay legacy
// and no handshake is attempted.
func TestFSLegacyFallback(t *testing.T) {
	h := newFSHarness(t)
	h.asAlice(func() {
		if _, err := h.alice.Send(h.bobCfg.Address, "legacy hello"); err != nil {
			t.Fatalf("alice send: %v", err)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "legacy hello" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
	h.asAlice(func() {
		infos, err := h.alice.FSStatus(h.bobCfg.Address)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 0 {
			t.Fatalf("unexpected FS session: %+v", infos)
		}
		if _, err := os.Stat(filepath.Join(h.aliceHome, ".courier", "fs.json")); err == nil {
			// fs.json may exist (neg cache) but must hold no session.
			ff, err := loadFS()
			if err != nil {
				t.Fatal(err)
			}
			if len(ff.Sessions) != 0 {
				t.Fatalf("unexpected sessions in fs.json")
			}
		}
	})
}

// TestFSOffDisablesAndErases: `fs off` erases the session and later
// messages go legacy.
func TestFSOffDisablesAndErases(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	h.asAlice(func() {
		if err := h.alice.FSSetPeerMode(h.bobCfg.Address, "off"); err != nil {
			t.Fatalf("fs off: %v", err)
		}
		infos, err := h.alice.FSStatus(h.bobCfg.Address)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 0 {
			t.Fatalf("session not erased: %+v", infos)
		}
		if _, err := h.alice.Send(h.bobCfg.Address, "back to legacy"); err != nil {
			t.Fatalf("send: %v", err)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "back to legacy" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// TestFSForget: forget erases the session and pins the peer off.
func TestFSForget(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	h.asAlice(func() {
		if err := h.alice.FSForget(h.bobCfg.Address); err != nil {
			t.Fatalf("forget: %v", err)
		}
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if ff.session(h.bobCfg.Address) != nil {
			t.Fatal("session survived forget")
		}
		if ff.PeerModes[h.bobCfg.Address] != "off" {
			t.Fatalf("peer mode not pinned off: %q", ff.PeerModes[h.bobCfg.Address])
		}
	})
}

// TestFSRekeyRotates: rekey forces a new ratchet key on the next send,
// and the old chain key is no longer on disk.
func TestFSRekeyRotates(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	var beforePub, beforeChain string
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess := ff.session(h.bobCfg.Address)
		beforePub, beforeChain = sess.RatchetPub, sess.SendChain
		if err := h.alice.FSRekey(h.bobCfg.Address); err != nil {
			t.Fatalf("rekey: %v", err)
		}
		if _, err := h.alice.Send(h.bobCfg.Address, "after rekey"); err != nil {
			t.Fatalf("send: %v", err)
		}
		ff2, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess2 := ff2.session(h.bobCfg.Address)
		if sess2.RatchetPub == beforePub {
			t.Fatal("ratchet public key unchanged after rekey")
		}
		if sess2.SendChain == beforeChain {
			t.Fatal("send chain unchanged after rekey")
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "after rekey" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// TestFSHandshakeNotInSentLog: init/accept frames are machine traffic
// and must never appear in the local sent log (dashboard threads it).
func TestFSHandshakeNotInSentLog(t *testing.T) {
	h := newFSHarness(t)
	h.asAlice(func() {
		if err := h.alice.FSSetPeerMode(h.bobCfg.Address, "on"); err != nil {
			t.Fatalf("fs on: %v", err)
		}
	})
	h.bobInbox(t)   // consumes init, sends accept
	h.aliceInbox(t) // consumes accept
	for _, home := range []string{h.aliceHome, h.bobHome} {
		data, err := os.ReadFile(filepath.Join(home, ".courier", "sent.jsonl"))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if len(data) != 0 {
			t.Fatalf("sent log in %s is not empty: %q", home, data)
		}
	}
}

// TestFSRestoreErasesSessions: restoring a backup wipes fs.json — the
// restored identity is a new device.
func TestFSRestoreErasesSessions(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	h.asAlice(func() {
		if _, err := os.Stat(filepath.Join(h.aliceHome, ".courier", "fs.json")); err != nil {
			t.Fatalf("fs.json missing before restore: %v", err)
		}
		raw, err := h.aliceCfg.CreateBackup([]byte("test-passphrase"), crypto.BackupKindBackup, "test-device")
		if err != nil {
			t.Fatalf("create backup: %v", err)
		}
		if _, err := RestoreBackup([]byte("test-passphrase"), raw, true); err != nil {
			t.Fatalf("restore: %v", err)
		}
		if _, err := os.Stat(filepath.Join(h.aliceHome, ".courier", "fs.json")); !os.IsNotExist(err) {
			t.Fatal("fs.json survived backup restore")
		}
	})
}

// TestFSBackupExcludesSessionKeys: session key material must not be
// recoverable from a backup envelope.
func TestFSBackupExcludesSessionKeys(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		rootKey := ff.session(h.bobCfg.Address).RootKey
		if rootKey == "" {
			t.Fatal("no root key in session")
		}
		raw, err := h.aliceCfg.CreateBackup([]byte("test-passphrase"), crypto.BackupKindBackup, "test-device")
		if err != nil {
			t.Fatalf("create backup: %v", err)
		}
		if strings.Contains(string(raw), rootKey) {
			t.Fatal("backup envelope contains the FS root key")
		}
		p, err := crypto.OpenBackup([]byte("test-passphrase"), raw)
		if err != nil {
			t.Fatalf("open backup: %v", err)
		}
		pj, _ := json.Marshal(p)
		for _, field := range []string{rootKey, ff.session(h.bobCfg.Address).SendChain, ff.session(h.bobCfg.Address).RecvChain} {
			if field != "" && strings.Contains(string(pj), field) {
				t.Fatalf("backup payload leaks FS key material")
			}
		}
	})
}

// TestFSAttachmentRoundTrip: attachments on FS messages unwrap with the
// message-derived key and round-trip byte-identical.
func TestFSAttachmentRoundTrip(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	content := []byte("forward-secret file contents")
	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	h.asAlice(func() {
		if _, err := h.alice.SendWithAttachments(h.bobCfg.Address, "see attached", []string{path}); err != nil {
			t.Fatalf("send: %v", err)
		}
	})
	var msgs []Message
	h.asBob(func() {
		var err error
		var skipped int
		msgs, _, skipped, _, err = h.bob.Inbox(0, 50)
		if err != nil {
			t.Fatalf("bob inbox: %v", err)
		}
		if skipped != 0 {
			t.Fatalf("bob inbox skipped %d", skipped)
		}
	})
	if len(msgs) != 1 || len(msgs[0].Attachments) != 1 {
		t.Fatalf("bob inbox: %+v", msgs)
	}
	ia := msgs[0].Attachments[0]
	if ia.KeyError != nil {
		t.Fatalf("attachment key unwrap: %v", ia.KeyError)
	}
	// The manifest went over FS: Eph is the zero marker, not a real key.
	if strings.Trim(ia.Manifest.Keys[0].Eph, "A") != "" {
		t.Fatalf("expected zero Eph marker on FS attachment, got %q", ia.Manifest.Keys[0].Eph)
	}
	blob, err := func() ([]byte, error) {
		var data []byte
		var derr error
		h.asBob(func() {
			data, derr = h.bob.DownloadAttachment(ia)
		})
		return data, derr
	}()
	if err != nil {
		t.Fatalf("download attachment: %v", err)
	}
	if string(blob) != string(content) {
		t.Fatal("attachment contents mismatch")
	}
}

// TestFSMigrationNoState: a config with no fs.json at all sends and
// receives legacy DMs fine (upgrade path for pre-0.11.0 installs).
func TestFSMigrationNoState(t *testing.T) {
	h := newFSHarness(t)
	h.asAlice(func() {
		if _, err := os.Stat(filepath.Join(h.aliceHome, ".courier", "fs.json")); !os.IsNotExist(err) {
			t.Fatal("fs.json should not exist yet")
		}
		if _, err := h.alice.Send(h.bobCfg.Address, "pre-fs install"); err != nil {
			t.Fatalf("send: %v", err)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "pre-fs install" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// TestAdvertiseFSCap: the fs token is added once, and never pushes user
// tokens over the directory capability budget.
func TestAdvertiseFSCap(t *testing.T) {
	got := advertiseFSCap([]string{"a", "b"})
	if len(got) != 3 || got[2] != "fs" {
		t.Fatalf("advertise: %q", got)
	}
	got = advertiseFSCap([]string{"fs", "a"})
	if len(got) != 2 {
		t.Fatalf("duplicate fs: %q", got)
	}
	full := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	got = advertiseFSCap(full)
	if len(got) != 8 {
		t.Fatalf("budget overflow: %q", got)
	}
}

// TestParseFSPayloadRejectsJunk: malformed or foreign frames never
// intercept ordinary messages.
func TestParseFSPayloadRejectsJunk(t *testing.T) {
	for _, s := range []string{
		`hello world`,
		`{"cf":3,"t":"nope","v":1}`,
		`{"cf":1,"t":"fs-msg","v":1}`,
		`{"cf":3,"t":"fs-msg","v":999}`,
		`{"cf":3}`,
		`[1,2,3]`,
		``,
	} {
		if _, ok := parseFSPayload([]byte(s)); ok {
			t.Fatalf("parseFSPayload accepted %q", s)
		}
	}
	p, ok := parseFSPayload([]byte(`{"cf":3,"t":"fs-msg","v":1,"sid":"x"}`))
	if !ok || p.Type != fsTypeMsg {
		t.Fatal("valid fs-msg frame rejected")
	}
}

// ---- FS suite negotiation tests (issue #138) ----

var fsV1ID = string(crypto.FSSuiteV1)

// fsTestInit builds a well-formed fs-init payload with the given suite
// offer (nil = legacy pre-negotiation init).
func fsTestInit(t *testing.T, suites []string) fsPayload {
	t.Helper()
	rk0, err := fsRand32()
	if err != nil {
		t.Fatal(err)
	}
	ephPub, _, err := fsGenX25519()
	if err != nil {
		t.Fatal(err)
	}
	rPub, _, err := fsGenX25519()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := fsRand16()
	if err != nil {
		t.Fatal(err)
	}
	initID, err := fsRand16()
	if err != nil {
		t.Fatal(err)
	}
	return fsPayload{
		Magic: fsMagic, Type: fsTypeInit, Version: fsPayloadVersion,
		SID: b64fs.EncodeToString(sid[:]), InitID: b64fs.EncodeToString(initID[:]),
		RK0: b64fs.EncodeToString(rk0[:]), EphPub: b64fs.EncodeToString(ephPub[:]),
		RPub: b64fs.EncodeToString(rPub[:]), Suites: suites,
	}
}

// fsTestAccept builds a well-formed fs-accept for initID/sid with the
// given suite selection ("" = legacy pre-negotiation accept).
func fsTestAccept(t *testing.T, initID, sid, suite string) fsPayload {
	t.Helper()
	ephPub, _, err := fsGenX25519()
	if err != nil {
		t.Fatal(err)
	}
	rPub, _, err := fsGenX25519()
	if err != nil {
		t.Fatal(err)
	}
	return fsPayload{
		Magic: fsMagic, Type: fsTypeAccept, Version: fsPayloadVersion,
		SID: sid, InitID: initID,
		EphPub: b64fs.EncodeToString(ephPub[:]), RPub: b64fs.EncodeToString(rPub[:]),
		Suite: suite,
	}
}

// fsPlantPending writes a pending (unestablished) init session into the
// client's fs.json and returns its InitID/SID. asWho selects whose HOME
// (and thus whose fs.json) is used.
func fsPlantPending(t *testing.T, asWho func(func()), peer string, offered []string) (initID, sid string) {
	t.Helper()
	rk0, err := fsRand32()
	if err != nil {
		t.Fatal(err)
	}
	_, ephPriv, err := fsGenX25519()
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := fsGenX25519()
	if err != nil {
		t.Fatal(err)
	}
	sidB, err := fsRand16()
	if err != nil {
		t.Fatal(err)
	}
	initIDB, err := fsRand16()
	if err != nil {
		t.Fatal(err)
	}
	initID = b64fs.EncodeToString(initIDB[:])
	sid = b64fs.EncodeToString(sidB[:])
	asWho(func() {
		if err := updateFS(func(ff *fsFile) error {
			ff.Sessions[peer] = &fsSession{
				Peer: peer, SID: sid, Initiator: true,
				InitID: initID, RK0: b64fs.EncodeToString(rk0[:]),
				EphPriv:     b64fs.EncodeToString(ephPriv[:]),
				RatchetPriv: b64fs.EncodeToString(rPriv[:]),
				RatchetPub:  b64fs.EncodeToString(rPub[:]),
				Offered:     offered,
				Skipped:     map[string]string{},
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	return initID, sid
}

// fsSessionOf reads one session from the client's fs.json.
func fsSessionOf(t *testing.T, asWho func(func()), peer string) *fsSession {
	t.Helper()
	var sess *fsSession
	asWho(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess = ff.Sessions[peer]
	})
	return sess
}

// The responder selects its most-preferred overlap and never invents a
// suite; with no overlap there is no handshake.
func TestFSSelectSuite(t *testing.T) {
	if s, ok := fsSelectSuite([]string{fsV1ID}); !ok || s != crypto.FSSuiteV1 {
		t.Fatalf("select([v1]) = %q, %v", s, ok)
	}
	// Unknown entries are skipped, not selected.
	if s, ok := fsSelectSuite([]string{"x25519-hkdf-sha256-v99", fsV1ID}); !ok || s != crypto.FSSuiteV1 {
		t.Fatalf("select([unknown, v1]) = %q, %v", s, ok)
	}
	// Most-preferred overlap wins (offer order = initiator preference).
	if s, ok := fsSelectSuite([]string{fsV1ID, "x25519-hkdf-sha256-v99"}); !ok || s != crypto.FSSuiteV1 {
		t.Fatalf("select([v1, unknown]) = %q, %v", s, ok)
	}
	if _, ok := fsSelectSuite([]string{"x25519-hkdf-sha256-v99"}); ok {
		t.Fatal("select([unknown]) unexpectedly succeeded")
	}
	if _, ok := fsSelectSuite(nil); ok {
		t.Fatal("select(nil) unexpectedly succeeded")
	}
}

// The initiator accepts only a selection it actually offered and that
// this build implements.
func TestFSCheckSelectedSuite(t *testing.T) {
	offered := []string{"x25519-hkdf-sha256-v99", fsV1ID}
	if s, err := fsCheckSelectedSuite(fsV1ID, offered); err != nil || s != crypto.FSSuiteV1 {
		t.Fatalf("check(v1, offered) = %q, %v", s, err)
	}
	if _, err := fsCheckSelectedSuite(fsV1ID, []string{"x25519-hkdf-sha256-v99"}); err == nil {
		t.Fatal("unoffered selection unexpectedly accepted")
	}
	if _, err := fsCheckSelectedSuite("x25519-hkdf-sha256-v99", offered); err == nil {
		t.Fatal("unknown suite selection unexpectedly accepted")
	}
	if _, err := fsCheckSelectedSuite(fsV1ID, nil); err == nil {
		t.Fatal("selection against empty offer unexpectedly accepted")
	}
}

// Full network handshake negotiates v1: both sides record the suite,
// pin the peer, and the session carries traffic.
func TestFSSuiteNegotiatedV1(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)

	for _, tc := range []struct {
		c     *Client
		asWho func(func())
		peer  string
	}{
		{h.alice, h.asAlice, h.bobCfg.Address},
		{h.bob, h.asBob, h.aliceCfg.Address},
	} {
		var infos []FSSessionInfo
		tc.asWho(func() {
			var err error
			infos, err = tc.c.FSStatus(tc.peer)
			if err != nil {
				t.Fatal(err)
			}
		})
		if len(infos) != 1 || !infos[0].Established {
			t.Fatalf("session not established: %+v", infos)
		}
		if infos[0].Suite != fsV1ID {
			t.Fatalf("negotiated suite = %q, want %q", infos[0].Suite, fsV1ID)
		}
		// The TOFU downgrade pin is set on both sides.
		tc.asWho(func() {
			ff, err := loadFS()
			if err != nil {
				t.Fatal(err)
			}
			if ff.FSNegotiated[tc.peer] != fsV1ID {
				t.Fatalf("FSNegotiated pin = %q, want %q", ff.FSNegotiated[tc.peer], fsV1ID)
			}
		})
	}

	// The negotiated session carries traffic both ways.
	h.asAlice(func() {
		if _, err := h.alice.Send(h.bobCfg.Address, "negotiated v1"); err != nil {
			t.Fatalf("alice send: %v", err)
		}
	})
	if msgs := h.bobInbox(t); len(msgs) != 1 || msgs[0].Body != "negotiated v1" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// An init whose offer has no overlap with our suites is ignored: no
// session, no handshake — fail closed, never a silent v1 assumption.
func TestFSSuiteInitNoCommonSuite(t *testing.T) {
	h := newFSHarness(t)
	init := fsTestInit(t, []string{"x25519-hkdf-sha256-v99"})
	h.asBob(func() { h.bob.handleFSInit(h.aliceCfg.Address, init) })
	if sess := fsSessionOf(t, h.asBob, h.aliceCfg.Address); sess != nil {
		t.Fatalf("session created despite no common suite: %+v", sess)
	}
}

// An accept selecting a suite that was never offered aborts the
// handshake: the session stays pending.
func TestFSSuiteAcceptUnofferedSelection(t *testing.T) {
	h := newFSHarness(t)
	initID, sid := fsPlantPending(t, h.asAlice, h.bobCfg.Address, []string{"x25519-hkdf-sha256-v99"})
	acc := fsTestAccept(t, initID, sid, fsV1ID)
	h.asAlice(func() { h.alice.handleFSAccept(h.bobCfg.Address, acc) })
	sess := fsSessionOf(t, h.asAlice, h.bobCfg.Address)
	if sess == nil || sess.Established {
		t.Fatalf("unoffered selection established a session: %+v", sess)
	}
}

// An accept selecting an unknown suite aborts the handshake.
func TestFSSuiteAcceptUnknownSelection(t *testing.T) {
	h := newFSHarness(t)
	initID, sid := fsPlantPending(t, h.asAlice, h.bobCfg.Address, []string{fsV1ID})
	acc := fsTestAccept(t, initID, sid, "x25519-hkdf-sha256-v99")
	h.asAlice(func() { h.alice.handleFSAccept(h.bobCfg.Address, acc) })
	sess := fsSessionOf(t, h.asAlice, h.bobCfg.Address)
	if sess == nil || sess.Established {
		t.Fatalf("unknown selection established a session: %+v", sess)
	}
}

// A valid selection establishes: suite recorded, offer erased, peer pinned.
func TestFSSuiteAcceptValidSelection(t *testing.T) {
	h := newFSHarness(t)
	initID, sid := fsPlantPending(t, h.asAlice, h.bobCfg.Address, []string{"x25519-hkdf-sha256-v99", fsV1ID})
	acc := fsTestAccept(t, initID, sid, fsV1ID)
	h.asAlice(func() { h.alice.handleFSAccept(h.bobCfg.Address, acc) })
	sess := fsSessionOf(t, h.asAlice, h.bobCfg.Address)
	if sess == nil || !sess.Established {
		t.Fatalf("valid selection did not establish: %+v", sess)
	}
	if sess.Suite != fsV1ID {
		t.Fatalf("session suite = %q, want %q", sess.Suite, fsV1ID)
	}
	if len(sess.Offered) != 0 || sess.RK0 != "" || sess.EphPriv != "" {
		t.Fatal("handshake secrets not erased at establishment")
	}
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if ff.FSNegotiated[h.bobCfg.Address] != fsV1ID {
			t.Fatalf("FSNegotiated pin = %q, want %q", ff.FSNegotiated[h.bobCfg.Address], fsV1ID)
		}
	})
}

// Downgrade resistance, initiator side: a peer pinned as negotiating
// that stops offering suites gets its init ignored.
func TestFSSuiteDowngradePinInit(t *testing.T) {
	h := newFSHarness(t)
	h.asBob(func() {
		if err := updateFS(func(ff *fsFile) error {
			fsPinNegotiatedLocked(ff, h.aliceCfg.Address, crypto.FSSuiteV1)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	init := fsTestInit(t, nil) // legacy init: suites stripped
	h.asBob(func() { h.bob.handleFSInit(h.aliceCfg.Address, init) })
	if sess := fsSessionOf(t, h.asBob, h.aliceCfg.Address); sess != nil {
		t.Fatalf("downgraded init created a session: %+v", sess)
	}
}

// Downgrade resistance, responder side: a peer pinned as negotiating
// that stops selecting a suite gets its accept ignored.
func TestFSSuiteDowngradePinAccept(t *testing.T) {
	h := newFSHarness(t)
	initID, sid := fsPlantPending(t, h.asAlice, h.bobCfg.Address, []string{fsV1ID})
	h.asAlice(func() {
		if err := updateFS(func(ff *fsFile) error {
			fsPinNegotiatedLocked(ff, h.bobCfg.Address, crypto.FSSuiteV1)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	acc := fsTestAccept(t, initID, sid, "") // legacy accept: selection stripped
	h.asAlice(func() { h.alice.handleFSAccept(h.bobCfg.Address, acc) })
	sess := fsSessionOf(t, h.asAlice, h.bobCfg.Address)
	if sess == nil || sess.Established {
		t.Fatalf("downgraded accept established a session: %+v", sess)
	}
}

// Legacy interop: an unoffered init from an unpinned (older) peer still
// completes as v1, exactly like the pre-negotiation handshake.
func TestFSSuiteLegacyInitInterop(t *testing.T) {
	h := newFSHarness(t)
	init := fsTestInit(t, nil)
	h.asBob(func() { h.bob.handleFSInit(h.aliceCfg.Address, init) })
	sess := fsSessionOf(t, h.asBob, h.aliceCfg.Address)
	if sess == nil || !sess.Established {
		t.Fatalf("legacy init did not establish: %+v", sess)
	}
	if sess.Suite != fsV1ID {
		t.Fatalf("legacy session suite = %q, want %q", sess.Suite, fsV1ID)
	}
}

// Legacy interop: a suitless accept for an unoffered pending init still
// completes as v1.
func TestFSSuiteLegacyAcceptInterop(t *testing.T) {
	h := newFSHarness(t)
	initID, sid := fsPlantPending(t, h.asAlice, h.bobCfg.Address, nil)
	acc := fsTestAccept(t, initID, sid, "")
	h.asAlice(func() { h.alice.handleFSAccept(h.bobCfg.Address, acc) })
	sess := fsSessionOf(t, h.asAlice, h.bobCfg.Address)
	if sess == nil || !sess.Established {
		t.Fatalf("legacy accept did not establish: %+v", sess)
	}
	if sess.Suite != fsV1ID {
		t.Fatalf("legacy session suite = %q, want %q", sess.Suite, fsV1ID)
	}
}
