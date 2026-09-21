// Forward-secrecy fail-closed policy, capability pinning, and downgrade
// warnings (issue #110).
package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFSRequireFailsClosed: with require_fs set and no established
// session, sends fail closed (errFSRequired) instead of silently
// falling back to legacy. A pending (unaccepted) handshake is not
// enough — only an established session unlocks sends.
func TestFSRequireFailsClosed(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		if err := h.alice.FSSetRequireFS(bob, true); err != nil {
			t.Fatalf("fs require: %v", err)
		}
		if _, err := h.alice.Send(bob, "must not go"); !errors.Is(err, errFSRequired) {
			t.Fatalf("send without session: want errFSRequired, got %v", err)
		}
		// Initiate, but the accept hasn't arrived: still fail closed.
		if err := h.alice.FSSetPeerMode(bob, "on"); err != nil {
			t.Fatalf("fs on: %v", err)
		}
		if _, err := h.alice.Send(bob, "still must not go"); !errors.Is(err, errFSRequired) {
			t.Fatalf("send with pending handshake: want errFSRequired, got %v", err)
		}
	})
	// Bob's inbox consumes the init (silently) and answers.
	if msgs := h.bobInbox(t); len(msgs) != 0 {
		t.Fatalf("bob inbox: got %d chat messages during suppression, want 0", len(msgs))
	}
	if msgs := h.aliceInbox(t); len(msgs) != 0 {
		t.Fatalf("alice inbox: got %d chat messages, want 0", len(msgs))
	}
	// Session established: sends now work, over FS, with the policy
	// visible in status.
	h.asAlice(func() {
		if _, err := h.alice.Send(bob, "fs now"); err != nil {
			t.Fatalf("send after handshake: %v", err)
		}
		infos, err := h.alice.FSStatus(bob)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || !infos[0].Established || !infos[0].RequireFS {
			t.Fatalf("status: %+v (want established + require-fs)", infos)
		}
		if infos[0].MsgsSent != 1 {
			t.Fatalf("msgs sent: %d, want 1 (the refused sends must not count)", infos[0].MsgsSent)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "fs now" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// TestFSRequireDefaultFailOpen: without the policy, behavior is
// unchanged — unknown peers fall back to legacy silently.
func TestFSRequireDefaultFailOpen(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		required, err := h.alice.FSRequireForPeer(bob)
		if err != nil {
			t.Fatal(err)
		}
		if required {
			t.Fatal("require_fs must default to off")
		}
		if _, err := h.alice.Send(bob, "legacy hello"); err != nil {
			t.Fatalf("send: %v", err)
		}
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if len(ff.RequireFS) != 0 {
			t.Fatalf("RequireFS should be empty by default: %v", ff.RequireFS)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "legacy hello" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// TestFSRequireHandshakeSuppressedThenRecovers simulates a relay that
// suppresses handshake traffic (envelopes never delivered) and then
// resets: while suppressed, require_fs sends fail closed; once the
// relay delivers again, the handshake completes and sends flow.
func TestFSRequireHandshakeSuppressedThenRecovers(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		if err := h.alice.FSSetRequireFS(bob, true); err != nil {
			t.Fatalf("fs require: %v", err)
		}
		if err := h.alice.FSSetPeerMode(bob, "on"); err != nil {
			t.Fatalf("fs on: %v", err)
		}
		// Relay suppresses handshake delivery: Bob never polls, so no
		// accept ever arrives. Every send must fail closed.
		for _, body := range []string{"one", "two"} {
			if _, err := h.alice.Send(bob, body); !errors.Is(err, errFSRequired) {
				t.Fatalf("send %q during suppression: want errFSRequired, got %v", body, err)
			}
		}
	})
	// Relay recovers: queued handshake traffic is delivered.
	if msgs := h.bobInbox(t); len(msgs) != 0 {
		t.Fatalf("bob inbox: got %d chat messages, want 0", len(msgs))
	}
	if msgs := h.aliceInbox(t); len(msgs) != 0 {
		t.Fatalf("alice inbox: got %d chat messages, want 0", len(msgs))
	}
	h.asAlice(func() {
		if _, err := h.alice.Send(bob, "three"); err != nil {
			t.Fatalf("send after recovery: %v", err)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "three" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// TestFSPinRecordedOnHandshake: completing a handshake pins the peer's
// FS capability on both sides, first-observed-wins.
func TestFSPinRecordedOnHandshake(t *testing.T) {
	h := newFSHarness(t)
	h.doHandshake(t)
	var first int64
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		if first, ok = ff.FSPins[h.bobCfg.Address]; !ok || first <= 0 {
			t.Fatalf("alice has no pin for bob: %v", ff.FSPins)
		}
	})
	h.asBob(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ff.FSPins[h.aliceCfg.Address]; !ok {
			t.Fatalf("bob has no pin for alice: %v", ff.FSPins)
		}
	})
	// Re-handshaking must not move the pin.
	h.doHandshake(t)
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if ff.FSPins[h.bobCfg.Address] != first {
			t.Fatalf("pin moved: %d -> %d", first, ff.FSPins[h.bobCfg.Address])
		}
	})
}

// suppressDirectoryFor simulates a relay suppressing FS directory
// availability for peer: the positive capability cache is expired and
// a fresh negative entry is planted, as if reverse lookups stopped
// advertising the `fs` token.
func suppressDirectoryFor(t *testing.T, peer string) {
	t.Helper()
	now := time.Now().Unix()
	if err := updateFS(func(ff *fsFile) error {
		ff.CapCache[peer] = fsCapEntry{Capable: true, At: now - fsCapCacheTTL - 1}
		ff.NegCapCache[peer] = now
		return nil
	}); err != nil {
		t.Fatalf("suppress directory: %v", err)
	}
}

// breakSession erases our session with peer while keeping the
// capability pin — the shape of a peer that previously negotiated FS
// but is suddenly only reachable via legacy.
func breakSession(t *testing.T, peer string) {
	t.Helper()
	if err := updateFS(func(ff *fsFile) error {
		delete(ff.Sessions, peer)
		return nil
	}); err != nil {
		t.Fatalf("break session: %v", err)
	}
}

// clearModeOverride drops an explicit `fs on`/`fs off` override,
// returning the peer to opportunistic ("auto") mode — the common case
// for downgrade scenarios, where FS was discovered via the directory
// rather than asserted by the user.
func clearModeOverride(t *testing.T, peer string) {
	t.Helper()
	if err := updateFS(func(ff *fsFile) error {
		delete(ff.PeerModes, peer)
		return nil
	}); err != nil {
		t.Fatalf("clear mode: %v", err)
	}
}

// TestFSDowngradeWarning: a pinned peer whose capability evidence
// disappears (relay suppressing directory availability) triggers a
// downgrade warning on the next legacy send — while the default
// fail-open behavior still delivers the message, and handshake
// pressure continues (the pin keeps inits flowing).
func TestFSDowngradeWarning(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.doHandshake(t)
	h.asAlice(func() {
		clearModeOverride(t, bob)
		breakSession(t, bob)
		suppressDirectoryFor(t, bob)
		// Direct assessment first: the warning must be queued with the
		// expected shape before the send path consumes it.
		h.alice.fsAssessDowngrade(bob)
		w := h.alice.FSConsumeWarning(bob)
		if !strings.Contains(w, "DOWNGRADE WARNING") {
			t.Fatalf("want downgrade warning, got %q", w)
		}
		// Default is fail-open: the message still goes out (legacy).
		if _, err := h.alice.Send(bob, "downgrade test"); err != nil {
			t.Fatalf("send: %v", err)
		}
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ff.Downgrade[bob]; !ok {
			t.Fatal("want persistent downgrade marker in fs.json")
		}
		if ff.LastInitAt[bob] <= 0 {
			t.Fatal("want a fresh fs-init attempt despite the suppression (pin drives inits)")
		}
	})
	// Bob receives the legacy message; his FS counters don't move.
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "downgrade test" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
	h.asBob(func() {
		infos, err := h.bob.FSStatus(h.aliceCfg.Address)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || infos[0].MsgsRecvd != 0 {
			t.Fatalf("bob status: %+v (legacy message must not count as FS)", infos)
		}
	})
	// The marker is visible in `fs status` (on the pending session
	// the pin's re-init created).
	h.asAlice(func() {
		infos, err := h.alice.FSStatus(bob)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || infos[0].Established || !infos[0].Pinned || !infos[0].DowngradeSuspected {
			t.Fatalf("status: %+v (want pending + pinned + downgrade-suspected)", infos)
		}
		if infos[0].DowngradeSince <= 0 {
			t.Fatal("want DowngradeSince set")
		}
	})
}

// TestFSDowngradeClearsOnRecovery: once handshake traffic flows again
// and the session re-establishes, the downgrade marker is cleared and
// sends stop warning.
func TestFSDowngradeClearsOnRecovery(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.doHandshake(t)
	h.asAlice(func() {
		clearModeOverride(t, bob)
		breakSession(t, bob)
		suppressDirectoryFor(t, bob)
		if _, err := h.alice.Send(bob, "legacy during suppression"); err != nil {
			t.Fatalf("send: %v", err)
		}
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ff.Downgrade[bob]; !ok {
			t.Fatal("want downgrade marker before recovery")
		}
		// Drain the queued warning so the recovery send is a clean
		// signal (send() prints + consumes it on success).
		h.alice.FSConsumeWarning(bob)
	})
	// Relay recovers: Bob gets the legacy chat plus the queued init,
	// adopts it (rekey path), and answers.
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "legacy during suppression" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
	if msgs := h.aliceInbox(t); len(msgs) != 0 {
		t.Fatalf("alice inbox: got %d chat messages, want 0", len(msgs))
	}
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if len(ff.Downgrade) != 0 {
			t.Fatalf("downgrade marker not cleared on re-establishment: %v", ff.Downgrade)
		}
		if _, err := h.alice.Send(bob, "back on fs"); err != nil {
			t.Fatalf("send: %v", err)
		}
		if w := h.alice.FSConsumeWarning(bob); w != "" {
			t.Fatalf("unexpected warning after recovery: %q", w)
		}
		infos, err := h.alice.FSStatus(bob)
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || !infos[0].Established || infos[0].DowngradeSuspected {
			t.Fatalf("status after recovery: %+v", infos)
		}
	})
	msgs = h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "back on fs" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

// TestFSRequireSetClear: the policy round-trips through fs.json.
func TestFSRequireSetClear(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		if err := h.alice.FSSetRequireFS(bob, true); err != nil {
			t.Fatalf("require on: %v", err)
		}
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if !ff.RequireFS[bob] {
			t.Fatal("policy not persisted")
		}
		if err := h.alice.FSSetRequireFS(bob, false); err != nil {
			t.Fatalf("require off: %v", err)
		}
		ff, err = loadFS()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ff.RequireFS[bob]; ok {
			t.Fatal("policy not cleared")
		}
		if required, err := h.alice.FSRequireForPeer(bob); err != nil || required {
			t.Fatalf("FSRequireForPeer: %v, %v", required, err)
		}
	})
}

// TestFSRequireWinsOverOff: require_fs + `fs off` is contradictory
// configuration; fail-closed wins over the legacy-only mode rather
// than silently dropping the policy.
func TestFSRequireWinsOverOff(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		if err := h.alice.FSSetRequireFS(bob, true); err != nil {
			t.Fatalf("fs require: %v", err)
		}
		if err := h.alice.FSSetPeerMode(bob, "off"); err != nil {
			t.Fatalf("fs off: %v", err)
		}
		if _, err := h.alice.Send(bob, "must not go"); !errors.Is(err, errFSRequired) {
			t.Fatalf("want errFSRequired, got %v", err)
		}
	})
}

// TestFSMigrationKeepsOldFSJSON: fs.json written by a pre-#110 client
// (no require_fs / pins / downgrade fields) loads cleanly and keeps
// fail-open behavior — the new fields are purely additive.
func TestFSMigrationKeepsOldFSJSON(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		// Write a legacy-shaped fs.json by hand: sessions only.
		p, err := fsFilePath()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{\"sessions\":{},\"peer_modes\":{}}\n"), 0o600); err != nil {
			t.Fatalf("write legacy fs.json: %v", err)
		}
		ff, err := loadFS()
		if err != nil {
			t.Fatalf("load legacy fs.json: %v", err)
		}
		if ff.RequireFS == nil || ff.FSPins == nil || ff.Downgrade == nil || ff.DowngradeWarnedAt == nil {
			t.Fatal("new maps not normalized on load")
		}
		// Fail-open default preserved on the migrated file.
		if _, err := h.alice.Send(bob, "still fail-open"); err != nil {
			t.Fatalf("send: %v", err)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "still fail-open" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}
