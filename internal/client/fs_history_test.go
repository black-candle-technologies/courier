package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	// Give the first observation an older timestamp so an erroneous overwrite
	// cannot hide behind one-second clock resolution.
	h.asAlice(func() {
		first -= 3600
		if err := updateFS(func(ff *fsFile) error { ff.FSPins[h.bobCfg.Address] = first; return nil }); err != nil {
			t.Fatal(err)
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

func breakSession(t *testing.T, peer string) {
	t.Helper()
	if err := updateFS(func(ff *fsFile) error {
		delete(ff.Sessions, peer)
		return nil
	}); err != nil {
		t.Fatalf("break session: %v", err)
	}
}

func TestFSDowngradeWarning(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.doHandshake(t)
	h.asAlice(func() {
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
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess := ff.session(h.aliceCfg.Address)
		if sess == nil || sess.MsgsRecvd != 0 {
			t.Fatalf("bob session: %+v (legacy message must not count as FS)", sess)
		}
	})
	// The marker is visible in `fs status` (on the pending session
	// the pin's re-init created).
	h.asAlice(func() {
		ff, err := loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess := ff.session(bob)
		if sess == nil || sess.Established || ff.FSPins[bob] <= 0 || ff.Downgrade[bob] <= 0 {
			t.Fatalf("session: %+v (want pending + pinned + downgrade-suspected)", sess)
		}
		if ff.Downgrade[bob] <= 0 {
			t.Fatal("want DowngradeSince set")
		}
	})
}

func TestFSDowngradeClearsOnRecovery(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.doHandshake(t)
	h.asAlice(func() {
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
		ff, err = loadFS()
		if err != nil {
			t.Fatal(err)
		}
		sess := ff.session(bob)
		if sess == nil || !sess.Established || ff.Downgrade[bob] > 0 {
			t.Fatalf("session after recovery: %+v", sess)
		}
	})
	msgs = h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "back on fs" {
		t.Fatalf("bob inbox: %+v", msgs)
	}
}

func TestFSMigrationKeepsOldFSJSON(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		// Write a legacy-shaped fs.json by hand: sessions only.
		p, err := h.aliceCfg.Context().fsFilePath()
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
