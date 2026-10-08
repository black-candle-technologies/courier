package client

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFSRequiredPrivatePeerBootstraps(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		if err := h.alice.FSRequire(bob, true); err != nil {
			t.Fatal(err)
		}
		if err := updateFS(func(ff *fsFile) error { ff.NegCapCache[bob] = time.Now().Unix(); return nil }); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if _, err := h.alice.Send(bob, "must not leak"); !errors.Is(err, errFSRequired) {
				t.Fatalf("send: %v", err)
			}
		}
	})
	if msgs := h.bobInbox(t); len(msgs) != 0 {
		t.Fatal("failed-closed send leaked chat", msgs)
	}
	if msgs := h.aliceInbox(t); len(msgs) != 0 {
		t.Fatal(msgs)
	}
	h.asAlice(func() {
		active, err := h.alice.FSActive(bob)
		if err != nil || !active {
			t.Fatalf("no session: %v %v", active, err)
		}
		if _, err := h.alice.Send(bob, "protected"); err != nil {
			t.Fatal(err)
		}
	})
	msgs := h.bobInbox(t)
	if len(msgs) != 1 || msgs[0].Body != "protected" {
		t.Fatal(msgs)
	}
}
func TestFSRequiredDowngradeRemainsVisible(t *testing.T) {
	h := newFSHarness(t)
	bob := h.bobCfg.Address
	h.asAlice(func() {
		if err := h.alice.FSRequire(bob, true); err != nil {
			t.Fatal(err)
		}
		if err := updateFS(func(ff *fsFile) error {
			ff.FSPins[bob] = time.Now().Unix() - 100
			ff.Downgrade[bob] = time.Now().Unix() - 1
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		suspected, err := h.alice.FSDowngradeSuspected(bob)
		if err != nil || !suspected {
			t.Fatal(suspected, err)
		}
		_, err = h.alice.Send(bob, "secret")
		if !errors.Is(err, errFSRequired) {
			t.Fatal(err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "downgrade") {
			t.Fatalf("warning hidden: %v", err)
		}
	})
}
