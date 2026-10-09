package client

import (
	"errors"
	"fmt"
	"testing"
)

func TestContactRequiredRebindRuntime(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("shared=%v/existingReplacementPolicy=%v", shared, existing), func(t *testing.T) {
				h := newFSHarness(t)
				h.asAlice(func() {
					former, err := NewIdentity(h.srv.URL)
					if err != nil {
						t.Fatal(err)
					}
					if err = h.aliceCfg.AddContact("peer", former.Address); err != nil {
						t.Fatal(err)
					}
					if shared {
						if err = h.aliceCfg.AddContact("remaining", former.Address); err != nil {
							t.Fatal(err)
						}
					}
					if err = h.alice.FSRequire(former.Address, true); err != nil {
						t.Fatal(err)
					}
					if existing {
						if err = h.alice.FSRequire(h.bobCfg.Address, true); err != nil {
							t.Fatal(err)
						}
					}
					if err = h.aliceCfg.AddContact("peer", h.bobCfg.Address); err != nil {
						t.Fatal(err)
					}
					cfg, err := LoadConfig()
					if err != nil {
						t.Fatal(err)
					}
					restarted := New(cfg)
					ff, err := loadFS()
					if err != nil {
						t.Fatal(err)
					}
					if !ff.RequireFS[h.bobCfg.Address] {
						t.Fatal("replacement lost required-FS policy")
					}
					if ff.RequireFS[former.Address] != shared {
						t.Fatalf("former policy=%v; remaining alias=%v", ff.RequireFS[former.Address], shared)
					}
					if ff.session(h.bobCfg.Address) != nil {
						t.Fatal("replacement inherited a session")
					}
					if cfg.Contacts["peer"] != h.bobCfg.Address {
						t.Fatal("replacement not persisted")
					}
					if _, err = restarted.Send(cfg.Contacts["peer"], "must never arrive as legacy"); !errors.Is(err, errFSRequired) {
						t.Fatalf("first send did not fail closed: %v", err)
					}
				})
				if msgs := h.bobInbox(t); len(msgs) != 0 {
					t.Fatalf("failed-closed rebind leaked messages: %v", msgs)
				}
			})
		}
	}
}

func TestContactReplacementReceiptRuntime(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared=%v", shared), func(t *testing.T) {
			h := newFSHarness(t)
			h.asAlice(func() {
				if err := h.aliceCfg.AddContact("peer", h.bobCfg.Address); err != nil {
					t.Fatal(err)
				}
				if shared {
					if err := h.aliceCfg.AddContact("remaining", h.bobCfg.Address); err != nil {
						t.Fatal(err)
					}
				}
				if err := h.aliceCfg.SetReceiptsOptIn(h.bobCfg.Address, true); err != nil {
					t.Fatal(err)
				}
				replacement, err := NewIdentity(h.srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				if err = h.aliceCfg.AddContact("peer", replacement.Address); err != nil {
					t.Fatal(err)
				}
				cfg, err := LoadConfig()
				if err != nil {
					t.Fatal(err)
				}
				if cfg.ReceiptsEnabledFor(h.bobCfg.Address) != shared {
					t.Fatal("former identity receipt consent mismatches surviving aliases")
				}
				if cfg.ReceiptsEnabledFor(replacement.Address) {
					t.Fatal("replacement inherited receipt consent")
				}
				h.alice = New(cfg)
			})
			var sentID int64
			h.asBob(func() {
				var err error
				sentID, err = h.bob.Send(h.aliceCfg.Address, "authenticated former identity")
				if err != nil {
					t.Fatal(err)
				}
			})
			msgs := h.aliceInbox(t)
			if len(msgs) != 1 || msgs[0].Body != "authenticated former identity" || msgs[0].Request {
				t.Fatalf("expected accepted authenticated DM: %+v", msgs)
			}
			h.asAlice(func() {
				rs, err := loadReceipts()
				if err != nil {
					t.Fatal(err)
				}
				if (len(rs.Sent) > 0) != shared {
					t.Fatalf("sent receipt state=%v; shared=%v", rs.Sent, shared)
				}
			})
			if msgs := h.bobInbox(t); len(msgs) != 0 {
				t.Fatalf("receipt surfaced as chat: %v", msgs)
			}
			h.asBob(func() {
				rs, err := loadReceipts()
				if err != nil {
					t.Fatal(err)
				}
				rec := rs.Received[receivedReceiptKey(h.aliceCfg.Address, sentID)]
				got := rec != nil && rec.DeliveryAt > 0
				if got != shared {
					t.Fatalf("actual delivery receipt=%v; surviving alias=%v", got, shared)
				}
			})
		})
	}
}
