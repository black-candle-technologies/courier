package client

import (
	"testing"
	"time"
)

func TestForgottenContactCanImmediatelyBootstrap(t *testing.T) {
	for _, mutation := range []string{"remove", "replace"} {
		for _, shared := range []bool{false, true} {
			t.Run(mutation+"/"+map[bool]string{false: "last-alias", true: "shared-alias"}[shared], func(t *testing.T) {
				h := newFSHarness(t)
				h.asAlice(func() {
					c := h.aliceCfg
					a := h.bobCfg.Address
					if err := c.AddContact("peer", a); err != nil {
						t.Fatal(err)
					}
					if shared {
						if err := c.AddContact("remaining", a); err != nil {
							t.Fatal(err)
						}
					}
					now := time.Now().Unix()
					if err := updateFS(func(f *fsFile) error {
						f.LastInitAt[a] = now
						f.CapCache[a] = fsCapEntry{Capable: true, At: now}
						f.Sessions[a] = &fsSession{SID: "old-pending"}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
					mutate := func() error {
						if mutation == "remove" {
							return c.RemoveContact("peer")
						}
						other, err := NewIdentity("")
						if err != nil {
							return err
						}
						return c.AddContact("peer", other.Address)
					}
					if err := mutate(); err != nil {
						t.Fatal(err)
					}
					f, err := loadFS()
					if err != nil {
						t.Fatal(err)
					}
					if shared {
						if f.LastInitAt[a] != now || f.Sessions[a] == nil {
							t.Fatal("shared alias lost pending state")
						}
						return
					}
					if f.LastInitAt[a] != 0 {
						t.Fatal("forgotten identity retained cooldown")
					}
					if err := c.AddContact("peer", a); err != nil {
						t.Fatal(err)
					}
					if _, err := h.alice.fsPrepareSend(a); err != nil {
						t.Fatal(err)
					}
					f, err = loadFS()
					if err != nil {
						t.Fatal(err)
					}
					if f.Sessions[a] == nil || f.Sessions[a].SID == "old-pending" {
						t.Fatal("immediate bootstrap did not create a fresh pending session")
					}
				})
			})
		}
	}
}
