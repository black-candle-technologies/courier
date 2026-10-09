package client

import (
	"errors"
	"os"
	"testing"
)

func TestContactMutationUsesFreshState(t *testing.T) {
	for _, op := range []string{"add", "remove", "repoint"} {
		t.Run(op, func(t *testing.T) {
			c := testConfig(t)
			a, _ := NewIdentity("")
			b, _ := NewIdentity("")
			if e := c.AddContact("peer", a.Address); e != nil {
				t.Fatal(e)
			}
			stale, e := LoadConfig()
			if e != nil {
				t.Fatal(e)
			}
			if e = c.AddContact("survivor", a.Address); e != nil {
				t.Fatal(e)
			}
			if e = c.Update(func(f *Config) error {
				f.VerifiedKeyEpochs = map[string]int64{a.Address: 999}
				f.EncKeys[0].Epoch++
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			epoch := c.EncKeys[0].Epoch
			if e = updateFS(func(f *fsFile) error {
				f.RequireFS[a.Address] = true
				f.Sessions[a.Address] = &fsSession{RootKey: "retained-ratchet"}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			switch op {
			case "add":
				e = stale.AddContact("new", b.Address)
			case "remove":
				e = stale.RemoveContact("peer")
			case "repoint":
				e = stale.AddContact("peer", b.Address)
			}
			if e != nil {
				t.Fatal(e)
			}
			f, e := LoadConfig()
			if e != nil {
				t.Fatal(e)
			}
			if f.Contacts["survivor"] != a.Address || f.VerifiedKeyEpochs[a.Address] != 999 || f.EncKeys[0].Epoch != epoch {
				t.Fatal("stale mutation clobbered concurrent security state")
			}
			fs, e := loadFS()
			if e != nil {
				t.Fatal(e)
			}
			if !fs.RequireFS[a.Address] || fs.session(a.Address) == nil {
				t.Fatal("surviving alias lost FS state")
			}
		})
	}
}
func TestContactRebindRevokesIdentityState(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "last", true: "shared"}[shared], func(t *testing.T) {
			c := testConfig(t)
			a, _ := NewIdentity("")
			b, _ := NewIdentity("")
			if e := c.AddContact("peer", a.Address); e != nil {
				t.Fatal(e)
			}
			if shared {
				if e := c.AddContact("alias", a.Address); e != nil {
					t.Fatal(e)
				}
			}
			if e := c.Update(func(f *Config) error {
				f.ContactVerifications = map[string]ContactVerification{"peer": {Address: a.Address, SafetyNumber: "old-safety", VerifiedAt: 1}}
				f.ReceiptContacts = map[string]bool{a.Address: true}
				f.HandleRefreshAt = 123
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			if e := c.AddContact("peer", a.Address); e != nil {
				t.Fatal(e)
			}
			if c.ContactVerifications["peer"].SafetyNumber != "old-safety" || !c.ReceiptsEnabledFor(a.Address) {
				t.Fatal("same-address mutation lost trust/consent")
			}
			if e := c.AddContact("peer", b.Address); e != nil {
				t.Fatal(e)
			}
			c, e := LoadConfig()
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := c.ContactVerifications["peer"]; ok {
				t.Fatal("rebind retained old verification")
			}
			if c.ReceiptsEnabledFor(a.Address) != shared || c.ReceiptsEnabledFor(b.Address) {
				t.Fatal("incorrect consent after rebind")
			}
			if c.HandleRefreshAt != 0 {
				t.Fatal("refresh not forced")
			}
			if e := c.AddContact("peer", a.Address); e != nil {
				t.Fatal(e)
			}
			if _, ok := c.ContactVerifications["peer"]; ok {
				t.Fatal("verification resurrected")
			}
		})
	}
}
func TestContactRebindPreservesRequiredPolicy(t *testing.T) {
	c := testConfig(t)
	a, _ := NewIdentity("")
	b, _ := NewIdentity("")
	if e := c.AddContact("peer", a.Address); e != nil {
		t.Fatal(e)
	}
	if e := New(c).FSRequire("peer", true); e != nil {
		t.Fatal(e)
	}
	if e := c.AddContact("peer", b.Address); e != nil {
		t.Fatal(e)
	}
	c, e := LoadConfig()
	if e != nil {
		t.Fatal(e)
	}
	required, e := New(c).FSRequired("peer")
	if e != nil || !required {
		t.Fatal("required contact became fail-open", e)
	}
	fs, e := loadFS()
	if e != nil {
		t.Fatal(e)
	}
	if fs.session(b.Address) != nil || fs.FSPins[b.Address] != 0 {
		t.Fatal("crypto state transferred")
	}
}

func TestContactRebindConfigFailureKeepsPolicySafe(t *testing.T) {
	c := testConfig(t)
	a, _ := NewIdentity("")
	b, _ := NewIdentity("")
	if e := c.AddContact("peer", a.Address); e != nil {
		t.Fatal(e)
	}
	if e := New(c).FSRequire("peer", true); e != nil {
		t.Fatal(e)
	}
	failure := errors.New("injected config persistence failure")
	e := c.updateWithSave(func(f *Config) error { _, _, e := replaceContactLocked(f, "peer", b.Address); return e }, true, func(*Config) error { return failure })
	if !errors.Is(e, failure) {
		t.Fatal(e)
	}
	fresh, e := LoadConfig()
	if e != nil {
		t.Fatal(e)
	}
	if fresh.Contacts["peer"] != a.Address || c.Contacts["peer"] != a.Address {
		t.Fatal("failed save exposed replacement")
	}
	fs, e := loadFS()
	if e != nil {
		t.Fatal(e)
	}
	if !fs.RequireFS[a.Address] || !fs.RequireFS[b.Address] {
		t.Fatal("policy not committed before config persistence")
	}
	if e = fresh.AddContact("peer", b.Address); e != nil {
		t.Fatal(e)
	}
	fresh, e = LoadConfig()
	if e != nil {
		t.Fatal(e)
	}
	required, e := New(fresh).FSRequired("peer")
	if e != nil || !required {
		t.Fatal("retry became fail-open", e)
	}
}

func TestContactUnsavedInitializationDoesNotResurrectDeletedConfig(t *testing.T) {
	setTestHome(t, t.TempDir())
	c, e := NewIdentity("")
	if e != nil {
		t.Fatal(e)
	}
	a, _ := NewIdentity("")
	if e = c.AddContact("peer", a.Address); e != nil {
		t.Fatal("explicit initial save failed", e)
	}
	p, e := configPath()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e = c.AddContact("other", a.Address); e == nil {
		t.Fatal("saved snapshot recreated deleted identity")
	}
	if _, e = os.Stat(p); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("deleted config recreated", e)
	}
}

func TestContactRequiredRebindAlwaysChecksDurability(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-policy-retry", true: "existing-policy"}[existing], func(t *testing.T) {
			c := testConfig(t)
			a, _ := NewIdentity("")
			b, _ := NewIdentity("")
			if e := c.AddContact("peer", a.Address); e != nil {
				t.Fatal(e)
			}
			if e := New(c).FSRequire(a.Address, true); e != nil {
				t.Fatal(e)
			}
			if existing {
				if e := New(c).FSRequire(b.Address, true); e != nil {
					t.Fatal(e)
				}
			}
			failure := errors.New("injected durability barrier failure")
			for range 2 {
				called := false
				e := c.updateWithSave(func(f *Config) error {
					_, _, e := replaceContactWithSyncLocked(f, "peer", b.Address, func() error { called = true; return failure })
					return e
				}, true, (*Config).saveAtomic)
				if !called || !errors.Is(e, failure) {
					t.Fatal("required rebind skipped durability barrier", e)
				}
				fresh, e := LoadConfig()
				if e != nil {
					t.Fatal(e)
				}
				if fresh.Contacts["peer"] != a.Address {
					t.Fatal("failed durability exposed mapping")
				}
			}
			if e := c.AddContact("peer", b.Address); e != nil {
				t.Fatal(e)
			}
			c, e := LoadConfig()
			if e != nil {
				t.Fatal(e)
			}
			r, e := New(c).FSRequired("peer")
			if e != nil || !r {
				t.Fatal("retry lost requirement", e)
			}
		})
	}
}
