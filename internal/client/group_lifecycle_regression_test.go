package client

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/black-candle-technologies/courier/internal/relay"
	"github.com/black-candle-technologies/courier/internal/store"
)

func TestGroupLifecycleRemovalDelivery(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	routes := relay.New(st).Routes()
	var fail atomic.Bool
	var activeGroup atomic.Value
	var dashboard bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/dashboard/push" {
			b, _ := io.ReadAll(r.Body)
			dashboard.Write(b)
			w.Write([]byte(`{}`))
			return
		}
		if fail.Load() && r.Method == "POST" && r.URL.Path == "/v1/send" {
			gs, err := loadGroups()
			if err != nil {
				t.Error(err)
			} else {
				g := gs[activeGroup.Load().(string)]
				if g == nil || g.MyEpoch != 2 || !g.KeyPending {
					t.Error("key distribution preceded durable rotation")
				}
			}
			http.Error(w, "injected delivery failure", http.StatusServiceUnavailable)
			return
		}
		routes.ServeHTTP(w, r)
	}))
	defer srv.Close()
	homes := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	clients := make([]*Client, 3)
	use := func(i int) { t.Setenv("HOME", homes[i]); t.Setenv("USERPROFILE", homes[i]) }
	for i := range clients {
		use(i)
		cfg, e := NewIdentity(srv.URL)
		if e != nil {
			t.Fatal(e)
		}
		if e = cfg.Save(); e != nil {
			t.Fatal(e)
		}
		clients[i] = New(cfg)
		if e = clients[i].PublishKey(); e != nil {
			t.Fatal(e)
		}
	}
	use(0)
	g, err := clients[0].GroupCreate("three", []string{clients[1].cfg.Address, clients[2].cfg.Address})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 3; i++ {
		use(i)
		if msgs, _, _, _, e := clients[i].Inbox(0, 50); e != nil || len(msgs) != 0 {
			t.Fatalf("invite: %v %v", msgs, e)
		}
	}
	use(0)
	if _, _, _, _, err = clients[0].Inbox(0, 50); err != nil {
		t.Fatal(err)
	}
	before, _ := loadGroups()
	old := before[g.ID].MyKey
	activeGroup.Store(g.ID)
	fail.Store(true)
	if err = clients[0].GroupRemove(g.ID, clients[2].cfg.Address); err == nil {
		t.Fatal("expected delivery failure")
	}
	saved, e := loadGroups()
	if e != nil {
		t.Fatal(e)
	}
	rotated := saved[g.ID]
	if rotated.MyKey == old || rotated.MyEpoch != 2 || inRoster(rotated.Roster, clients[2].cfg.Address) {
		t.Fatal("removal/key rotation not durable")
	}
	fail.Store(false)
	if err = clients[0].GroupRemove(g.ID, clients[2].cfg.Address); err != nil {
		t.Fatalf("retry: %v", err)
	}
	saved, _ = loadGroups()
	if saved[g.ID].MyKey != rotated.MyKey || saved[g.ID].MyEpoch != rotated.MyEpoch {
		t.Fatal("retry changed committed key")
	}
	use(1)
	if _, _, _, _, err = clients[1].Inbox(0, 50); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if _, err = clients[1].GroupInbox(g.ID); err == nil {
		t.Fatal("expected member rekey delivery failure")
	}
	memberSaved, err := loadGroups()
	if err != nil {
		t.Fatal(err)
	}
	memberKey, memberEpoch := memberSaved[g.ID].MyKey, memberSaved[g.ID].MyEpoch
	if memberEpoch != 2 || inRoster(memberSaved[g.ID].Roster, clients[2].cfg.Address) || !memberSaved[g.ID].KeyPending {
		t.Fatal("member rekey not committed before failed distribution")
	}
	fail.Store(false)
	if _, err = clients[1].GroupInbox(g.ID); err != nil {
		t.Fatal(err)
	}
	memberSaved, err = loadGroups()
	if err != nil {
		t.Fatal(err)
	}
	if memberSaved[g.ID].MyKey != memberKey || memberSaved[g.ID].MyEpoch != memberEpoch || memberSaved[g.ID].KeyPending {
		t.Fatal("member retry did not distribute same committed key")
	}
	use(0)
	if _, _, _, _, err = clients[0].Inbox(0, 50); err != nil {
		t.Fatal(err)
	}
	if _, err = clients[0].GroupSend(g.ID, "safe message"); err != nil {
		t.Fatal(err)
	}
	use(1)
	msgs, err := clients[1].GroupInbox(g.ID)
	if err != nil || len(msgs) != 1 || msgs[0].Body != "safe message" {
		t.Fatalf("rekey delivery: %v %v", msgs, err)
	}
	for i := range clients {
		use(i)
		clients[i].cfg.DashboardURL = srv.URL
		clients[i].cfg.DashboardToken = "fixture"
		if err = clients[i].cfg.Save(); err != nil {
			t.Fatal(err)
		}
		if _, err = clients[i].DashboardPush(); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"sent.jsonl", "thread_cache.jsonl"} {
			raw, e := os.ReadFile(filepath.Join(homes[i], ".courier", name))
			if e != nil && !os.IsNotExist(e) {
				t.Fatal(e)
			}
			if bytes.Contains(raw, []byte(`"cg"`)) || bytes.Contains(raw, []byte(old)) || bytes.Contains(raw, []byte(rotated.MyKey)) {
				t.Fatalf("protocol secret in %s", name)
			}
		}
	}
	if bytes.Contains(dashboard.Bytes(), []byte(`\"cg\"`)) || bytes.Contains(dashboard.Bytes(), []byte(old)) || bytes.Contains(dashboard.Bytes(), []byte(rotated.MyKey)) {
		t.Fatal("protocol secret in dashboard")
	}
}

func TestGroupInboxPreservesConcurrentState(t *testing.T) {
	for _, removed := range []bool{false, true} {
		t.Run(map[bool]string{false: "peer-key-and-cursor", true: "removed"}[removed], func(t *testing.T) {
			cfg := testConfig(t)
			home, _ := os.UserHomeDir()
			t.Setenv("USERPROFILE", home)
			key, err := newSenderKey(1)
			if err != nil {
				t.Fatal(err)
			}
			const groupID = "group:concurrent-fixture"
			if err = LegacyContext().updateGroups(func(gs map[string]*groupState) error {
				gs[groupID] = &groupState{ID: groupID, Admin: cfg.Address, Roster: []string{cfg.Address, "peer"}, MyKey: key.Key, MyEpoch: 1, ControlEpoch: 1, Keys: map[string]groupSenderKey{cfg.Address: key}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := LegacyContext().updateGroups(func(gs map[string]*groupState) error {
					g := gs[groupID]
					g.Keys["peer"] = groupSenderKey{Key: "new-peer-key", Epoch: 7}
					g.InboxCursor = 99
					g.Removed = removed
					return nil
				}); err != nil {
					t.Error(err)
				}
				w.Write([]byte(`{"messages":[],"controls":[]}`))
			}))
			defer srv.Close()
			cfg.RelayURL = srv.URL
			_, err = New(cfg).GroupInbox(groupID)
			if (err != nil) != removed {
				t.Fatalf("error=%v removed=%v", err, removed)
			}
			gs, err := loadGroups()
			if err != nil {
				t.Fatal(err)
			}
			g := gs[groupID]
			if g.Keys["peer"].Epoch != 7 || g.InboxCursor != 99 || g.Removed != removed {
				t.Fatalf("concurrent state overwritten: %+v", g)
			}
		})
	}
}
