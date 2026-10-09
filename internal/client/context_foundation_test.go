package client

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

func TestNamedFoundationStateAndRotationIsolation(t *testing.T) {
	a, sa := reviewConfig(t, true)
	b, sb := reviewConfig(t, true) // Process default now points at B, not A.
	old, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	ca, cb := New(a), New(b)
	for _, cfg := range []*Config{a, b} {
		if err := cfg.AddContact("peer", old.Address); err != nil {
			t.Fatal(err)
		}
	}
	if err := ca.FSRequire(old.Address, true); err != nil {
		t.Fatal(err)
	}
	rotating, err := sa.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 5; i++ {
			pub, priv, err := crypto.GenerateX25519Keypair()
			if err != nil {
				done <- err
				return
			}
			enc := base64.RawURLEncoding.EncodeToString
			if err := rotating.Update(func(f *Config) error {
				f.EncKeys = append([]EncKey{{Pub: enc(pub[:]), Priv: enc(priv[:]), Epoch: f.EncKeys[0].Epoch + 1}}, f.EncKeys...)
				return nil
			}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 5; i++ {
		if err := ca.queuePeerDiscovery(next.Address); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := a.PendingPeerDiscovery[next.Address]; !ok {
		t.Fatal("caller pending metadata was not refreshed")
	}
	if err := a.AddContact("peer", next.Address); err != nil {
		t.Fatal(err)
	}
	if len(a.EncKeys) != 6 {
		t.Fatal("contact update overwrote concurrent rotations")
	}
	if a.PublishedPeerTrust[old.Address] != "pending-clear" {
		t.Fatal("caller badge clear was not refreshed")
	}
	afs, err := sa.loadFS()
	if err != nil {
		t.Fatal(err)
	}
	bfs, err := sb.loadFS()
	if err != nil {
		t.Fatal(err)
	}
	if !afs.RequireFS[next.Address] || bfs.RequireFS[next.Address] || bfs.RequireFS[old.Address] {
		t.Fatal("required policy crossed contexts or failed to carry")
	}
	freshB, err := sb.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if freshB.Contacts["peer"] != old.Address || len(freshB.EncKeys) != 1 || len(freshB.PendingPeerDiscovery) != 0 || len(freshB.PublishedPeerTrust) != 0 {
		t.Fatal("A mutation reached B")
	}
	if cb.cfg.Context() != sb {
		t.Fatal("B context changed")
	}
}

func TestNamedMetadataAcknowledgementUsesCapturedContext(t *testing.T) {
	a, sa := reviewConfig(t, true)
	b, sb := reviewConfig(t, true)
	var pushed map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Verified map[string]string `json:"verified"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		pushed = body.Verified
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := a.Update(func(f *Config) error {
		f.DashboardURL = srv.URL
		f.DashboardToken = "fixture-token"
		f.PublishedPeerTrust = map[string]string{a.Address: "pending-clear"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Update(func(f *Config) error {
		f.PublishedPeerTrust = map[string]string{b.Address: "pending-clear"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	New(a).refreshPeerHandles(srv.Client())
	if v, ok := pushed[a.Address]; !ok || v != "" {
		t.Fatal("A pending clear was not published")
	}
	if _, ok := pushed[b.Address]; ok {
		t.Fatal("B metadata leaked into A dashboard")
	}
	freshA, err := sa.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	freshB, err := sb.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(freshA.PublishedPeerTrust) != 0 || freshB.PublishedPeerTrust[b.Address] != "pending-clear" {
		t.Fatal("ACK reached wrong context")
	}
}

func TestNamedLegacyBootstrapAuthorizationIsolation(t *testing.T) {
	a, sa := reviewConfig(t, true)
	_, sb := reviewConfig(t, true)
	peer, err := NewIdentity("https://fixture.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.updateFS(func(f *fsFile) error {
		f.LegacyEnabledPeers = map[string]bool{peer.Address: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !New(a).fsShouldInit(peer.Address) {
		t.Fatal("captured context lost authorization")
	}
	other, err := sb.loadFS()
	if err != nil {
		t.Fatal(err)
	}
	if other.LegacyEnabledPeers[peer.Address] {
		t.Fatal("bootstrap authorization crossed contexts")
	}
	if err := sa.updateFS(func(f *fsFile) error { forgetFSAddress(f, peer.Address); return nil }); err != nil {
		t.Fatal(err)
	}
	if New(a).fsShouldInit(peer.Address) {
		t.Fatal("forget retained bootstrap authorization")
	}
}
