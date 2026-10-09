package client

import (
	"testing"
	"time"
)

func TestDiscoveryRepeatedPeerDoesNotWrite(t *testing.T) {
	cfg := testConfig(t)
	peer, _ := NewIdentity("")
	cl := New(cfg)
	writes := 0
	save := func(f *Config) error { writes++; return f.saveAtomic() }
	for i := 0; i < 100; i++ {
		if err := cl.queuePeerDiscoveryWithSave(peer.Address, save); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 1 {
		t.Fatalf("repeated pending peer wrote %d times", writes)
	}
	if err := cfg.Update(func(f *Config) error {
		e := f.PendingPeerDiscovery[peer.Address]
		e.RetryAt = time.Now().Unix() + 300
		f.PendingPeerDiscovery[peer.Address] = e
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := cfg.PendingPeerDiscovery[peer.Address]
	if err := cl.queuePeerDiscoveryWithSave(peer.Address, save); err != nil {
		t.Fatal(err)
	}
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PendingPeerDiscovery[peer.Address] != before || writes != 1 {
		t.Fatal("dedup changed fairness or wrote")
	}
	if err := cfg.Update(func(f *Config) error {
		delete(f.PendingPeerDiscovery, peer.Address)
		f.HandleCache = map[string]HandleCacheEntry{peer.Address: {At: time.Now().Unix()}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := cl.queuePeerDiscoveryWithSave(peer.Address, save); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatal("fresh cache caused write")
	}
}
