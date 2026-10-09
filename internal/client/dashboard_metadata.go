package client

import (
	"context"
	"sort"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// RunDashboardMetadataRefresh renews expired discovery evidence separately
// from dashboard rendering. The worker owns a fresh Config/Client per pass;
// it never shares mutable client state with the message delivery loop.
func RunDashboardMetadataRefresh(ctx context.Context) {
	retries := make(map[string]time.Time)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if cfg, err := LoadConfig(); err == nil {
			pass, cancel := context.WithTimeout(ctx, 5*time.Second)
			New(cfg).refreshDashboardMetadata(pass, retries, time.Now())
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// PeerDiscoveryEntry contains addresses and scheduling data only, never message
// plaintext. RetryAt survives worker restarts; ObservedAt provides a stable cap.
type PeerDiscoveryEntry struct {
	ObservedAt int64 `json:"observed_at"`
	RetryAt    int64 `json:"retry_at,omitempty"`
}

const maxPendingPeerDiscovery = 256

func (c *Client) queuePeerDiscovery(address string) error {
	if _, err := crypto.ParseAddress(address); err != nil {
		return err
	}
	return c.cfg.Update(func(fresh *Config) error {
		now := time.Now().Unix()
		if entry, ok := fresh.HandleCache[address]; ok && now-entry.At < 24*3600 {
			return nil
		}
		if fresh.PendingPeerDiscovery == nil {
			fresh.PendingPeerDiscovery = map[string]PeerDiscoveryEntry{}
		}
		if _, ok := fresh.PendingPeerDiscovery[address]; !ok {
			fresh.PendingPeerDiscovery[address] = PeerDiscoveryEntry{ObservedAt: now}
		}
		for len(fresh.PendingPeerDiscovery) > maxPendingPeerDiscovery {
			oldest := ""
			for peer, e := range fresh.PendingPeerDiscovery {
				if oldest == "" || e.ObservedAt < fresh.PendingPeerDiscovery[oldest].ObservedAt || (e.ObservedAt == fresh.PendingPeerDiscovery[oldest].ObservedAt && peer < oldest) {
					oldest = peer
				}
			}
			delete(fresh.PendingPeerDiscovery, oldest)
		}
		return nil
	})
}

// Aggregate all aliases; a stale verified alias dominates, and an unverified
// alias cannot clear another alias's verification for the same address.
func cachedDashboardTrust(cfg *Config) map[string]string {
	verified := map[string]string{}
	cl := New(cfg)
	for name, address := range cfg.Contacts {
		status, _ := cl.CachedContactTrust(name)
		switch status {
		case TrustVerified:
			if verified[address] != "stale" {
				verified[address] = "verified_cached"
			}
		case TrustStale:
			verified[address] = "stale"
		default:
			if _, exists := verified[address]; !exists {
				verified[address] = ""
			}
		}
	}
	return verified
}

// At most eight peers and five seconds per pass, including pending strangers.
// Pending work goes first, ordered by retry time so failures yield to new peers.
func (c *Client) refreshDashboardMetadata(ctx context.Context, retries map[string]time.Time, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	peers := map[string]bool{}
	for address := range c.cfg.HandleCache {
		peers[address] = true
	}
	for _, address := range c.cfg.Contacts {
		peers[address] = true
	}
	for address := range c.cfg.PendingPeerDiscovery {
		peers[address] = true
	}
	ordered := make([]string, 0, len(peers))
	for address := range peers {
		ordered = append(ordered, address)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, aok := c.cfg.PendingPeerDiscovery[ordered[i]]
		b, bok := c.cfg.PendingPeerDiscovery[ordered[j]]
		if aok != bok {
			return aok
		}
		if a.RetryAt != b.RetryAt {
			return a.RetryAt < b.RetryAt
		}
		return ordered[i] < ordered[j]
	})
	for address, until := range retries {
		if !now.Before(until) {
			delete(retries, address)
		}
	}
	attempts := 0
	for _, address := range ordered {
		if ctx.Err() != nil || attempts >= 8 {
			return
		}
		if e, ok := c.cfg.HandleCache[address]; ok && now.Unix()-e.At < 24*3600 {
			if _, pending := c.cfg.PendingPeerDiscovery[address]; pending {
				_ = c.cfg.Update(func(fresh *Config) error {
					if e, ok := fresh.HandleCache[address]; ok && now.Unix()-e.At < 24*3600 {
						delete(fresh.PendingPeerDiscovery, address)
					}
					return nil
				})
			}
			continue
		}
		pending, queued := c.cfg.PendingPeerDiscovery[address]
		if now.Before(retries[address]) || (queued && now.Unix() < pending.RetryAt) {
			continue
		}
		attempts++
		retries[address] = now.Add(5 * time.Minute)
		if queued {
			if err := c.cfg.Update(func(fresh *Config) error {
				if e, ok := fresh.PendingPeerDiscovery[address]; ok {
					e.RetryAt = now.Add(5 * time.Minute).Unix()
					fresh.PendingPeerDiscovery[address] = e
				}
				return nil
			}); err != nil {
				continue
			}
		}
		profiles, err := c.directoryReverseContext(ctx, address)
		if err != nil {
			continue
		}
		handle := ""
		if len(profiles) > 0 {
			handle = profiles[0].Handle
		}
		if c.cachePeerHandle(address, handle) == nil {
			// A failed ACK write leaves harmless queued work, never loses a
			// discovery before the authoritative cache result is durable.
			if err := c.cfg.Update(func(fresh *Config) error { delete(fresh.PendingPeerDiscovery, address); return nil }); err == nil {
				delete(retries, address)
			}
		}
	}
}
