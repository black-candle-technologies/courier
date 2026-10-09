package client

import (
	"context"
	"sort"
	"time"
)

// RunDashboardMetadataRefresh renews expired discovery evidence separately
// from dashboard rendering. The worker owns a fresh Config/Client per pass;
// it never shares mutable client state with the message delivery loop.
func (c *Client) RunDashboardMetadataRefresh(ctx context.Context) {
	scope := c.cfg.Context()
	address, seed, relay, pin := c.cfg.Address, c.cfg.Seed, c.cfg.RelayURL, c.cfg.RelayFingerprint
	retries := make(map[string]time.Time)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if cfg, err := scope.LoadConfig(); err == nil {
			if cfg.Address != address || cfg.Seed != seed || cfg.RelayURL != relay || cfg.RelayFingerprint != pin {
				return
			}
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

// At most eight peers and five seconds per worker pass (set by the caller).
// Failures receive an in-memory five-minute retry delay, never a false cache
// entry. Successful verified responses keep the normal 24-hour cache TTL.
func (c *Client) refreshDashboardMetadata(ctx context.Context, retries map[string]time.Time, now time.Time) {
	peers := map[string]bool{}
	for address := range c.cfg.HandleCache {
		peers[address] = true
	}
	for _, address := range c.cfg.Contacts {
		peers[address] = true
	}
	ordered := make([]string, 0, len(peers))
	for address := range peers {
		ordered = append(ordered, address)
	}
	sort.Strings(ordered)
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
			continue
		}
		if now.Before(retries[address]) {
			continue
		}
		attempts++
		retries[address] = now.Add(5 * time.Minute)
		profiles, err := c.directoryReverseContext(ctx, address)
		if err != nil {
			continue
		}
		handle := ""
		if len(profiles) > 0 {
			handle = profiles[0].Handle
		}
		if c.cachePeerHandle(address, handle) == nil {
			delete(retries, address)
		}
	}
}

// RunDashboardMetadataRefresh is the legacy adapter. Resolve once before the
// worker starts; changing the default context never redirects a running worker.
func RunDashboardMetadataRefresh(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	cfg, err := LoadConfig()
	if err != nil {
		return
	}
	New(cfg).RunDashboardMetadataRefresh(ctx)
}
