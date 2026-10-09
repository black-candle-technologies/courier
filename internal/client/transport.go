package client

import (
	"encoding/json"
	"github.com/black-candle-technologies/courier/internal/transport"
	"os"
)

func (c *Config) validateTransport() error {
	if _, err := transport.Resolve(c.RelayTransport, c.RelayURL); err != nil {
		return err
	}
	endpoint := c.DashboardURL
	if endpoint == "" {
		endpoint = DefaultDashboardURL
	}
	_, err := transport.Resolve(c.DashboardTransport, endpoint)
	return err
}

// LoadTransportConfig reads without lazy migrations, key generation or writes.
// It is used by the optional upgrade review; damaged state must not block updating.
func (s Context) LoadTransportConfig() (*Config, error) { return s.loadConfigRaw() }

// AcknowledgeTransport records only the operator's review. Unlike Update, this
// transaction must not generate keys, migrate replay state or materialize defaults:
// even a damaged legacy identity must be able to update its executable.
func (c *Config) AcknowledgeTransport() error {
	scope := c.local()
	return scope.withConfigLock(func() error {
		fresh, err := scope.loadConfigRaw()
		if err != nil {
			return err
		}
		if fresh.Seed != c.Seed || fresh.Address != c.Address || fresh.RelayURL != c.RelayURL || fresh.RelayFingerprint != c.RelayFingerprint || fresh.RelayTransport != c.RelayTransport || fresh.DashboardURL != c.DashboardURL || fresh.DashboardFingerprint != c.DashboardFingerprint || fresh.DashboardTransport != c.DashboardTransport {
			return ErrContextMismatch
		}
		if !fresh.TransportReviewed {
			path, err := scope.configPath()
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				return err
			}
			fields["transport_reviewed"] = json.RawMessage("true")
			raw, err = json.MarshalIndent(fields, "", "  ")
			if err != nil {
				return err
			}
			if err := durableReplace(path, raw); err != nil {
				return err
			}
		}
		fresh.TransportReviewed = true
		c.refreshState(fresh)
		return nil
	})
}
