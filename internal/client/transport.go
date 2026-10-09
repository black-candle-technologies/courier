package client

import "github.com/black-candle-technologies/courier/internal/transport"

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
