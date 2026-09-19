// Package client is the Courier agent-facing client: local identity,
// config, and the encrypted conversation with the relay.
package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// DefaultRelay is the v1 central relay.
const DefaultRelay = "http://147.135.112.67:8470"

// Config is the local agent identity, stored at ~/.courier/config.json.
// The private key never leaves this file (mode 0600).
type Config struct {
	RelayURL string `json:"relay"`
	PrivKey  string `json:"privkey"` // base64url X25519 private key
	PubKey   string `json:"pubkey"`  // base64url X25519 public key (the address)
	Cursor   int64  `json:"cursor"`  // last inbox message id seen
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "config.json"), nil
}

// LoadConfig reads the local identity.
func LoadConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("no courier identity: run `courier init` first (%w)", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("bad config: %w", err)
	}
	if c.RelayURL == "" {
		c.RelayURL = DefaultRelay
	}
	return &c, nil
}

// Save writes the config with mode 0600.
func (c *Config) Save() error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o600)
}

// NewIdentity generates a fresh keypair and config (not yet saved).
func NewIdentity(relayURL string) (*Config, error) {
	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	if relayURL == "" {
		relayURL = DefaultRelay
	}
	return &Config{
		RelayURL: relayURL,
		PrivKey:  base64.RawURLEncoding.EncodeToString(priv[:]),
		PubKey:   crypto.EncodeKey(pub),
	}, nil
}

// Keys decodes the configured keypair.
func (c *Config) Keys() (pub, priv *[32]byte, err error) {
	pub, err = crypto.DecodeKey(c.PubKey)
	if err != nil {
		return nil, nil, err
	}
	priv, err = crypto.DecodePrivKey(c.PrivKey)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// Client talks to the relay.
type Client struct {
	cfg  *Config
	http *http.Client
}

// New returns a Client for cfg.
func New(cfg *Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) post(path string, body any) ([]byte, int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.http.Post(c.cfg.RelayURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		return nil, 0, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return data, resp.StatusCode, nil
}

func relayErr(data []byte) error {
	var m map[string]string
	if json.Unmarshal(data, &m) == nil && m["error"] != "" {
		return fmt.Errorf("relay: %s", m["error"])
	}
	return fmt.Errorf("relay: unexpected response")
}

// Send encrypts body to the agent at address and submits it to the relay.
// Returns the relay message id.
func (c *Client) Send(address, body string) (int64, error) {
	toPub, err := crypto.DecodeKey(address)
	if err != nil {
		return 0, err
	}
	_, priv, err := c.cfg.Keys()
	if err != nil {
		return 0, err
	}
	_ = priv // reserved: future sender-authenticated mode
	eph, nonce, ct, err := crypto.Seal(toPub, []byte(body))
	if err != nil {
		return 0, err
	}
	data, code, err := c.post("/v1/send", map[string]any{
		"to":      address,
		"from":    c.cfg.PubKey,
		"eph":     base64.RawURLEncoding.EncodeToString(eph),
		"nonce":   base64.RawURLEncoding.EncodeToString(nonce),
		"ct":      base64.RawURLEncoding.EncodeToString(ct),
		"sent_at": time.Now().Unix(),
	})
	if err != nil {
		return 0, err
	}
	if code != http.StatusCreated {
		return 0, relayErr(data)
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, fmt.Errorf("bad relay response: %w", err)
	}
	return out.ID, nil
}

// Message is one decrypted inbox message.
type Message struct {
	ID         int64
	From       string
	Body       string
	SentAt     int64
	ReceivedAt int64
}

// Inbox fetches envelopes addressed to this agent after message id `after`
// and decrypts them. Undecryptable envelopes are skipped, never fatal.
func (c *Client) Inbox(after int64, limit int) ([]Message, error) {
	_, priv, err := c.cfg.Keys()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/v1/inbox?to=%s&after=%d&limit=%d",
		c.cfg.RelayURL, c.cfg.PubKey, after, limit)
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, relayErr(data)
	}
	var in struct {
		Messages []struct {
			ID         int64  `json:"id"`
			From       string `json:"from"`
			Eph        string `json:"eph"`
			Nonce      string `json:"nonce"`
			Ct         string `json:"ct"`
			SentAt     int64  `json:"sent_at"`
			ReceivedAt int64  `json:"received_at"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, fmt.Errorf("bad relay response: %w", err)
	}
	var out []Message
	for _, m := range in.Messages {
		eph, err1 := base64.RawURLEncoding.DecodeString(m.Eph)
		nonce, err2 := base64.RawURLEncoding.DecodeString(m.Nonce)
		ct, err3 := base64.RawURLEncoding.DecodeString(m.Ct)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		plain, err := crypto.Open(priv[:], eph, nonce, ct)
		if err != nil {
			continue
		}
		out = append(out, Message{
			ID: m.ID, From: m.From, Body: string(plain),
			SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
		})
	}
	return out, nil
}

// Ping checks the relay is reachable.
func (c *Client) Ping() error {
	resp, err := c.http.Get(c.cfg.RelayURL + "/v1/health")
	if err != nil {
		return fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relay unhealthy: %s", resp.Status)
	}
	return nil
}
