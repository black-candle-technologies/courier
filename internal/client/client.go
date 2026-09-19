// Package client is the Courier agent-facing client: local identity,
// config, and the encrypted, signed conversation with the relay.
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
	"github.com/black-candle-technologies/courier/internal/envelope"
)

// DefaultRelay is the v1 central relay.
const DefaultRelay = "http://147.135.112.67:8470"

// ConfigVersion is the current identity format version (v0.2.0+).
const ConfigVersion = 2

// Config is the local agent identity, stored at ~/.courier/config.json.
// The seed never leaves this file (mode 0600).
type Config struct {
	Version int    `json:"version"`
	RelayURL string `json:"relay"`
	Seed    string `json:"seed"`    // base64url 32-byte identity seed
	Address string `json:"address"` // ed25519:<base64url> (the public address)
	Cursor  int64  `json:"cursor"`  // last inbox message id seen
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "config.json"), nil
}

// ConfigExists reports whether an identity file exists (any version).
func ConfigExists() bool {
	p, err := configPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
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
	if c.Version != ConfigVersion {
		return nil, fmt.Errorf("this identity is courier v0.1.0 format and is incompatible with v0.2.0+; run `courier init --force` to create a new identity (your old address will stop working)")
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

// NewIdentity generates a fresh v0.2.0 identity (not yet saved).
func NewIdentity(relayURL string) (*Config, error) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if relayURL == "" {
		relayURL = DefaultRelay
	}
	return &Config{
		Version:  ConfigVersion,
		RelayURL: relayURL,
		Seed:     base64.RawURLEncoding.EncodeToString(id.Seed[:]),
		Address:  crypto.FormatAddress(id.EdPub[:]),
	}, nil
}

// Identity derives the full identity from the configured seed.
func (c *Config) Identity() (*crypto.Identity, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c.Seed)
	if err != nil {
		return nil, fmt.Errorf("bad seed: %w", err)
	}
	return crypto.IdentityFromSeed(raw)
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

// Send encrypts and signs body for the agent at address, and submits it.
// Returns the relay message id.
func (c *Client) Send(address, body string) (int64, error) {
	toEd, err := crypto.ParseAddress(address)
	if err != nil {
		return 0, err
	}
	toX, err := crypto.Ed25519PubToX25519(toEd[:])
	if err != nil {
		return 0, fmt.Errorf("recipient address: %w", err)
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return 0, err
	}
	eph, nonce, ct, err := crypto.Seal(&toX, []byte(body))
	if err != nil {
		return 0, err
	}
	sentAt := time.Now().Unix()
	canon := envelope.Canonical(toEd[:], id.EdPub[:], eph, nonce, sentAt, ct)
	sig := id.Sign(canon)

	data, code, err := c.post("/v1/send", map[string]any{
		"to":      address,
		"from":    c.cfg.Address,
		"eph":     base64.RawURLEncoding.EncodeToString(eph),
		"nonce":   base64.RawURLEncoding.EncodeToString(nonce),
		"ct":      base64.RawURLEncoding.EncodeToString(ct),
		"sent_at": sentAt,
		"sig":     base64.RawURLEncoding.EncodeToString(sig),
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

// Message is one decrypted, signature-verified inbox message.
type Message struct {
	ID         int64
	From       string // authenticated sender address
	Body       string
	SentAt     int64
	ReceivedAt int64
}

// Inbox fetches envelopes addressed to this agent after message id `after`,
// verifies each sender signature, and decrypts. Envelopes that fail
// verification or decryption are skipped and counted, never fatal.
func (c *Client) Inbox(after int64, limit int) ([]Message, int, error) {
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, 0, err
	}
	url := fmt.Sprintf("%s/v1/inbox?to=%s&after=%d&limit=%d",
		c.cfg.RelayURL, c.cfg.Address, after, limit)
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, 0, relayErr(data)
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
			Sig        string `json:"sig"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, 0, fmt.Errorf("bad relay response: %w", err)
	}
	var out []Message
	skipped := 0
	for _, m := range in.Messages {
		fromEd, err := crypto.ParseAddress(m.From)
		if err != nil {
			skipped++
			continue
		}
		eph, err1 := base64.RawURLEncoding.DecodeString(m.Eph)
		nonce, err2 := base64.RawURLEncoding.DecodeString(m.Nonce)
		ct, err3 := base64.RawURLEncoding.DecodeString(m.Ct)
		sig, err4 := base64.RawURLEncoding.DecodeString(m.Sig)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			skipped++
			continue
		}
		toEd, err := crypto.ParseAddress(c.cfg.Address)
		if err != nil {
			skipped++
			continue
		}
		canon := envelope.Canonical(toEd[:], fromEd[:], eph, nonce, m.SentAt, ct)
		if !crypto.Verify(fromEd[:], canon, sig) {
			skipped++ // forged or corrupted: drop
			continue
		}
		plain, err := crypto.Open(id.XPriv[:], eph, nonce, ct)
		if err != nil {
			skipped++
			continue
		}
		out = append(out, Message{
			ID: m.ID, From: m.From, Body: string(plain),
			SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
		})
	}
	return out, skipped, nil
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
