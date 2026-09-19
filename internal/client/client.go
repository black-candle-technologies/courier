// Package client is the Courier agent-facing client: local identity,
// config, and the encrypted, signed conversation with the relay.
//
// Transport security (v0.3.0+): the relay serves HTTPS with a self-signed
// certificate. Clients pin the certificate's SHA256 fingerprint (stored in
// the config at init time, SSH-style TOFU). A relay presenting any other
// certificate is rejected, which defeats network-level impersonation and
// passive metadata collection.
package client

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/update"
)

// DefaultRelay is the central relay (HTTPS, pinned certificate).
const DefaultRelay = "https://147.135.112.67:8470"

// DefaultDashboardURL is the web dashboard (HTTPS, pinned certificate).
const DefaultDashboardURL = "https://147.135.112.67:8471"

// ConfigVersion is the current identity format version (v0.2.0+).
// v0.5.0 keeps version 2: new fields (contacts, encryption keys,
// auto-update) are lazily migrated on load, so existing identities keep
// working without re-init.
const ConfigVersion = 2

// maxRetainedKeys bounds how many retired encryption keys are kept for
// decrypting in-flight messages after a rotation.
const maxRetainedKeys = 4

// EncKey is one X25519 encryption keypair owned by this identity.
// Keys[0] is always the current key used for newly received messages;
// older entries decrypt messages sealed before a rotation.
type EncKey struct {
	Pub       string `json:"pub"`        // base64url 32-byte X25519 public key
	Priv      string `json:"priv"`       // base64url 32-byte X25519 private key
	Epoch     int64  `json:"epoch"`      // unix seconds of rotation (monotonic)
	CreatedAt int64  `json:"created_at"` // unix seconds
}

// Config is the local agent identity, stored at ~/.courier/config.json.
// The seed and encryption private keys never leave this file (mode 0600).
type Config struct {
	Version          int               `json:"version"`
	RelayURL         string            `json:"relay"`
	Seed             string            `json:"seed"`    // base64url 32-byte identity seed
	Address          string            `json:"address"` // ed25519:<base64url> (the public address)
	Cursor           int64             `json:"cursor"`  // last inbox message id seen
	RelayFingerprint string            `json:"relay_fingerprint,omitempty"` // hex SHA256 of relay cert
	Contacts         map[string]string `json:"contacts,omitempty"`          // name -> ed25519:<base64url> address
	EncKeys          []EncKey          `json:"enc_keys,omitempty"`          // current first; lazily migrated
	AutoUpdate       bool              `json:"auto_update,omitempty"`       // self-update when a newer release exists
	UpdateCheckedAt  int64             `json:"update_checked_at,omitempty"` // unix seconds of last update check
	// v0.6.0: web dashboard account. Token is the push API token (the
	// dashboard stores only its hash). DashboardCursor is the last
	// courier message id pushed.
	DashboardURL         string `json:"dashboard_url,omitempty"`
	DashboardUser        string `json:"dashboard_user,omitempty"`
	DashboardToken       string `json:"dashboard_token,omitempty"`
	DashboardFingerprint string `json:"dashboard_fingerprint,omitempty"`
	DashboardCursor      int64  `json:"dashboard_cursor,omitempty"`
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
	// v0.5.0 lazy migration: identities created before rotatable keys
	// derive their single encryption key from the seed (epoch 0).
	if len(c.EncKeys) == 0 {
		id, err := c.Identity()
		if err != nil {
			return nil, err
		}
		now := time.Now().Unix()
		c.EncKeys = []EncKey{{
			Pub:       base64.RawURLEncoding.EncodeToString(id.XPub[:]),
			Priv:      base64.RawURLEncoding.EncodeToString(id.XPriv[:]),
			Epoch:     0,
			CreatedAt: now,
		}}
		// Best effort: persist the migration so it only happens once.
		_ = c.Save()
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
	now := time.Now().Unix()
	return &Config{
		Version:  ConfigVersion,
		RelayURL: relayURL,
		Seed:     base64.RawURLEncoding.EncodeToString(id.Seed[:]),
		Address:  crypto.FormatAddress(id.EdPub[:]),
		EncKeys: []EncKey{{
			Pub:       base64.RawURLEncoding.EncodeToString(id.XPub[:]),
			Priv:      base64.RawURLEncoding.EncodeToString(id.XPriv[:]),
			Epoch:     0,
			CreatedAt: now,
		}},
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

// ---- contacts (v0.5.0) ----

var contactNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// AddContact stores name -> address after validating both.
func (c *Config) AddContact(name, address string) error {
	if !contactNameRe.MatchString(name) {
		return fmt.Errorf("bad contact name %q: use 1-32 chars, lowercase letters, digits, - and _, starting with a letter or digit", name)
	}
	if _, err := crypto.ParseAddress(address); err != nil {
		return fmt.Errorf("bad address: %w", err)
	}
	if c.Contacts == nil {
		c.Contacts = map[string]string{}
	}
	c.Contacts[name] = address
	return c.Save()
}

// RemoveContact deletes a contact. It is not an error if absent.
func (c *Config) RemoveContact(name string) error {
	delete(c.Contacts, name)
	return c.Save()
}

// LookupContact returns the address for a contact name.
func (c *Config) LookupContact(name string) (string, error) {
	addr, ok := c.Contacts[name]
	if !ok {
		return "", fmt.Errorf("unknown contact %q (see `courier contacts list`)", name)
	}
	return addr, nil
}

// ResolveRecipient accepts either a full "ed25519:..." address or a
// contact name, and returns the address.
func (c *Config) ResolveRecipient(toOrName string) (string, error) {
	if strings.HasPrefix(toOrName, crypto.AddressPrefix) {
		if _, err := crypto.ParseAddress(toOrName); err != nil {
			return "", err
		}
		return toOrName, nil
	}
	return c.LookupContact(toOrName)
}

// ---- rotatable encryption keys (v0.5.0) ----

// currentEncKey returns the active encryption keypair.
func (c *Config) currentEncKey() (pub, priv [32]byte, epoch int64, err error) {
	if len(c.EncKeys) == 0 {
		return pub, priv, 0, errors.New("no encryption keys in config")
	}
	k := c.EncKeys[0]
	pubRaw, err1 := base64.RawURLEncoding.DecodeString(k.Pub)
	privRaw, err2 := base64.RawURLEncoding.DecodeString(k.Priv)
	if err1 != nil || err2 != nil || len(pubRaw) != 32 || len(privRaw) != 32 {
		return pub, priv, 0, errors.New("corrupt encryption key in config")
	}
	copy(pub[:], pubRaw)
	copy(priv[:], privRaw)
	return pub, priv, k.Epoch, nil
}

// encryptionPrivKeys returns all retained private keys, current first,
// for trial decryption of messages sealed before a rotation.
func (c *Config) encryptionPrivKeys() [][32]byte {
	var out [][32]byte
	for _, k := range c.EncKeys {
		raw, err := base64.RawURLEncoding.DecodeString(k.Priv)
		if err != nil || len(raw) != 32 {
			continue
		}
		var p [32]byte
		copy(p[:], raw)
		out = append(out, p)
	}
	return out
}

// RotateKey generates a fresh encryption keypair, makes it current, and
// publishes a signed announcement to the relay so future senders use it.
// Retired keys are kept (up to maxRetainedKeys) to decrypt in-flight
// messages. The Ed25519 identity — and therefore the address — is unchanged.
func (c *Client) RotateKey() (published bool, err error) {
	pub, priv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return false, err
	}
	epoch := time.Now().Unix()
	// Monotonic epoch even within the same second as a previous rotation.
	if len(c.cfg.EncKeys) > 0 && epoch <= c.cfg.EncKeys[0].Epoch {
		epoch = c.cfg.EncKeys[0].Epoch + 1
	}
	c.cfg.EncKeys = append([]EncKey{{
		Pub:       base64.RawURLEncoding.EncodeToString(pub[:]),
		Priv:      base64.RawURLEncoding.EncodeToString(priv[:]),
		Epoch:     epoch,
		CreatedAt: time.Now().Unix(),
	}}, c.cfg.EncKeys...)
	if len(c.cfg.EncKeys) > maxRetainedKeys {
		c.cfg.EncKeys = c.cfg.EncKeys[:maxRetainedKeys]
	}
	if err := c.cfg.Save(); err != nil {
		return false, err
	}
	if err := c.PublishKey(); err != nil {
		return false, fmt.Errorf("key rotated locally but NOT published: %w (run `courier publish-key` to announce it)", err)
	}
	return true, nil
}

// PublishKey announces the current encryption key to the relay's key
// directory, signed by the Ed25519 identity key.
func (c *Client) PublishKey() error {
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	pub, _, epoch, err := c.cfg.currentEncKey()
	if err != nil {
		return err
	}
	canon := envelope.KeyAnnounce(id.EdPub[:], pub[:], epoch)
	sig := id.Sign(canon)
	data, code, err := c.post("/v1/keys", map[string]any{
		"address":    c.cfg.Address,
		"x25519_pub": base64.RawURLEncoding.EncodeToString(pub[:]),
		"epoch":      epoch,
		"sig":        base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if code != http.StatusCreated {
		return relayErr(data)
	}
	return nil
}

// recipientKey returns the X25519 public key to seal for: the recipient's
// published (rotated) key if they announced one, else the key derived from
// their address (pre-v0.5.0 peers and anyone who never rotated).
func (c *Client) recipientKey(address string) ([32]byte, error) {
	var out [32]byte
	hc, err := c.httpClient()
	if err != nil {
		return out, err
	}
	resp, err := hc.Get(c.cfg.RelayURL + "/v1/keys/" + url.PathEscape(address))
	if err != nil {
		return out, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode == http.StatusNotFound {
		toEd, err := crypto.ParseAddress(address)
		if err != nil {
			return out, err
		}
		return crypto.Ed25519PubToX25519(toEd[:])
	}
	if resp.StatusCode != http.StatusOK {
		return out, relayErr(data)
	}
	var ann struct {
		X25519Pub string `json:"x25519_pub"`
	}
	if err := json.Unmarshal(data, &ann); err != nil {
		return out, fmt.Errorf("bad relay response: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ann.X25519Pub)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("bad relay response: invalid x25519_pub")
	}
	copy(out[:], raw)
	return out, nil
}

// Client talks to the relay.
type Client struct {
	cfg *Config
}

// New returns a Client for cfg.
func New(cfg *Config) *Client {
	return &Client{cfg: cfg}
}

// httpClient builds the transport, enforcing certificate pinning for
// https relays. Plain http relays (custom/local) skip TLS.
func (c *Client) httpClient() (*http.Client, error) {
	if !strings.HasPrefix(c.cfg.RelayURL, "https://") {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	if c.cfg.RelayFingerprint == "" {
		return nil, fmt.Errorf("no pinned certificate for relay %s; run `courier init --repin` to pin it (verify the fingerprint against the published value first)", c.cfg.RelayURL)
	}
	tr, err := pinnedTransport(c.cfg.RelayFingerprint)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}, nil
}

// pinnedTransport builds an HTTP transport that pins the server's TLS
// certificate to the given hex SHA256 fingerprint. Proxy env vars are
// honored; the pin still applies end-to-end.
func pinnedTransport(fingerprint string) (*http.Transport, error) {
	want, err := hex.DecodeString(fingerprint)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("bad pinned fingerprint; verify and re-pin")
	}
	return &http.Transport{
		// Honor HTTPS_PROXY etc. so agents behind egress proxies can
		// reach the server. The proxy only tunnels bytes (CONNECT);
		// TLS still terminates at the server and the pin below applies
		// end-to-end.
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			// Certificate authority validation is skipped: trust comes
			// from the pinned fingerprint checked below, not from CAs.
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("server presented no certificate")
				}
				sum := sha256.Sum256(rawCerts[0])
				if subtle.ConstantTimeCompare(sum[:], want) != 1 {
					return fmt.Errorf("server certificate mismatch: got SHA256 %x; the server may be impersonated or its certificate rotated", sum)
				}
				return nil
			},
		},
	}, nil
}

// dashboardHTTPClient returns a pinned client for the dashboard, or an
// error directing the agent to run `courier dashboard setup`.
func (c *Client) dashboardHTTPClient() (*http.Client, error) {
	if c.cfg.DashboardToken == "" {
		return nil, fmt.Errorf("no dashboard account configured; run `courier dashboard setup` first")
	}
	if !strings.HasPrefix(c.cfg.DashboardURL, "https://") {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	if c.cfg.DashboardFingerprint == "" {
		return nil, fmt.Errorf("no pinned certificate for dashboard %s; run `courier dashboard setup` again", c.cfg.DashboardURL)
	}
	tr, err := pinnedTransport(c.cfg.DashboardFingerprint)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}, nil
}

// FetchRelayFingerprint dials an https relay and returns the hex SHA256 of
// the certificate it presents, without trusting it. This is the TOFU step:
// the caller must show the fingerprint to the user for verification before
// saving it. Returns "" for non-https relays. Honors HTTPS_PROXY.
func FetchRelayFingerprint(relayURL string) (string, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return "", fmt.Errorf("bad relay URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", nil
	}
	var peer *x509.Certificate
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	hc := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	resp, err := hc.Get(relayURL + "/v1/health")
	if err != nil {
		return "", fmt.Errorf("relay unreachable: %w", err)
	}
	resp.Body.Close()
	// The presented certificate is captured from the completed TLS session.
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", errors.New("relay presented no certificate")
	}
	peer = resp.TLS.PeerCertificates[0]
	sum := sha256.Sum256(peer.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Client) post(path string, body any) ([]byte, int, error) {
	hc, err := c.httpClient()
	if err != nil {
		return nil, 0, err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	resp, err := hc.Post(c.cfg.RelayURL+path, "application/json", bytes.NewReader(raw))
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

// Send encrypts and signs body for the agent at toOrName (a full address
// or a contact name), and submits it. The recipient's published encryption
// key is used when they rotated; otherwise the address-derived key.
// Returns the relay message id.
func (c *Client) Send(toOrName, body string) (int64, error) {
	address, err := c.cfg.ResolveRecipient(toOrName)
	if err != nil {
		return 0, err
	}
	toEd, err := crypto.ParseAddress(address)
	if err != nil {
		return 0, err
	}
	toX, err := c.recipientKey(address)
	if err != nil {
		return 0, fmt.Errorf("recipient key: %w", err)
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
	hc, err := c.httpClient()
	if err != nil {
		return nil, 0, err
	}
	url := fmt.Sprintf("%s/v1/inbox?to=%s&after=%d&limit=%d",
		c.cfg.RelayURL, c.cfg.Address, after, limit)
	resp, err := hc.Get(url)
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
		// Trial-decrypt across retained keys: messages sealed before a
		// rotation still open with the retired key.
		var plain []byte
		for _, xp := range c.cfg.encryptionPrivKeys() {
			if p, err := crypto.Open(xp[:], eph, nonce, ct); err == nil {
				plain = p
				break
			}
		}
		if plain == nil {
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
	hc, err := c.httpClient()
	if err != nil {
		return err
	}
	resp, err := hc.Get(c.cfg.RelayURL + "/v1/health")
	if err != nil {
		return fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("relay unhealthy: %s", resp.Status)
	}
	return nil
}

// updateCheckInterval bounds how often the client phones home to the
// GitHub releases API: at most once per 24 hours.
const updateCheckInterval = 24 * 3600

// MaybeUpdateCheck looks for a newer Courier release (at most once per
// day). If one exists it either auto-installs it (AutoUpdate set) or
// prints a notice to stderr. Network failures are silent: an unreachable
// update server must never break messaging.
func (c *Client) MaybeUpdateCheck(current string) {
	now := time.Now().Unix()
	if now-c.cfg.UpdateCheckedAt < updateCheckInterval {
		return
	}
	rel, err := update.Latest()
	c.cfg.UpdateCheckedAt = now
	_ = c.cfg.Save()
	if err != nil {
		return
	}
	if !update.NewerThan(current, rel.Tag) {
		return
	}
	if c.cfg.AutoUpdate {
		if err := rel.Apply(); err != nil {
			fmt.Fprintf(os.Stderr, "courier auto-update to %s failed: %v\n", rel.Tag, err)
			return
		}
		fmt.Fprintf(os.Stderr, "courier auto-updated to %s (this run used the previous version)\n", rel.Tag)
		if c.cfg.DashboardToken == "" {
			fmt.Fprintf(os.Stderr, "new in this release: web dashboard — run `courier dashboard setup --username <name>` to create your user's login\n")
		}
		return
	}
	fmt.Fprintf(os.Stderr, "a newer courier %s is available: run `courier update`\n", rel.Tag)
}

// ---- v0.6.0: web dashboard ----

// dashboardUsernameRe validates dashboard usernames (same shape as
// contacts: 3-32 lowercase alnum, - and _).
var dashboardUsernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

// tempPasswordAlphabet avoids ambiguous characters (no 0/O, 1/l).
const tempPasswordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GenerateTempPassword returns a 20-character cryptographically random
// temporary password for dashboard registration.
func GenerateTempPassword() (string, error) {
	out := make([]byte, 20)
	for i := range out {
		var b [1]byte
		if _, err := crand.Read(b[:]); err != nil {
			return "", err
		}
		out[i] = tempPasswordAlphabet[int(b[0])%len(tempPasswordAlphabet)]
	}
	return string(out), nil
}

// DashboardSetup registers a dashboard user for this Courier identity.
// The agent picks (or prompts the user for) a username; the client
// generates a temporary password, proves identity ownership with an
// Ed25519 registration signature, and stores the returned API token.
// It returns the temporary password, which the agent must hand to the
// user: it is never stored server-side and must be changed on first
// login.
func (c *Client) DashboardSetup(username string) (tempPassword string, err error) {
	if !dashboardUsernameRe.MatchString(username) {
		return "", fmt.Errorf("username must be 3-32 chars: lowercase letters, digits, - and _")
	}
	if c.cfg.DashboardToken != "" {
		return "", fmt.Errorf("dashboard already configured for user %q; reset by clearing dashboard_* in the config", c.cfg.DashboardUser)
	}
	if c.cfg.DashboardURL == "" {
		c.cfg.DashboardURL = DefaultDashboardURL
	}
	tempPassword, err = GenerateTempPassword()
	if err != nil {
		return "", err
	}
	addr, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return "", err
	}
	canon := envelope.DashboardRegister(username, addr[:])
	id, err := c.cfg.Identity()
	if err != nil {
		return "", err
	}
	sig := id.Sign(canon)

	// Pin the dashboard certificate (TOFU). The dashboard shares the
	// relay's certificate, so the fingerprint should match the published
	// relay value; print it for verification.
	fp, err := FetchRelayFingerprint(c.cfg.DashboardURL)
	if err != nil {
		return "", fmt.Errorf("dashboard unreachable: %w", err)
	}
	fmt.Fprintf(os.Stderr, "dashboard certificate SHA256: %s\n", fp)

	hc, err := pinnedTransport(fp)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": tempPassword,
		"address":  c.cfg.Address,
		"sig":      base64.RawURLEncoding.EncodeToString(sig),
	})
	resp, err := (&http.Client{Timeout: 30 * time.Second, Transport: hc}).Post(
		c.cfg.DashboardURL+"/v1/dashboard/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusCreated {
		var er struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &er)
		if er.Error == "" {
			er.Error = resp.Status
		}
		return "", fmt.Errorf("register failed: %s", er.Error)
	}
	var out struct {
		Username string `json:"username"`
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.APIToken == "" {
		return "", fmt.Errorf("register: bad response")
	}
	c.cfg.DashboardUser = out.Username
	c.cfg.DashboardToken = out.APIToken
	c.cfg.DashboardFingerprint = fp
	if err := c.cfg.Save(); err != nil {
		return "", fmt.Errorf("save config: %w", err)
	}
	return tempPassword, nil
}

// pushMsg is one decrypted message forwarded to the dashboard.
type pushMsg struct {
	CourierID  int64  `json:"courier_id"`
	From       string `json:"from"`
	Body       string `json:"body"`
	SentAt     int64  `json:"sent_at"`
	ReceivedAt int64  `json:"received_at"`
}

// DashboardPush decrypts new inbox messages and pushes them to the
// dashboard for the user to read. It advances the dashboard cursor past
// every message it attempted, so a retry never re-pushes.
func (c *Client) DashboardPush() (pushed int, err error) {
	hc, err := c.dashboardHTTPClient()
	if err != nil {
		return 0, err
	}
	msgs, next, err := c.Inbox(c.cfg.DashboardCursor, 200)
	if err != nil {
		return 0, err
	}
	var batch []pushMsg
	for _, m := range msgs {
		batch = append(batch, pushMsg{
			CourierID: m.ID, From: m.From, Body: m.Body,
			SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
		})
	}
	if len(batch) > 0 {
		body, _ := json.Marshal(map[string]any{"messages": batch})
		req, _ := http.NewRequest(http.MethodPost, c.cfg.DashboardURL+"/v1/dashboard/push", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.cfg.DashboardToken)
		resp, err := hc.Do(req)
		if err != nil {
			return 0, fmt.Errorf("push: %w", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if resp.StatusCode != http.StatusOK {
			var er struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(raw, &er)
			if er.Error == "" {
				er.Error = resp.Status
			}
			return 0, fmt.Errorf("push failed: %s", er.Error)
		}
		var out struct {
			Stored int `json:"stored"`
		}
		_ = json.Unmarshal(raw, &out)
		pushed = out.Stored
	}
	c.cfg.DashboardCursor = int64(next)
	_ = c.cfg.Save()
	return pushed, nil
}
