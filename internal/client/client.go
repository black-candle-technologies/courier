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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/update"
)

// DefaultRelay is the central relay (HTTPS, pinned certificate).
const DefaultRelay = "https://courier.blackcandletech.com:8470"

// DefaultDashboardURL is the web dashboard (HTTPS, pinned certificate).
const DefaultDashboardURL = "https://courier.blackcandletech.com:8471"

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
	Seed             string            `json:"seed"`                        // base64url 32-byte identity seed
	Address          string            `json:"address"`                     // ed25519:<base64url> (the public address)
	Cursor           int64             `json:"cursor"`                      // last inbox message id seen
	RelayFingerprint string            `json:"relay_fingerprint,omitempty"` // hex SHA256 of relay cert
	Contacts         map[string]string `json:"contacts,omitempty"`          // name -> ed25519:<base64url> address
	// issue #48 (phase 1): out-of-band contact verifications, keyed by
	// contact name. A record pins the address + key epoch the safety
	// number was computed over; if either changes, trust goes stale.
	ContactVerifications map[string]ContactVerification `json:"contact_verifications,omitempty"`
	EncKeys              []EncKey                       `json:"enc_keys,omitempty"`          // current first; lazily migrated
	AutoUpdate           *bool                          `json:"auto_update,omitempty"`       // nil = unset: auto-install newer releases (v0.6.12+ default); false opts out
	UpdateCheckedAt      int64                          `json:"update_checked_at,omitempty"` // unix seconds of last update check
	// v0.6.0: web dashboard account. Token is the push API token (the
	// dashboard stores only its hash). DashboardCursor is the last
	// courier message id pushed.
	DashboardURL         string `json:"dashboard_url,omitempty"`
	DashboardUser        string `json:"dashboard_user,omitempty"`
	DashboardToken       string `json:"dashboard_token,omitempty"`
	DashboardFingerprint string `json:"dashboard_fingerprint,omitempty"`
	DashboardCursor      int64  `json:"dashboard_cursor,omitempty"`
	// v0.6.5: sent-message log cursor for dashboard threading.
	DashboardSentCursor int64 `json:"dashboard_sent_cursor,omitempty"`
	// v0.6.11: highest verified key-directory epoch per recipient address
	// (F1). The relay's key announcement is only trusted after its
	// Ed25519 signature verifies under the recipient's address, and an
	// announcement with a lower epoch than recorded is rejected as a
	// rollback — so a malicious relay cannot substitute keys.
	VerifiedKeyEpochs map[string]int64 `json:"verified_key_epochs,omitempty"`
	// v0.6.11 (F3): hashes of envelopes already delivered to this
	// client, for replay suppression independent of relay message ids.
	// Bounded (oldest dropped); the relay also dedups permanently.
	//
	// v0.9.2 (issue #45): the set is tracked per consumer. The legacy
	// shared seen_envelope_hashes let `dashboard push` and the inbox
	// poller consume each other's messages — whichever ran first
	// marked an envelope seen and the other silently suppressed it as
	// a replay. SeenInboxHashes covers `courier inbox` (plus the group
	// inbox and request-review paths); SeenPushHashes covers
	// `dashboard push`. The legacy field is migrated into both sets on
	// load (migrateSeenSets) and then dropped.
	SeenEnvelopeHashes []string `json:"seen_envelope_hashes,omitempty"` // deprecated: use the per-consumer sets
	SeenInboxHashes    []string `json:"seen_inbox_hashes,omitempty"`
	SeenPushHashes     []string `json:"seen_push_hashes,omitempty"`
	// issue #49: SeenStateHashes covers `courier state sync`, the
	// shared-state catch-up fetch. It starts empty on upgrade; the
	// sync cursor is seeded from the inbox/push cursors, whose fetches
	// already applied older state events.
	SeenStateHashes []string `json:"seen_state_hashes,omitempty"`
	// issue #52: per-contact delivery/read receipt opt-in, keyed by
	// recipient address. Strictly opt-in: receipts never leak read
	// activity unless the operator explicitly enabled them for the
	// sender (`courier contacts receipts-on <name>`). Default off;
	// cleared when the contact is removed.
	ReceiptContacts map[string]bool `json:"receipt_contacts,omitempty"`
	// Spam/abuse filtering (metadata-only; the relay never sees
	// plaintext). DMPolicy is "open" (default, unset) or "contacts":
	// in contacts mode, messages from senders not in contacts are
	// quarantined — held for review, never silently dropped.
	DMPolicy string `json:"dm_policy,omitempty"`
	// Blocked lists sender addresses whose messages are dropped at
	// inbox time. The cursor still advances past them, so unblocking
	// later plus `inbox --all` recovers them.
	Blocked []string `json:"blocked,omitempty"`
	// Dismissed lists sender addresses whose message requests were
	// dismissed via `courier request dismiss`. Their messages no longer
	// surface as requests; they are dropped at read time like blocked
	// senders, visibly counted but never mixed into the inbox.
	// Reversible with `courier request undismiss`.
	Dismissed []string `json:"dismissed,omitempty"`
	// Contact discovery (issue #39, v0.8.0). DirectoryHandle is this
	// agent's registered handle; DirectoryEpoch is the last directory
	// epoch used (strictly increasing, survives restarts). Introductions
	// are pending introduction requests/introductions awaiting a
	// decision. HandleCache maps peer addresses to listed handles for
	// dashboard display (24h TTL, bounded).
	DirectoryHandle string                      `json:"directory_handle,omitempty"`
	DirectoryEpoch  int64                       `json:"directory_epoch,omitempty"`
	Introductions   []PendingIntroduction       `json:"introductions,omitempty"`
	HandleCache     map[string]HandleCacheEntry `json:"handle_cache,omitempty"`
	// HandleRefreshAt is the last time refreshPeerHandles pushed a
	// handles-only update; refreshed at most once per 24h so inactive
	// threads get their labels without a message batch.
	HandleRefreshAt int64 `json:"handle_refresh_at,omitempty"`
	// Instant wake (issue #42). WakeCursor is the last envelope id the
	// wake daemon observed. It is tracked separately from Cursor so
	// observing a message never consumes it: a woken agent still sees
	// it as new in `courier inbox`.
	WakeCursor int64 `json:"wake_cursor,omitempty"`
}

// HandleCacheEntry is a cached address→handle mapping with a local
// timestamp; entries older than 24h are refreshed on next use.
type HandleCacheEntry struct {
	Handle string `json:"handle"`
	At     int64  `json:"at"`
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

// configMu serializes in-process config access across goroutines.
// withConfigLock holds it for the whole read-modify-write cycle, and the
// flock serializes across processes; together they make Update atomic
// against every other Courier config writer on the machine.
var configMu sync.Mutex

// loadConfigRaw reads and parses the config file: version check and
// defaults, but no migrations and no writes.
func loadConfigRaw() (*Config, error) {
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

// seenConsumer identifies one of the independent consumers that read
// the inbox. Each tracks its own replay-suppression set (issue #45):
// the inbox poller and the dashboard pusher must never consume each
// other's messages.
type seenConsumer int

const (
	// seenConsumerInbox covers `courier inbox`, the group inbox fetch,
	// and request review — everything that delivers to the local agent.
	seenConsumerInbox seenConsumer = iota
	// seenConsumerPush covers `courier dashboard push` — everything
	// whose delivery target is the web dashboard.
	seenConsumerPush
	// seenConsumerState covers `courier state sync` — the shared-state
	// catch-up fetch (issue #49). It never consumes inbox or
	// dashboard-push messages: it only applies state events, which the
	// other consumers apply idempotently on their own passes.
	seenConsumerState
)

// migrateSeenSets applies the v0.9.2 lazy migration (issue #45): the
// legacy shared seen_envelope_hashes is split into per-consumer sets.
// Both consumers are seeded with the legacy union so nothing replays
// on upgrade, whichever consumer originally recorded a hash; the
// legacy field is then dropped.
func migrateSeenSets(c *Config) {
	if len(c.SeenEnvelopeHashes) == 0 {
		return
	}
	c.SeenInboxHashes = unionSeen(c.SeenInboxHashes, c.SeenEnvelopeHashes)
	c.SeenPushHashes = unionSeen(c.SeenPushHashes, c.SeenEnvelopeHashes)
	c.SeenEnvelopeHashes = nil
}

// unionSeen merges hashes into dst without duplicates, keeping the
// newest maxSeenEnvelopeHashes entries. The "" quarantine sentinel is
// never stored: held messages are not delivered.
func unionSeen(dst, hashes []string) []string {
	known := make(map[string]bool, len(dst))
	for _, h := range dst {
		known[h] = true
	}
	for _, h := range hashes {
		if h == "" || known[h] {
			continue
		}
		known[h] = true
		dst = append(dst, h)
	}
	if len(dst) > maxSeenEnvelopeHashes {
		dst = dst[len(dst)-maxSeenEnvelopeHashes:]
	}
	return dst
}

// migrateEncKeys applies the v0.5.0 lazy migration: identities created
// before rotatable keys derive their single encryption key from the seed
// (epoch 0).
func migrateEncKeys(c *Config) error {
	if len(c.EncKeys) != 0 {
		return nil
	}
	id, err := c.Identity()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	c.EncKeys = []EncKey{{
		Pub:       base64.RawURLEncoding.EncodeToString(id.XPub[:]),
		Priv:      base64.RawURLEncoding.EncodeToString(id.XPriv[:]),
		Epoch:     0,
		CreatedAt: now,
	}}
	return nil
}

// LoadConfig reads the local identity.
func LoadConfig() (*Config, error) {
	c, err := loadConfigRaw()
	if err != nil {
		return nil, err
	}
	migrated := false
	if len(c.EncKeys) == 0 {
		if err := migrateEncKeys(c); err != nil {
			return nil, err
		}
		migrated = true
	}
	if len(c.SeenEnvelopeHashes) > 0 {
		migrateSeenSets(c)
		migrated = true
	}
	if migrated {
		// Best effort: persist the migration so it only happens once.
		_ = c.Save()
	}
	return c, nil
}

// saveAtomic writes the config via temp file + rename in the same
// directory, so a crash can never leave a partially written config.
func (c *Config) saveAtomic() error {
	p, err := configPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

// Save writes the config with mode 0600: atomically (temp file + rename)
// and serialized against other Courier processes via the config lock.
//
// NOTE: Save persists the in-memory struct as-is. Code that mutates a
// long-lived Config (e.g. advancing a cursor in a --follow loop) must use
// Update instead, which reloads the freshest on-disk state first —
// otherwise fields another process changed meanwhile (e.g. rotated
// encryption keys) are silently clobbered.
func (c *Config) Save() error {
	return withConfigLock(func() error { return c.saveAtomic() })
}

// Update performs an atomic read-modify-write: it takes the cross-process
// config lock, reloads the freshest on-disk state, applies fn, and saves
// atomically. On success the receiver is refreshed to the saved state.
// This is the correct way to mutate config from long-running processes;
// mutating a stale in-memory Config and calling Save would clobber fields
// another process wrote meanwhile (v0.6.11 F5).
func (c *Config) Update(fn func(*Config) error) error {
	return withConfigLock(func() error {
		fresh, err := loadConfigRaw()
		if err != nil {
			return err
		}
		if len(fresh.EncKeys) == 0 {
			if err := migrateEncKeys(fresh); err != nil {
				return err
			}
		}
		// v0.9.2 (issue #45): migrate the legacy shared seen set into
		// the per-consumer sets. Persisted by the saveAtomic below.
		migrateSeenSets(fresh)
		if err := fn(fresh); err != nil {
			return err
		}
		if err := fresh.saveAtomic(); err != nil {
			return err
		}
		*c = *fresh
		return nil
	})
}

// NewIdentity generates a fresh v0.2.0 identity (not yet saved).
//
// v0.6.11 (F13): the initial encryption key is an independent random
// X25519 keypair, NOT derived from the identity seed. A seed-derived
// initial key could be regenerated by anyone holding the seed,
// defeating the point of key separation. The announcement for this key
// should be published at init (cmdInit does so best-effort); until it
// is, senders fall back to the address-derived key, which this identity
// cannot decrypt — so publishing promptly matters.
func NewIdentity(relayURL string) (*Config, error) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	if relayURL == "" {
		relayURL = DefaultRelay
	}
	now := time.Now().Unix()
	xpub, xpriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return nil, err
	}
	return &Config{
		Version:  ConfigVersion,
		RelayURL: relayURL,
		Seed:     base64.RawURLEncoding.EncodeToString(id.Seed[:]),
		Address:  crypto.FormatAddress(id.EdPub[:]),
		EncKeys: []EncKey{{
			Pub:       base64.RawURLEncoding.EncodeToString(xpub[:]),
			Priv:      base64.RawURLEncoding.EncodeToString(xpriv[:]),
			Epoch:     now,
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

// RemoveContact deletes a contact and its verification record (issue
// #48: a removed contact's trust must not resurrect if re-added), plus
// its receipt opt-in (issue #52: no lingering activity-leak consent).
// It is not an error if absent.
func (c *Config) RemoveContact(name string) error {
	if addr, ok := c.Contacts[name]; ok {
		delete(c.ReceiptContacts, addr)
	}
	delete(c.Contacts, name)
	delete(c.ContactVerifications, name)
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

// ---- spam / abuse filtering (metadata-only) ----

// DMPolicyOpen and DMPolicyContacts are the valid dm_policy values.
const (
	DMPolicyOpen     = "open"
	DMPolicyContacts = "contacts"
)

// DMPolicyEffective returns the recipient-consent policy: "open" unless
// the operator set "contacts". Unset (pre-existing configs) means open,
// so the default never changes behavior for existing users.
func (c *Config) DMPolicyEffective() string {
	if c.DMPolicy == DMPolicyContacts {
		return DMPolicyContacts
	}
	return DMPolicyOpen
}

// ContactsOnly reports whether inbound messages from unknown senders
// should be quarantined instead of delivered.
func (c *Config) ContactsOnly() bool { return c.DMPolicyEffective() == DMPolicyContacts }

// contactAddressSet returns every trusted sender address: all contacts
// plus the agent's own address (self-messages are never quarantined).
func (c *Config) contactAddressSet() map[string]bool {
	set := make(map[string]bool, len(c.Contacts)+1)
	for _, addr := range c.Contacts {
		set[addr] = true
	}
	set[c.Address] = true
	return set
}

// HoldForReview reports whether a message from `from` should be
// quarantined: in contacts mode, any authenticated sender who is not a
// contact (and not self) is held for review instead of delivered.
func (c *Config) HoldForReview(from string) bool {
	if !c.ContactsOnly() {
		return false
	}
	return !c.contactAddressSet()[from]
}

// IsBlocked reports whether from is on this recipient's blocklist.
func (c *Config) IsBlocked(from string) bool {
	for _, b := range c.Blocked {
		if b == from {
			return true
		}
	}
	return false
}

// IsDismissed reports whether from's message requests were dismissed.
func (c *Config) IsDismissed(from string) bool {
	for _, d := range c.Dismissed {
		if d == from {
			return true
		}
	}
	return false
}

// IsFirstContact reports whether from is an unknown sender: not the
// agent itself and not in contacts. First-contact messages carry the
// machine-readable "first_contact" flag and, under contacts-only
// dm_policy, are held as message requests instead of delivered.
func (c *Config) IsFirstContact(from string) bool {
	if from == c.Address {
		return false
	}
	return !c.contactAddressSet()[from]
}

// Block adds address to the blocklist in memory; callers persist the
// change with Config.Update. It is not an error if already present.
func (c *Config) Block(address string) error {
	if _, err := crypto.ParseAddress(address); err != nil {
		return fmt.Errorf("bad address: %w", err)
	}
	if !c.IsBlocked(address) {
		c.Blocked = append(c.Blocked, address)
	}
	return nil
}

// Unblock removes address from the blocklist in memory; callers persist
// the change with Config.Update. It is not an error if absent.
func (c *Config) Unblock(address string) {
	kept := c.Blocked[:0]
	for _, b := range c.Blocked {
		if b != address {
			kept = append(kept, b)
		}
	}
	c.Blocked = kept
}

// Dismiss adds address to the dismissed-requests set in memory; callers
// persist the change with Config.Update. It is not an error if already
// present.
func (c *Config) Dismiss(address string) error {
	if _, err := crypto.ParseAddress(address); err != nil {
		return fmt.Errorf("bad address: %w", err)
	}
	if !c.IsDismissed(address) {
		c.Dismissed = append(c.Dismissed, address)
	}
	return nil
}

// Undismiss removes address from the dismissed-requests set in memory;
// callers persist the change with Config.Update. It is not an error if
// absent.
func (c *Config) Undismiss(address string) {
	kept := c.Dismissed[:0]
	for _, d := range c.Dismissed {
		if d != address {
			kept = append(kept, d)
		}
	}
	c.Dismissed = kept
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
//
// v0.6.11 (F1): a directory hit is only trusted after its Ed25519
// signature verifies against the recipient's address, and its epoch must
// not be lower than the highest previously verified epoch for that
// address. A relay that substitutes keys — or omits the signature — fails
// closed instead of silently downgrading confidentiality.
func (c *Client) recipientKey(address string) ([32]byte, error) {
	k, _, err := c.recipientKeyWithEpoch(address)
	return k, err
}

// recipientKeyWithEpoch is recipientKey plus the key-directory epoch of
// the returned key: the announcement epoch when the contact published a
// key, or 0 when the key is address-derived because they never published
// (deterministic, so both sides of a safety-number computation agree).
// Needed by contact verification (issue #48), which pins the epoch the
// safety number was computed over.
func (c *Client) recipientKeyWithEpoch(address string) ([32]byte, int64, error) {
	var out [32]byte
	hc, err := c.httpClient()
	if err != nil {
		return out, 0, err
	}
	resp, err := hc.Get(c.cfg.RelayURL + "/v1/keys/" + url.PathEscape(address))
	if err != nil {
		return out, 0, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode == http.StatusNotFound {
		toEd, err := crypto.ParseAddress(address)
		if err != nil {
			return out, 0, err
		}
		k, err := crypto.Ed25519PubToX25519(toEd[:])
		return k, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, 0, relayErr(data)
	}
	var ann struct {
		X25519Pub string `json:"x25519_pub"`
		Epoch     int64  `json:"epoch"`
		Sig       string `json:"sig"`
	}
	if err := json.Unmarshal(data, &ann); err != nil {
		return out, 0, fmt.Errorf("bad relay response: %w", err)
	}
	k, err := c.verifyKeyAnnouncement(address, ann.X25519Pub, ann.Epoch, ann.Sig)
	return k, ann.Epoch, err
}

// verifyKeyAnnouncement authenticates one key-directory announcement and
// returns the X25519 key to seal for. It records the highest verified
// epoch per recipient so rollbacks are rejected.
func (c *Client) verifyKeyAnnouncement(address, x25519Pub string, epoch int64, sig string) ([32]byte, error) {
	var out [32]byte
	toEd, err := crypto.ParseAddress(address)
	if err != nil {
		return out, fmt.Errorf("bad address: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(x25519Pub)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("bad relay response: invalid x25519_pub")
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(sigRaw) != 64 {
		return out, fmt.Errorf("bad relay response: key announcement is not signed (refusing to encrypt to an unauthenticated key)")
	}
	canon := envelope.KeyAnnounce(toEd[:], raw, epoch)
	if !crypto.Verify(toEd[:], canon, sigRaw) {
		return out, fmt.Errorf("key announcement signature verification failed for %s: refusing to encrypt", address)
	}
	if epoch <= 0 {
		return out, fmt.Errorf("bad relay response: invalid announcement epoch")
	}
	if max, ok := c.cfg.VerifiedKeyEpochs[address]; ok && epoch < max {
		return out, fmt.Errorf("key announcement epoch %d is older than the verified epoch %d for %s: possible rollback, refusing to encrypt", epoch, max, address)
	}
	if c.cfg.VerifiedKeyEpochs == nil {
		c.cfg.VerifiedKeyEpochs = map[string]int64{}
	}
	if epoch > c.cfg.VerifiedKeyEpochs[address] {
		// Best effort: a lost epoch record only weakens rollback
		// detection, never confidentiality of this send. Update
		// reloads fresh state so a concurrent rotation's keys are not
		// clobbered (v0.6.11 F5).
		_ = c.cfg.Update(func(fresh *Config) error {
			if fresh.VerifiedKeyEpochs == nil {
				fresh.VerifiedKeyEpochs = map[string]int64{}
			}
			if epoch > fresh.VerifiedKeyEpochs[address] {
				fresh.VerifiedKeyEpochs[address] = epoch
			}
			return nil
		})
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
	return c.SendWithAttachments(toOrName, body, nil)
}

// SendReply encrypts and signs body for the agent at toOrName as a reply
// to the parent message replyTo (a relay envelope id, as shown by
// `courier inbox`). The parent snippet is resolved best-effort from the
// local sent log and reply cache and embedded in the message so the
// recipient can render the quote even without a local copy; when the
// parent is unknown locally the reply still sends, referencing the id.
// Returns the relay message id.
func (c *Client) SendReply(toOrName, body string, replyTo int64) (int64, error) {
	return c.SendReplyWithAttachments(toOrName, body, nil, replyTo)
}

// SendReplyWithAttachments is SendWithAttachments as a reply to the
// parent message replyTo. See SendReply.
func (c *Client) SendReplyWithAttachments(toOrName, body string, attachPaths []string, replyTo int64) (int64, error) {
	if replyTo < 0 {
		return 0, fmt.Errorf("invalid reply-to id %d: want a positive message id", replyTo)
	}
	var quote string
	if replyTo > 0 {
		quote, _ = LookupReplyParent(replyTo)
	}
	return c.send(toOrName, body, attachPaths, replyTo, quote, true)
}

// SendWithAttachments encrypts body for the agent at toOrName and
// attaches the files at attachPaths. Each file is encrypted under a fresh
// random data key, chunked, and uploaded to the relay as an opaque blob
// before the message is sent; the message ciphertext carries the
// manifests (with the data keys wrapped for the recipient), so the relay
// never sees filenames, MIME types, plaintext hashes, or data keys.
// Returns the relay message id.
func (c *Client) SendWithAttachments(toOrName, body string, attachPaths []string) (int64, error) {
	return c.send(toOrName, body, attachPaths, 0, "", true)
}

// sendProtocolDM sends a machine-protocol DM (channel handshake traffic)
// without recording it in the sent log: protocol DMs are not chat and
// must not be pushed to the dashboard as sent messages.
func (c *Client) sendProtocolDM(toOrName, body string) (int64, error) {
	return c.send(toOrName, body, nil, 0, "", false)
}

func (c *Client) send(toOrName, body string, attachPaths []string, replyTo int64, quote string, logSent bool) (int64, error) {
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
	// Forward-secrecy sessions (issue #50): when an FS session is
	// established with the peer, the message body is wrapped in an FS
	// frame and attachment data keys are wrapped with the FS
	// message-derived wrap key. The FS init handshake is best-effort:
	// it is attempted opportunistically, and this message goes legacy
	// until the peer accepts.
	//
	// FS applies only to human sends (logSent=true). Machine protocol
	// traffic (group/channel/shared-state DMs, logSent=false) stays on
	// legacy encryption by design, so protocol payloads never enter an
	// FS session's ratchet.
	var fsOut *fsSendOutput
	if logSent {
		var err error
		fsOut, err = c.fsPrepareSend(address)
		if err != nil {
			return 0, fmt.Errorf("fs prepare: %w", err)
		}
	}
	// If we fail after deriving FS keys but before sealing, erase them.
	defer func() {
		if fsOut != nil {
			fsOut.erase()
			fsOut = nil
		}
	}()
	var manifests []envelope.AttachmentManifest
	for _, p := range attachPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return 0, fmt.Errorf("attach %s: %w", p, err)
		}
		var m envelope.AttachmentManifest
		var blob []byte
		if fsOut != nil {
			m, blob, err = EncryptAttachmentFS(data, p, fsOut.WrapKey, address)
		} else {
			m, blob, err = EncryptAttachment(data, p, toX, address)
		}
		if err != nil {
			return 0, fmt.Errorf("attach %s: %w", p, err)
		}
		if err := c.uploadBlob(address, toEd, m.BlobID, blob); err != nil {
			return 0, fmt.Errorf("attach %s: %w", p, err)
		}
		manifests = append(manifests, m)
	}
	var plain []byte
	plain, err = encodeMessageBody(body, manifests, replyTo, quote)
	if err != nil {
		return 0, fmt.Errorf("encode payload: %w", err)
	}
	if fsOut != nil {
		plain, err = fsSealMessage(fsOut, plain)
		if err != nil {
			return 0, fmt.Errorf("fs seal: %w", err)
		}
		// Sealed: the message key and wrap key have been consumed;
		// fsSealMessage erases them, so disarm the deferred erase.
		fsOut = nil
	}
	return c.sendSealed(address, plain, body, replyTo, quote, logSent)
}

// sendSealed encrypts plain for address and posts it as a DM. sentLogBody
// is the human-readable summary recorded in the local sent log (and shown
// on the dashboard); it may differ from the plaintext, e.g. for protocol
// payloads like shared-state events (issue #49). replyTo/quote thread
// the sent log for human replies (issue #51). logSent=false skips the
// sent log for machine protocol DMs (channel handshakes).
func (c *Client) sendSealed(address string, plain []byte, sentLogBody string, replyTo int64, quote string, logSent bool) (int64, error) {
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
	eph, nonce, ct, err := crypto.Seal(&toX, plain)
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
	// Best-effort local record so the dashboard can thread the
	// conversation. A logging failure must never fail the send itself.
	// Protocol DMs skip the log: they are machine traffic, not chat.
	if logSent {
		_ = appendSentLog(SentEntry{CourierID: out.ID, To: address, Body: sentLogBody, SentAt: sentAt, ReplyTo: replyTo, Quote: quote})
	}
	return out.ID, nil
}

// uploadBlob stores one encrypted attachment blob on the relay. The
// request is signed by the uploader over the recipient, the random blob
// id, the exact byte size, and a timestamp, so the relay can attribute
// stored blobs and reject replays.
func (c *Client) uploadBlob(toAddr string, toEd [32]byte, blobID string, blob []byte) error {
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	blobIDRaw, err := base64.RawURLEncoding.DecodeString(blobID)
	if err != nil {
		return fmt.Errorf("bad blob id: %w", err)
	}
	ts := time.Now().Unix()
	sig := id.Sign(envelope.BlobUpload(id.EdPub[:], toEd[:], blobIDRaw, int64(len(blob)), ts))
	q := url.Values{}
	q.Set("from", c.cfg.Address)
	q.Set("to", toAddr)
	q.Set("blob_id", blobID)
	q.Set("size", fmt.Sprintf("%d", len(blob)))
	q.Set("ts", fmt.Sprintf("%d", ts))
	q.Set("sig", base64.RawURLEncoding.EncodeToString(sig))
	hc, err := c.httpClient()
	if err != nil {
		return err
	}
	resp, err := hc.Post(c.cfg.RelayURL+"/v1/blobs?"+q.Encode(), "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		return fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusCreated {
		return relayErr(data)
	}
	return nil
}

// downloadBlob fetches one attachment blob's ciphertext. The request is
// signed by the recipient (this agent) over the blob id with a fresh
// timestamp, mirroring inbox reads — only the address the blob was
// uploaded for can fetch it.
func (c *Client) downloadBlob(blobID string) ([]byte, error) {
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, err
	}
	toEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("bad address: %w", err)
	}
	blobIDRaw, err := base64.RawURLEncoding.DecodeString(blobID)
	if err != nil || len(blobIDRaw) != 32 {
		return nil, fmt.Errorf("bad blob id")
	}
	ts := time.Now().Unix()
	sig := id.Sign(envelope.BlobRequest(toEd[:], blobIDRaw, ts))
	u := fmt.Sprintf("%s/v1/blobs/%s?ts=%d&sig=%s",
		c.cfg.RelayURL, blobID, ts, base64.RawURLEncoding.EncodeToString(sig))
	hc, err := c.httpClient()
	if err != nil {
		return nil, err
	}
	resp, err := hc.Get(u)
	if err != nil {
		return nil, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, envelope.MaxBlobBytes+1))
	if resp.StatusCode != http.StatusOK {
		return nil, relayErr(data)
	}
	return data, nil
}

// DownloadAttachment fetches and verifies one attachment from a received
// message: it downloads the blob as the recipient, re-authenticates every
// chunk, and checks the reassembled size and SHA256 against the manifest.
// It fails closed — tampered, truncated, or missing data is an error,
// never a file.
func (c *Client) DownloadAttachment(a IncomingAttachment) ([]byte, error) {
	if a.KeyError != nil {
		return nil, fmt.Errorf("no usable data key: %w", a.KeyError)
	}
	blob, err := c.downloadBlob(a.Manifest.BlobID)
	if err != nil {
		return nil, err
	}
	return DecryptAttachment(blob, a.Manifest, a.DataKey)
}

// SentEntry is one locally recorded outbound message: the plaintext the
// agent sent, kept so `courier dashboard push` can thread conversations.
// It lives next to config.json (mode 0600 material already lives there).
type SentEntry struct {
	CourierID int64  `json:"courier_id"` // relay envelope id
	To        string `json:"to"`
	Body      string `json:"body"`
	SentAt    int64  `json:"sent_at"`
	// ReplyTo/Quote thread the sent log (issue #51): the parent
	// envelope id this message replied to and the parent snippet
	// embedded at send time. Replies are human chat, so they are
	// logged like any send (unlike machine protocol DMs).
	ReplyTo int64  `json:"reply_to,omitempty"`
	Quote   string `json:"quote,omitempty"`
}

// maxSentLog is the cap on the local sent log; older entries are dropped.
const maxSentLog = 1000

func sentLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "sent.jsonl"), nil
}

// readSentLog returns all logged sent entries, oldest first.
func readSentLog() ([]SentEntry, error) {
	p, err := sentLogPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []SentEntry
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var e SentEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// appendSentLog records a sent message, pruning the log to maxSentLog.
func appendSentLog(e SentEntry) error {
	p, err := sentLogPath()
	if err != nil {
		return err
	}
	entries, err := readSentLog()
	if err != nil {
		return err
	}
	entries = append(entries, e)
	if len(entries) > maxSentLog {
		entries = entries[len(entries)-maxSentLog:]
	}
	var buf bytes.Buffer
	for _, en := range entries {
		line, _ := json.Marshal(en)
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, buf.Bytes(), 0o600)
}

// Message is one decrypted, signature-verified inbox message.
type Message struct {
	ID          int64
	From        string // authenticated sender address
	Body        string
	SentAt      int64
	ReceivedAt  int64
	Attachments []IncomingAttachment // verified manifests (data keys unwrapped when possible)
	// ReplyTo is the relay envelope id of the parent message this
	// message replies to (issue #51); 0 when not a reply.
	ReplyTo int64 `json:"reply_to,omitempty"`
	// ReplyQuote is the best-effort parent snippet for display:
	// resolved locally when possible, else the sender's embedded
	// quote, else "" (rendered as a bare "in reply to #id").
	ReplyQuote string `json:"reply_quote,omitempty"`
	// Flags carries the machine-readable reasons a message was
	// flagged for review. Client-derived: "first_contact" (sender not
	// in contacts and not self), "quarantined_by_policy" (held by the
	// recipient's contacts-only dm_policy). Relay-attached (advisory,
	// metadata-only): "rate_limited" (sender's send bucket currently
	// exhausted), "reported" (sender currently over the
	// distinct-reporter throttle threshold).
	Flags []string `json:"flags,omitempty"`
	// Request marks a message held for review instead of delivered:
	// it appears in the dedicated message-requests section (`courier
	// inbox`, `courier request list`), never in the normal inbox and
	// never pushed to the dashboard. Held, never silently dropped.
	Request bool `json:"request,omitempty"`
}

// Inbox fetches envelopes addressed to this agent after message id `after`,
// verifies each sender signature, and decrypts. Envelopes that fail
// verification or decryption are skipped and counted, never fatal.
//
// It returns the decrypted messages, the highest envelope id inspected
// in this page (lastID), and the skip count. lastID advances past every
// inspected envelope — including undecryptable or replayed ones — so
// callers must persist it as their cursor: a page of only undecryptable
// messages must not wedge pagination (v0.6.11 F4). lastID is at least
// `after`.
// Inbox fetches and decrypts messages after the given id. See inbox for
// the lastID contract. Delivered envelopes are marked seen so they are
// never delivered twice (v0.6.11 F3).
func (c *Client) Inbox(after int64, limit int) ([]Message, int64, int, int, error) {
	msgs, lastID, skipped, filtered, _, _, err := c.inbox(after, limit, true, seenConsumerInbox)
	return msgs, lastID, skipped, filtered, err
}

// inbox is Inbox with control over replay bookkeeping and consumer
// selection. Push consumers (dashboard push) pass markSeen=false and
// record hashes themselves, but only for batches the server
// acknowledges — so a failed batch's messages stay re-fetchable on
// retry instead of being suppressed as replays while the cursor
// advances past them (v0.6.11 F11). It returns the dedup hashes of the
// delivered messages for that bookkeeping, plus the shared-state
// events newly applied to the local log during this fetch (issue #49)
// with their envelope metadata — the dashboard push announces those;
// other consumers ignore them.
//
// The consumer selects which replay-suppression set is used (issue
// #45): inbox delivery and dashboard pushing are independent
// consumers, and each suppresses only envelopes it has itself
// delivered. A shared set let the two consume each other's messages.
//
// skipped counts envelopes that failed authentication or decryption
// (corrupt/forged); filtered counts messages intentionally filtered by
// the recipient's own rules (blocked or dismissed senders). Suppressed
// replays are counted in neither: identical envelope bytes are routine
// dedup, never an attack, and the "no new messages." sentinel contract
// depends on them staying silent. The three are reported separately so
// routine delivery mechanics never look like an attack.
func (c *Client) inbox(after int64, limit int, markSeen bool, consumer seenConsumer) ([]Message, int64, int, int, []string, []appliedStateEvent, error) {
	hc, err := c.httpClient()
	if err != nil {
		return nil, after, 0, 0, nil, nil, err
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return nil, after, 0, 0, nil, nil, err
	}
	toEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return nil, after, 0, 0, nil, nil, fmt.Errorf("bad address: %w", err)
	}
	// v0.6.11 (F10): the inbox request is signed by the recipient, so
	// the relay serves ciphertext only to the address owner. after and
	// limit are covered by the signature to prevent cursor tampering.
	ts := time.Now().Unix()
	sig := id.Sign(envelope.InboxRequest(toEd[:], after, int64(limit), ts))
	url := fmt.Sprintf("%s/v1/inbox?to=%s&after=%d&limit=%d&ts=%d&sig=%s",
		c.cfg.RelayURL, c.cfg.Address, after, limit, ts,
		base64.RawURLEncoding.EncodeToString(sig))
	resp, err := hc.Get(url)
	if err != nil {
		return nil, after, 0, 0, nil, nil, fmt.Errorf("relay unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, after, 0, 0, nil, nil, relayErr(data)
	}
	var in struct {
		Messages []struct {
			ID          int64    `json:"id"`
			From        string   `json:"from"`
			Eph         string   `json:"eph"`
			Nonce       string   `json:"nonce"`
			Ct          string   `json:"ct"`
			SentAt      int64    `json:"sent_at"`
			ReceivedAt  int64    `json:"received_at"`
			Sig         string   `json:"sig"`
			SenderFlags []string `json:"sender_flags"`
			Kind        string   `json:"kind"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, after, 0, 0, nil, nil, fmt.Errorf("bad relay response: %w", err)
	}
	var out []Message
	skipped := 0
	filtered := 0
	lastID := after
	var newHashes []string
	// issue #49: shared-state events newly applied during this fetch,
	// with envelope metadata for the dashboard push announcements.
	var stateApplied []appliedStateEvent
	// issue #51: reply-cache entries for this fetch's deliveries,
	// flushed once after the loop.
	var cacheEntries []replyCacheEntry
	seen := c.seenSet(consumer)
	for _, m := range in.Messages {
		// Track the highest inspected envelope id regardless of
		// outcome: the cursor must advance past undecryptable and
		// replayed messages too (v0.6.11 F4).
		if m.ID > lastID {
			lastID = m.ID
		}
		// issue #32: skip envelope kinds this client does not
		// understand (sent by newer clients) without stalling the
		// cursor.
		if m.Kind != "" && m.Kind != "dm" {
			skipped++
			continue
		}
		// v0.6.11 (F3): suppress replays independently of relay message
		// ids — identical envelope bytes are never delivered twice to
		// the same consumer. Replays are routine dedup, not failures
		// (v0.9.1): they stay silent so the "no new messages." sentinel
		// contract that poll-based wake scripts rely on holds.
		// Suppression is per consumer (issue #45, v0.9.2): a message
		// the dashboard pusher already pushed is still new to the
		// inbox poller, and vice versa.
		h := envelope.DedupHash(c.cfg.Address, m.From, m.Eph, m.Nonce, m.SentAt, m.Ct, m.Sig)
		if seen[h] {
			continue
		}
		fromEd, err := crypto.ParseAddress(m.From)
		if err != nil {
			skipped++
			continue
		}
		// Blocklist and dismissed requests: messages from these senders
		// are dropped at read time, before any decryption work. The
		// cursor still advances past them (F4) and they are never marked
		// seen, so unblocking/undismissing later plus `inbox --all`
		// recovers them. Counted as filtered (the recipient's own
		// choice), not as skipped (corrupt/forged).
		if c.cfg.IsBlocked(m.From) || c.cfg.IsDismissed(m.From) {
			filtered++
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

		// issue #50: forward-secrecy frames are consumed by the FS
		// layer and never surface as chat messages. Handshake frames
		// (init/accept) are answered silently; message frames are
		// decrypted into the inner plaintext, which is then dispatched
		// exactly like a legacy DM below. Frames that fail decryption
		// count as skipped (genuine failures), matching the existing
		// docstring.
		var fsWrapKey *[32]byte
		if fp, ok := parseFSPayload(plain); ok {
			switch fp.Type {
			case fsTypeInit, fsTypeAccept:
				c.handleFSHandshake(m.From, fp)
				seen[h] = true
				newHashes = append(newHashes, h)
				continue
			case fsTypeMsg:
				inner, wk, ferr := c.fsDecryptMessage(m.From, fp)
				if ferr != nil {
					skipped++
					continue
				}
				plain = inner
				fsWrapKey = wk // attachment data-key unwrap, below
			}
		}

		// issue #32: group protocol direct messages (sender-key
		// distributions and group invitations) are consumed by the
		// group layer and never surface as chat messages.
		if gp, ok := parseGroupDMPayload(plain); ok {
			c.handleGroupDM(m.From, gp)
			seen[h] = true
			newHashes = append(newHashes, h)
			continue
		}
		// issue #48: channel protocol direct messages (join requests
		// and accepts, channel messages, rekeys, leaves) are consumed
		// by the channel layer and never surface as chat messages.
		if cp, ok := parseChannelDMPayload(plain); ok {
			c.handleChannelDM(m.From, cp)
			seen[h] = true
			newHashes = append(newHashes, h)
			continue
		}
		// issue #52: receipt protocol direct messages are consumed by
		// the receipt layer and never surface as chat messages.
		if rp, ok := parseReceiptDMPayload(plain); ok {
			c.handleReceiptDM(m.From, rp)
			seen[h] = true
			newHashes = append(newHashes, h)
			continue
		}
		// issue #39: introduction protocol DMs are consumed by the
		// introduction layer and never surface as chat messages (same
		// as group-control DMs, issue #32). Valid payloads are recorded
		// as pending introductions, listed via
		// `courier directory introductions`. Payloads that fail
		// validation (bad signature, unknown parties) fall through as
		// ordinary messages — never silently swallowed.
		if ip, ok := parseIntroductionPayload(plain); ok {
			if _, rec := c.recordIntroduction(m.From, m.ID, ip); rec {
				seen[h] = true
				newHashes = append(newHashes, h)
				continue
			}
		}
		// issue #49: shared-agent-state payloads are consumed by the
		// state layer and never surface as chat messages (same as
		// group-control DMs, issue #32). Events are appended to the
		// per-peer log; application is idempotent, so every consumer
		// (inbox, dashboard push, state sync) applies them on its own
		// pass. A sender held for review does not get events applied:
		// the payload falls through as an ordinary message instead, so
		// a quarantined stranger cannot write into the shared log.
		if sp, ok := parseStatePayload(plain); ok {
			if c.cfg.HoldForReview(m.From) || slices.Contains(m.SenderFlags, "reported") {
				// fall through to normal delivery below
			} else {
				applied, aerr := c.applyStateEvents(m.From, m.From, sp.Events)
				_ = aerr // best effort: the cursor must advance regardless
				if consumer == seenConsumerPush {
					for _, ev := range applied {
						stateApplied = append(stateApplied, appliedStateEvent{
							From: m.From, EnvelopeID: m.ID,
							SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
							Hash: h, Event: ev,
						})
					}
				}
				seen[h] = true
				newHashes = append(newHashes, h)
				continue
			}
		}
		// Split a decrypted payload into its body text, attachment
		// manifests, and reply threading metadata (issue #51).
		// Manifests are validated and their data keys are
		// unwrapped with this recipient's keys; a manifest whose key
		// cannot be opened is kept with KeyError set, so the message is
		// still delivered and the failure is visible, never silent.
		body, manifests, rinfo := parseMessagePayload(plain)
		var atts []IncomingAttachment
		for _, mf := range manifests {
			ia := IncomingAttachment{Manifest: mf}
			if err := envelope.ValidateManifest(&mf); err != nil {
				ia.KeyError = fmt.Errorf("bad manifest: %w", err)
			} else {
				var wk *envelope.WrappedKey
				for i := range mf.Keys {
					if mf.Keys[i].Recipient == c.cfg.Address {
						wk = &mf.Keys[i]
						break
					}
				}
				if wk == nil {
					ia.KeyError = errors.New("no wrapped data key for this recipient")
				} else if fsWrapKey != nil {
					// issue #50: FS messages wrap attachment data
					// keys under the message-derived key.
					if dk, err := UnwrapDataKeyFS(*wk, *fsWrapKey); err == nil {
						ia.DataKey = dk
					} else {
						ia.KeyError = err
					}
				} else {
					var uerr error
					opened := false
					for _, xp := range c.cfg.encryptionPrivKeys() {
						if dk, err := UnwrapDataKey(*wk, xp); err == nil {
							ia.DataKey = dk
							opened = true
							break
						} else {
							uerr = err
						}
					}
					if !opened {
						ia.KeyError = uerr
					}
				}
			}
			atts = append(atts, ia)

		}
		// The FS wrap key exists only for this message's manifests;
		// erase it now that the data keys are extracted.
		if fsWrapKey != nil {
			crypto.Zero(fsWrapKey[:])
			fsWrapKey = nil
		}
		msg := Message{
			ID: m.ID, From: m.From, Body: body,
			SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
			Attachments: atts,
			ReplyTo:     rinfo.To, ReplyQuote: rinfo.Quote,
		}
		// issue #51: remember this delivery in the reply cache so a
		// later reply to it can quote the parent without a relay
		// round-trip. Best effort; delivery never depends on it.
		cacheEntries = append(cacheEntries, replyCacheEntry{
			CourierID: m.ID, From: m.From,
			Snippet: truncateQuote(body), SentAt: m.SentAt,
		})
		// Machine-readable flag reasons. "first_contact" is derived
		// locally (sender not in contacts and not self); the rest are
		// relay-attached sender-reputation metadata (advisory). Flags
		// ride along on delivered messages too, so agents can see at a
		// glance why a message was singled out.
		if c.cfg.IsFirstContact(m.From) {
			msg.Flags = append(msg.Flags, "first_contact")
		}
		msg.Flags = append(msg.Flags, m.SenderFlags...)
		// Hold rule: a message becomes a request (held for review,
		// never delivered to the inbox or dashboard) when the
		// recipient's contacts-only policy quarantines a first contact,
		// or when the relay reports the sender is currently throttled
		// for spam — even under the open policy. Held messages are not
		// marked seen, so review re-derives them; the empty hash keeps
		// newHashes parallel to out for DashboardPush.
		hold := c.cfg.HoldForReview(m.From) || slices.Contains(msg.Flags, "reported")
		if hold {
			msg.Request = true
			// Machine-readable reason when the hold comes from the
			// recipient's contacts-only policy (as opposed to the
			// relay's spam throttle, which arrives as a flag).
			if c.cfg.HoldForReview(m.From) {
				msg.Flags = append(msg.Flags, "quarantined_by_policy")
			}
			out = append(out, msg)
			newHashes = append(newHashes, "")
			continue
		}
		out = append(out, msg)
		// issue #52: opt-in delivery receipt. Fires only for the inbox
		// consumer on first delivery — never for dashboard pushes,
		// state syncs, or review re-derivations (markSeen=false) — and
		// only when this agent explicitly opted into receipts for the
		// sender. Held requests continue above, so they never generate
		// receipts. The receipt is a signed protocol DM excluded from
		// the sent log; best effort, never fatal to delivery.
		if consumer == seenConsumerInbox && markSeen && c.cfg.ReceiptsEnabledFor(m.From) {
			c.sendDeliveryReceipt(m.From, m.ID)
		}
		// Only successfully delivered messages are marked seen: a
		// message that fails verification or decryption now may become
		// readable later (e.g. after the sender's key announcement
		// arrives), and must not be suppressed.
		seen[h] = true
		newHashes = append(newHashes, h)
	}
	// issue #51: resolve reply quotes. A locally-known parent snippet
	// (my sent log, or an earlier delivery on this machine) is this
	// recipient's own copy of the parent bytes, so it takes precedence
	// over the sender's embedded quote; the embedded quote covers
	// parents unknown locally (other devices, aged-out logs). A parent
	// known nowhere renders as a bare "in reply to #id".
	needLocal := false
	for i := range out {
		if out[i].ReplyTo > 0 && out[i].ReplyQuote == "" {
			needLocal = true
			break
		}
	}
	if needLocal {
		// Load once per fetch, not once per reply. The current batch
		// comes first: a parent and its reply can arrive together.
		local := make(map[int64]string)
		for _, m := range out {
			if m.Body != "" {
				local[m.ID] = truncateQuote(m.Body)
			}
		}
		if sent, err := readSentLog(); err == nil {
			for _, e := range sent {
				if e.Body != "" {
					if _, ok := local[e.CourierID]; !ok {
						local[e.CourierID] = truncateQuote(e.Body)
					}
				}
			}
		}
		for _, e := range readReplyCache() {
			if e.Snippet != "" {
				if _, ok := local[e.CourierID]; !ok {
					local[e.CourierID] = e.Snippet
				}
			}
		}
		for i := range out {
			if out[i].ReplyTo > 0 && out[i].ReplyQuote == "" {
				if q, ok := local[out[i].ReplyTo]; ok {
					out[i].ReplyQuote = q
				}
			}
		}
	}
	// Best-effort reply cache write; delivery never depends on it.
	writeReplyCache(cacheEntries)
	if markSeen {
		c.recordSeen(consumer, newHashes)
	}
	return out, lastID, skipped, filtered, newHashes, stateApplied, nil
}

// InboxReview re-derives the messages currently held as requests,
// without advancing the inbox cursor or marking anything seen. Review
// is read-only: it never changes delivery state.
func (c *Client) InboxReview(limit int) ([]Message, error) {
	msgs, _, _, _, _, _, err := c.inbox(0, limit, false, seenConsumerInbox)
	if err != nil {
		return nil, err
	}
	var held []Message
	for _, m := range msgs {
		if m.Request {
			held = append(held, m)
		}
	}
	return held, nil
}

// requestContactName derives a default contact name for an accepted
// first-contact sender: "new-" plus 8 hex chars of the address hash.
// It fits the contact name rules and is made unique against existing
// contacts.
func (c *Client) requestContactName(address string) string {
	sum := sha256.Sum256([]byte(address))
	base := "new-" + hex.EncodeToString(sum[:])[:8]
	name := base
	for i := 2; ; i++ {
		if _, ok := c.cfg.Contacts[name]; !ok {
			return name
		}
		if c.cfg.Contacts[name] == address {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}

// AcceptRequest accepts the held message request id: the request's
// messages from that sender are returned for immediate delivery, and
// when the request is a first contact the sender is added to contacts
// (under --as name, or an auto-generated one), so future messages
// arrive normally. Accepting never drops anything: the held messages
// are handed back, not discarded.
func (c *Client) AcceptRequest(id int64, asName string) ([]Message, error) {
	held, err := c.InboxReview(200)
	if err != nil {
		return nil, err
	}
	var req *Message
	for i, m := range held {
		if m.ID == id {
			req = &held[i]
			break
		}
	}
	if req == nil {
		return nil, fmt.Errorf("no message request with id %d (see `courier request list`)", id)
	}
	sender := req.From
	if slices.Contains(req.Flags, "first_contact") && senderAddr(c.cfg, sender) == "" {
		name := asName
		if name == "" {
			name = c.requestContactName(sender)
		} else if !contactNameRe.MatchString(name) {
			return nil, fmt.Errorf("bad contact name %q: use 1-32 chars, lowercase letters, digits, - and _, starting with a letter or digit", asName)
		}
		// Never clobber an existing contact name that points at a
		// different address; fall back to a generated name instead.
		if addr, ok := c.cfg.Contacts[name]; ok && addr != sender {
			name = c.requestContactName(sender)
		}
		if err := c.cfg.AddContact(name, sender); err != nil {
			return nil, err
		}
	}
	var released []Message
	for _, m := range held {
		if m.From == sender {
			m.Request = false // released: no longer held
			released = append(released, m)
		}
	}
	return released, nil
}

// DismissRequest dismisses the held message request id: the sender is
// added to the dismissed set, so their messages no longer surface as
// requests. Dismissed messages are dropped at read time like blocked
// ones — visibly counted, never mixed into the inbox — and the
// dismissal is reversible with `courier request undismiss`.
func (c *Client) DismissRequest(id int64) (string, error) {
	held, err := c.InboxReview(200)
	if err != nil {
		return "", err
	}
	for _, m := range held {
		if m.ID == id {
			if err := c.cfg.Update(func(fresh *Config) error {
				return fresh.Dismiss(m.From)
			}); err != nil {
				return "", err
			}
			return m.From, nil
		}
	}
	return "", fmt.Errorf("no message request with id %d (see `courier request list`)", id)
}

// senderAddr is a tiny helper to check contact membership by address.
func senderAddr(cfg *Config, addr string) string {
	for name, a := range cfg.Contacts {
		if a == addr {
			return name
		}
	}
	return ""
}

// ReportSpam files a spam report against envelopeID with the relay.
// The reporter proves it is the message's recipient by signing a
// canonical spam-report payload (envelope.SpamReport); the relay
// verifies the signature, requires the reporter to be the envelope's
// recipient, and derives the reported sender from the stored envelope.
// Reports are idempotent per (sender, reporter): only distinct
// reporters count toward the relay's throttle threshold.
func (c *Client) ReportSpam(envelopeID int64) error {
	if envelopeID <= 0 {
		return fmt.Errorf("bad message id %d", envelopeID)
	}
	id, err := c.cfg.Identity()
	if err != nil {
		return err
	}
	reporterEd, err := crypto.ParseAddress(c.cfg.Address)
	if err != nil {
		return err
	}
	ts := time.Now().Unix()
	sig := id.Sign(envelope.SpamReport(reporterEd[:], envelopeID, ts))
	data, code, err := c.post("/v1/report", map[string]any{
		"reporter":    c.cfg.Address,
		"envelope_id": envelopeID,
		"ts":          ts,
		"sig":         base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return relayErr(data)
	}
	return nil
}

// maxSeenEnvelopeHashes bounds the client-side replay-suppression set.
// The relay dedups permanently; this is defense-in-depth against a rogue
// relay, so a bounded window is sufficient.
const maxSeenEnvelopeHashes = 1000

// seenSet returns one consumer's delivered-envelope hashes as a set.
// Replay suppression is per consumer (issue #45): the inbox poller and
// the dashboard pusher each suppress only envelopes they themselves
// delivered, so neither can consume the other's messages.
func (c *Client) seenSet(which seenConsumer) map[string]bool {
	var stored []string
	switch which {
	case seenConsumerPush:
		stored = c.cfg.SeenPushHashes
	case seenConsumerState:
		stored = c.cfg.SeenStateHashes
	default:
		stored = c.cfg.SeenInboxHashes
	}
	seen := make(map[string]bool, len(stored))
	for _, h := range stored {
		seen[h] = true
	}
	return seen
}

// recordSeen persists newly delivered envelope hashes for one
// consumer, dropping the oldest beyond the bound.
func (c *Client) recordSeen(which seenConsumer, hashes []string) {
	if len(hashes) == 0 {
		return
	}
	// Best effort: losing the set only weakens replay suppression,
	// never message delivery. Update reloads fresh state so hashes
	// recorded by a concurrent process are merged, not clobbered
	// (v0.6.11 F5).
	_ = c.cfg.Update(func(fresh *Config) error {
		switch which {
		case seenConsumerPush:
			fresh.SeenPushHashes = unionSeen(fresh.SeenPushHashes, hashes)
		case seenConsumerState:
			fresh.SeenStateHashes = unionSeen(fresh.SeenStateHashes, hashes)
		default:
			fresh.SeenInboxHashes = unionSeen(fresh.SeenInboxHashes, hashes)
		}
		return nil
	})
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

// AutoUpdateEnabled reports whether the client should automatically install
// a newer release when one is found. Since v0.6.12 auto-install is the
// default — a stale client cannot read from an upgraded relay, so staying
// current is a correctness requirement, not a convenience. Setting
// auto_update=false opts back out to a manual notice.
func (c *Config) AutoUpdateEnabled() bool {
	return c.AutoUpdate == nil || *c.AutoUpdate
}

// updateCheckInterval bounds how often the client phones home to the
// GitHub releases API: at most once per 12 hours.
const updateCheckInterval = 12 * 3600

// MaybeUpdateCheck looks for a newer Courier release (at most once per 12
// hours). If one exists it auto-installs it unless the operator opted out
// (auto_update=false), in which case it prints a notice to stderr instead.
// Network failures are silent: an unreachable update server must never
// break messaging.
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
	if c.cfg.AutoUpdateEnabled() {
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
//
// expectedFingerprint, when non-empty, is the dashboard certificate
// fingerprint the setup must see (fail closed on mismatch). When empty,
// the setup requires the dashboard certificate to match the already
// pinned relay fingerprint whenever the dashboard shares the relay's
// host (the documented deployment shares the relay's certificate);
// otherwise it falls back to TOFU, printing the fingerprint for the
// user to verify.
func (c *Client) DashboardSetup(username, expectedFingerprint string) (tempPassword string, err error) {
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

	// Pin the dashboard certificate. v0.6.11 (F2): authenticate it
	// instead of trusting the first certificate seen. An explicitly
	// provided fingerprint always wins; otherwise, when the dashboard
	// shares the relay's host (the documented deployment shares the
	// relay's certificate), the fetched fingerprint must equal the
	// already-pinned relay fingerprint. Anything else is TOFU with the
	// fingerprint printed for human verification.
	fp, err := FetchRelayFingerprint(c.cfg.DashboardURL)
	if err != nil {
		return "", fmt.Errorf("dashboard unreachable: %w", err)
	}
	want := c.expectedDashboardFingerprint(expectedFingerprint)
	fmt.Fprintf(os.Stderr, "dashboard certificate SHA256: %s\n", fp)
	if want != "" && !strings.EqualFold(fp, want) {
		return "", fmt.Errorf("dashboard certificate mismatch: got SHA256 %s, want %s; refusing to register (possible MITM or rotated certificate — verify and re-run with --fingerprint)", fp, want)
	}

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

// expectedDashboardFingerprint returns the dashboard certificate
// fingerprint the setup must see, or "" to fall back to TOFU. An
// explicitly provided fingerprint always wins; otherwise the pinned relay
// fingerprint applies when the dashboard shares the relay's host (the
// documented deployment shares the relay's certificate).
func (c *Client) expectedDashboardFingerprint(expected string) string {
	if expected != "" {
		return expected
	}
	if c.cfg.RelayFingerprint != "" && sameURLHost(c.cfg.DashboardURL, c.cfg.RelayURL) {
		return c.cfg.RelayFingerprint
	}
	return ""
}

// sameURLHost reports whether two URLs share a hostname (ignoring port).
func sameURLHost(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Hostname(), ub.Hostname())
}

// pushMsg is one decrypted message forwarded to the dashboard. To is set
// for outbound messages the agent sent; it is empty for inbox messages.
// ReplyTo/Quote carry reply threading metadata (issue #51) for the
// dashboard's quote rendering; the dashboard never decrypts.
type pushMsg struct {
	CourierID  int64  `json:"courier_id"`
	From       string `json:"from"`
	To         string `json:"to,omitempty"`
	Body       string `json:"body"`
	SentAt     int64  `json:"sent_at"`
	ReceivedAt int64  `json:"received_at"`
	ReplyTo    int64  `json:"reply_to,omitempty"`
	Quote      string `json:"quote,omitempty"`
}

// Bounds for a single dashboard push request (v0.6.11 F11). The
// dashboard rejects batches over 200 messages; the byte bound keeps
// each request far under the dashboard's 4 MiB body limit and keeps
// memory use predictable on the push side.
const (
	maxPushBatchMessages = 200
	maxPushBatchBytes    = 256 << 10 // 256 KiB of encoded JSON
)

// pushItem is one message queued for the dashboard; sent marks entries
// from the local sent log (advancing DashboardSentCursor) as opposed to
// inbox messages (advancing DashboardCursor). hash is the envelope dedup
// hash for inbox messages, recorded as seen only once the batch carrying
// it is acknowledged (v0.6.11 F11).
type pushItem struct {
	msg  pushMsg
	sent bool
	hash string
}

// splitPushBatches partitions queued messages into batches bounded by
// both message count and encoded JSON size, preserving order. A single
// message larger than the byte bound still forms its own batch so
// progress is always made.
func splitPushBatches(items []pushItem) [][]pushItem {
	var batches [][]pushItem
	var cur []pushItem
	curBytes := 0
	flush := func() {
		if len(cur) > 0 {
			batches = append(batches, cur)
			cur = nil
			curBytes = 0
		}
	}
	for _, it := range items {
		raw, _ := json.Marshal(it.msg)
		n := len(raw) + 1 // +1 for the array separator
		if len(cur) >= maxPushBatchMessages ||
			(len(cur) > 0 && curBytes+n > maxPushBatchBytes) {
			flush()
		}
		cur = append(cur, it)
		curBytes += n
	}
	flush()
	return batches
}

// DashboardPush decrypts new inbox messages and pushes them to the
// dashboard for the user to read, along with newly sent messages so the
// dashboard can thread each conversation.
//
// v0.6.11 (F11): messages go out in batches bounded by both count (200)
// and encoded size (256 KiB). Cursors and replay bookkeeping advance
// only through batches the dashboard acknowledges, so a failed batch is
// retried on the next run instead of wedging or re-pushing the backlog.
func (c *Client) DashboardPush() (pushed int, err error) {
	hc, err := c.dashboardHTTPClient()
	if err != nil {
		return 0, err
	}
	// Fetch without marking seen (v0.6.11 F11): envelopes are recorded
	// as seen only inside acknowledged push batches below, so a failed
	// batch's messages are re-fetched on retry instead of being
	// suppressed as replays while the cursor advances past them.
	// The push consumer uses its own replay set (issue #45): envelopes
	// the inbox poller already delivered are still new to the pusher.
	msgs, lastID, _, _, hashes, stateEvents, err := c.inbox(c.cfg.DashboardCursor, 200, false, seenConsumerPush)
	if err != nil {
		return 0, err
	}
	var items []pushItem
	for i, m := range msgs {
		if m.Request {
			continue // held for review; never pushed to the dashboard
		}
		items = append(items, pushItem{hash: hashes[i], msg: pushMsg{
			CourierID: m.ID, From: m.From, Body: m.Body,
			SentAt: m.SentAt, ReceivedAt: m.ReceivedAt,
			ReplyTo: m.ReplyTo, Quote: m.ReplyQuote,
		}})
	}
	// issue #49: newly applied shared-state events are announced to
	// the dashboard as human-readable summaries, so the user sees
	// their agent's notes and tasks. The envelope hash rides along so
	// the push consumer's replay bookkeeping covers the state message
	// exactly like a chat message.
	for _, a := range stateEvents {
		items = append(items, pushItem{hash: a.Hash, msg: pushMsg{
			CourierID: a.EnvelopeID, From: a.From,
			Body:   stateSummary(a.From, a.Event),
			SentAt: a.SentAt, ReceivedAt: a.ReceivedAt,
		}})
	}
	// Outbound messages, oldest first, from the local sent log.
	if sent, err := readSentLog(); err == nil {
		for _, e := range sent {
			if e.CourierID <= c.cfg.DashboardSentCursor {
				continue
			}
			items = append(items, pushItem{sent: true, msg: pushMsg{
				CourierID: e.CourierID, From: c.cfg.Address, To: e.To,
				Body: e.Body, SentAt: e.SentAt, ReceivedAt: e.SentAt,
				ReplyTo: e.ReplyTo, Quote: e.Quote,
			}})
		}
	}
	// Push in bounded batches (v0.6.11 F11): the dashboard rejects
	// oversized requests, so each batch is capped by both message count
	// and encoded byte size. Cursors advance only through batches the
	// server acknowledges — never all-or-nothing — so a failed batch is
	// retried next run instead of re-pushing (or forever retrying) the
	// whole backlog.
	for _, batch := range splitPushBatches(items) {
		n, inboxMax, sentMax, err := c.pushBatch(hc, batch)
		if err != nil {
			return pushed, err
		}
		pushed += n
		// Envelopes are marked seen only now that the dashboard has
		// them: a failed batch stays re-fetchable, and replay
		// suppression still works across ticks (v0.6.11 F3). The push
		// consumer's own set (issue #45) — inbox delivery is tracked
		// separately and must not suppress a push.
		var hashes []string
		for _, it := range batch {
			if !it.sent && it.hash != "" {
				hashes = append(hashes, it.hash)
			}
		}
		c.recordSeen(seenConsumerPush, hashes)
		_ = c.cfg.Update(func(fresh *Config) error {
			if inboxMax > fresh.DashboardCursor {
				fresh.DashboardCursor = inboxMax
			}
			if sentMax > fresh.DashboardSentCursor {
				fresh.DashboardSentCursor = sentMax
			}
			return nil
		})
	}
	// Advance past every message attempted — including undecryptable
	// ones, so a poisoned page never wedges the push cursor (v0.6.11
	// F4). Inbox order is ascending by id, so lastID is monotonic.
	// Read-modify-write via Update: a long-running --follow loop must
	// not clobber fields (e.g. rotated encryption keys) another process
	// wrote since this config was loaded (v0.6.11 F5). Cursors only move
	// forward, so taking the max is safe.
	_ = c.cfg.Update(func(fresh *Config) error {
		if lastID > fresh.DashboardCursor {
			fresh.DashboardCursor = lastID
		}
		return nil
	})
	// issue #39: refresh handle labels for known peers even when there
	// are no new messages, so inactive threads eventually show (or lose)
	// their @handle. At most once a day; the dashboard ignores stale
	// labels after its own TTL.
	c.refreshPeerHandles(hc)
	return pushed, nil
}

// refreshPeerHandles pushes a handles-only update for every cached peer
// whose label may be stale, at most once per 24h. Without this, threads
// with no new messages would never get (or lose) their @handle label,
// because handles are otherwise only attached to message batches.
func (c *Client) refreshPeerHandles(hc *http.Client) {
	if time.Now().Unix()-c.cfg.HandleRefreshAt < 24*3600 {
		return
	}
	peers := make([]string, 0, len(c.cfg.HandleCache))
	for peer := range c.cfg.HandleCache {
		peers = append(peers, peer)
	}
	// Also cover named contacts: their handles may have been registered
	// after the last refresh.
	for _, addr := range c.cfg.Contacts {
		peers = append(peers, addr)
	}
	handles := map[string]string{}
	seen := map[string]bool{}
	for _, peer := range peers {
		if seen[peer] {
			continue
		}
		seen[peer] = true
		if h := c.PeerHandle(peer); h != "" {
			handles[peer] = h
		}
	}
	// issue #48: push contact trust states alongside the handle labels.
	// Only contacts carry verification; verified/stale peers get a
	// badge in the dashboard, unverified peers get none.
	verified := map[string]string{}
	for name := range c.cfg.Contacts {
		addr, err := c.cfg.LookupContact(name)
		if err != nil {
			continue
		}
		if st, _ := c.ContactTrust(name); st == TrustVerified || st == TrustStale {
			verified[addr] = st.String()
		}
	}
	// Mark the refresh even when there is nothing to push, so a peer
	// set with no listed handles does not retry every minute.
	_ = c.cfg.Update(func(fresh *Config) error {
		fresh.HandleRefreshAt = time.Now().Unix()
		return nil
	})
	if len(handles) == 0 {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"messages": []any{},
		"handles":  handles,
		"verified": verified,
	})
	req, _ := http.NewRequest(http.MethodPost, c.cfg.DashboardURL+"/v1/dashboard/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.DashboardToken)
	resp, err := hc.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
}

// pushBatch POSTs one bounded batch of messages to the dashboard and
// returns the server's stored count plus the batch's inbox/sent cursor
// maxima. The batch is acknowledged (HTTP 200) or it isn't — callers
// advance cursors only on success.
func (c *Client) pushBatch(hc *http.Client, batch []pushItem) (stored int, inboxMax, sentMax int64, err error) {
	msgs := make([]pushMsg, 0, len(batch))
	for _, it := range batch {
		msgs = append(msgs, it.msg)
		if it.sent {
			if it.msg.CourierID > sentMax {
				sentMax = it.msg.CourierID
			}
		} else if it.msg.CourierID > inboxMax {
			inboxMax = it.msg.CourierID
		}
	}
	// issue #39: attach listed handles for the batch's peers so the
	// dashboard can display them. PeerHandle is cached (24h TTL), so the
	// per-minute push does not query the directory for every thread.
	handles := map[string]string{}
	for _, it := range batch {
		peer := it.msg.From
		if it.msg.To != "" {
			peer = it.msg.To
		}
		if _, done := handles[peer]; done {
			continue
		}
		if h := c.PeerHandle(peer); h != "" {
			handles[peer] = h
		}
	}
	payload := map[string]any{"messages": msgs}
	if len(handles) > 0 {
		payload["handles"] = handles
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, c.cfg.DashboardURL+"/v1/dashboard/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.DashboardToken)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("push: %w", err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var er struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &er)
		if er.Error == "" {
			er.Error = resp.Status
		}
		return 0, 0, 0, fmt.Errorf("push failed: %s", er.Error)
	}
	var out struct {
		Stored int `json:"stored"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Stored, inboxMax, sentMax, nil
}
