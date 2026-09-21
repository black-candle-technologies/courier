// Package store persists encrypted envelopes for the Courier relay.
// The relay never sees plaintext: it stores opaque ciphertext addressed
// by recipient public key.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/envelope"
	_ "modernc.org/sqlite"
)

// Envelope is one stored message, ciphertext only.
type Envelope struct {
	ID         int64
	To         string // v0.2.0+ "ed25519:<base64url>" address, or "group:<base64url>" (issue #32)
	From       string // sender address (signature-authenticated in v0.2.0+)
	Eph        string // base64url ephemeral X25519 public key (32 random bytes for group messages)
	Nonce      string // base64url nonce
	Ct         string // base64url ciphertext
	SentAt     int64  // unix seconds, sender's clock
	ReceivedAt int64  // unix seconds, relay's clock
	Sig        string // base64url Ed25519 signature (v0.2.0+)
	Kind       string // "" or "dm" for direct messages, "group" for group messages (issue #32)
	KeyEpoch   int64  // sender-key epoch for group messages (issue #32); 0 otherwise
}

// Blob is one stored attachment blob: the framed, encrypted chunks.
// The relay sees ciphertext only; the data key is wrapped for the
// recipient in the attachment manifest, which travels inside the
// message ciphertext.
type Blob struct {
	BlobID    string // base64url 32 random bytes, client-generated
	Recipient string // ed25519:<base64url> address the blob was uploaded for
	Uploader  string // ed25519:<base64url> address that uploaded it
	Size      int64  // bytes of the framed ciphertext
	Data      []byte // opaque encrypted chunk frames
}

// Store wraps a SQLite database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS envelopes (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	recipient   TEXT NOT NULL,
	sender      TEXT NOT NULL,
	eph         TEXT NOT NULL,
	nonce       TEXT NOT NULL,
	ct          TEXT NOT NULL,
	sent_at     INTEGER NOT NULL,
	received_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	sig         TEXT NOT NULL DEFAULT '',
	env_hash    TEXT,
	kind        TEXT NOT NULL DEFAULT '',
	key_epoch   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_envelopes_recipient ON envelopes(recipient, id);
-- The UNIQUE index on env_hash is created by the v0.6.11 (F3) migration,
-- after the column exists on upgraded databases.

-- v0.5.0: signed encryption-key announcements. One row per address: the
-- current X25519 encryption key the owner published (courier rotate).
-- Senders look this up before sealing; if absent they fall back to the
-- address-derived key.
CREATE TABLE IF NOT EXISTS keys (
	address    TEXT PRIMARY KEY,
	x25519_pub TEXT NOT NULL,
	epoch      INTEGER NOT NULL,
	signature  TEXT NOT NULL DEFAULT ''
);

-- v0.6.0: web dashboard accounts. One dashboard user per Courier address.
-- password_hash is bcrypt; api_token_hash is SHA256 of the push token
-- (the raw token is shown once at registration and never stored).
CREATE TABLE IF NOT EXISTS dashboard_users (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	username          TEXT NOT NULL UNIQUE,
	password_hash     TEXT NOT NULL,
	must_change       INTEGER NOT NULL DEFAULT 1,
	courier_address   TEXT NOT NULL UNIQUE,
	api_token_hash    TEXT NOT NULL UNIQUE,
	created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS dashboard_sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS dashboard_messages (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id     INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
	courier_id  INTEGER NOT NULL,
	sender      TEXT NOT NULL,
	recipient   TEXT NOT NULL DEFAULT '',
	peer        TEXT NOT NULL DEFAULT '',
	body        TEXT NOT NULL,
	sent_at     INTEGER NOT NULL,
	received_at INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL DEFAULT 0,
	UNIQUE(user_id, courier_id)
);
CREATE INDEX IF NOT EXISTS idx_dashboard_messages_user ON dashboard_messages(user_id, courier_id);

-- Attachments: one row per encrypted file blob. data is the framed,
-- secretbox-sealed chunks (ciphertext only); the data key is wrapped for
-- the recipient in the attachment manifest inside the message ciphertext.
-- Blobs expire with the same retention policy as envelopes.
CREATE TABLE IF NOT EXISTS blobs (
	blob_id     TEXT PRIMARY KEY,
	recipient   TEXT NOT NULL,
	uploader    TEXT NOT NULL,
	size        INTEGER NOT NULL,
	data        BLOB NOT NULL,
	received_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_blobs_recipient ON blobs(recipient);
`

// migrate adds columns introduced after the table was first created.
// Old rows keep empty defaults; v0.2.0+ always writes sig.
func migrate(db *sql.DB) error {
	addColumn := func(stmt string) error {
		_, err := db.Exec(stmt)
		if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
		return nil
	}
	if err := addColumn(`ALTER TABLE envelopes ADD COLUMN sig TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// v0.6.5: thread support. recipient is the other side of an outbound
	// message ('' for inbound); peer is the counterparty address, computed
	// at insert. Old rows predate peer, so queries fall back to sender.
	if err := addColumn(`ALTER TABLE dashboard_messages ADD COLUMN recipient TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	if err := addColumn(`ALTER TABLE dashboard_messages ADD COLUMN peer TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// issue #51: reply threading. reply_to is the parent relay envelope
	// id (0 when not a reply); quote is the agent-provided parent
	// snippet for display. The dashboard never decrypts: the agent
	// reports, the dashboard displays (same trust model as handles).
	if err := addColumn(`ALTER TABLE dashboard_messages ADD COLUMN reply_to INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	if err := addColumn(`ALTER TABLE dashboard_messages ADD COLUMN quote TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// issue #53: disappearing messages. expires_at is 0 for messages
	// that never expire; the dashboard filters expired rows from reads
	// and deletes them on push.
	if err := addColumn(`ALTER TABLE dashboard_messages ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	// v0.6.11: key announcements now carry their Ed25519 signature so
	// senders can authenticate the directory response (F1).
	if err := addColumn(`ALTER TABLE keys ADD COLUMN signature TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// v0.6.11 (F3): replay dedup. env_hash covers every sender-controlled
	// envelope field; the UNIQUE index makes re-POSTed envelopes
	// idempotent instead of duplicating delivery.
	if err := addColumn(`ALTER TABLE envelopes ADD COLUMN env_hash TEXT`); err != nil {
		return err
	}
	if err := backfillEnvelopeHashes(db); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_envelopes_env_hash ON envelopes(env_hash)`); err != nil {
		return err
	}
	// issue #32: envelope kind ("" or "dm" for direct messages, "group"
	// for group messages). Empty for pre-group envelopes.
	if err := addColumn(`ALTER TABLE envelopes ADD COLUMN kind TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// issue #32: sender-key epoch for group messages (0 for direct
	// messages). Covered by the group envelope signature; tells the
	// reader which sender key sealed the body.
	if err := addColumn(`ALTER TABLE envelopes ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	// issue #32: group messaging tables.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS groups(
		group_id     TEXT PRIMARY KEY,
		name         TEXT NOT NULL DEFAULT '',
		admin        TEXT NOT NULL,
		member_epoch INTEGER NOT NULL DEFAULT 1,
		created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')))`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS group_members(
		group_id TEXT NOT NULL,
		member   TEXT NOT NULL,
		PRIMARY KEY (group_id, member))`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS group_controls(
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		group_id   TEXT NOT NULL,
		action     TEXT NOT NULL,
		target     TEXT NOT NULL DEFAULT '',
		admin      TEXT NOT NULL,
		epoch      INTEGER NOT NULL,
		sig        TEXT NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		UNIQUE(group_id, epoch))`); err != nil {
		return err
	}
	// v0.6.9: per-thread read state for unread badges.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS dashboard_seen(
		user_id      INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
		peer         TEXT NOT NULL,
		last_seen_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, peer))`); err != nil {
		return err
	}
	// Spam/abuse reports (metadata-only filtering). One row per
	// (sender, reporter) pair: only distinct reporters count toward the
	// throttle threshold, and re-reports are idempotent. reported_at
	// implements decay: only reports inside the throttle window count.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS spam_reports(
		sender      TEXT NOT NULL,
		reporter    TEXT NOT NULL,
		envelope_id INTEGER NOT NULL,
		reported_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		PRIMARY KEY (sender, reporter))`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_spam_reports_sender
		ON spam_reports(sender, reported_at)`); err != nil {
		return err
	}
	// issue #39: contact-discovery directory. One row per handle
	// (handle is the primary key: first-come-first-served, §11 Q2).
	// capabilities are 0x00-joined tokens. tombstone marks an operator
	// takedown: the row stays so the handle cannot be re-registered and
	// the removal is visible (transparent takedown, §11 Q3).
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS directory(
		handle           TEXT PRIMARY KEY,
		address          TEXT NOT NULL,
		capabilities     TEXT NOT NULL DEFAULT '',
		contact_policy   TEXT NOT NULL DEFAULT 'open',
		visibility       TEXT NOT NULL DEFAULT 'private',
		epoch            INTEGER NOT NULL,
		signature        TEXT NOT NULL DEFAULT '',
		transfer_from    TEXT NOT NULL DEFAULT '',
		tombstone        INTEGER NOT NULL DEFAULT 0,
		tombstone_reason TEXT NOT NULL DEFAULT '',
		registered_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		updated_at       INTEGER NOT NULL DEFAULT (strftime('%s','now'))
	)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_directory_address
		ON directory(address)`); err != nil {
		return err
	}
	// v0.8.0 (issue #39): transfer proof. When a handle is transferred,
	// the stored signature is the previous holder's transfer signature
	// (not a registration signature by the new owner), so the previous
	// holder's address is kept alongside it. Clients verify the binding
	// as: register-sig by the profile address, or transfer-sig by
	// transfer_from over (handle, new address, epoch).
	if err := addColumn(`ALTER TABLE directory ADD COLUMN transfer_from TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	// issue #39: per-user peer handle labels for the dashboard. The
	// agent resolves listed handles via the signed directory reverse
	// endpoint and pushes them with its messages; the dashboard only
	// displays what the agent tells it — it never queries the directory
	// itself (it holds no identity key). Stale on purpose: rows older
	// than the display TTL are ignored so unregistered handles fade.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS dashboard_peer_handles(
		user_id    INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
		peer       TEXT NOT NULL,
		handle     TEXT NOT NULL,
		updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		PRIMARY KEY (user_id, peer))`); err != nil {
		return err
	}
	// issue #48: per-user peer verification states for the dashboard.
	// The agent pushes them with its peer labels; the dashboard only
	// displays what the agent reports — it never verifies identities
	// itself. Rows older than the display TTL are ignored.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS dashboard_peer_verified(
		user_id    INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
		peer       TEXT NOT NULL,
		status     TEXT NOT NULL,
		updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		PRIMARY KEY (user_id, peer))`); err != nil {
		return err
	}
	// Optional Black Candle account linking (config-gated, off unless the
	// dashboard is started with the auth service configured). bct_user_id
	// is the authd user id, NULL when the dashboard user is not linked.
	// The unique index enforces one dashboard user per BCT account;
	// SQLite treats NULLs as distinct, so any number of unlinked users
	// is fine.
	if err := addColumn(`ALTER TABLE dashboard_users ADD COLUMN bct_user_id INTEGER`); err != nil {
		return err
	}
	if err := addColumn(`ALTER TABLE dashboard_users ADD COLUMN bct_email TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_users_bct_user_id ON dashboard_users(bct_user_id)`); err != nil {
		return err
	}
	return nil
}

// backfillEnvelopeHashes computes env_hash for envelopes stored before
// the v0.6.11 (F3) replay-dedup migration, so old messages are covered too.
func backfillEnvelopeHashes(db *sql.DB) error {
	rows, err := db.Query(`SELECT id, recipient, sender, eph, nonce, ct, sent_at, sig
		FROM envelopes WHERE env_hash IS NULL`)
	if err != nil {
		return err
	}
	type update struct {
		id   int64
		hash string
	}
	var updates []update
	for rows.Next() {
		var id, sentAt int64
		var to, from, eph, nonce, ct, sig string
		if err := rows.Scan(&id, &to, &from, &eph, &nonce, &ct, &sentAt, &sig); err != nil {
			rows.Close()
			return err
		}
		updates = append(updates, update{id, envelope.DedupHash(to, from, eph, nonce, sentAt, ct, sig)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, u := range updates {
		if _, err := db.Exec(`UPDATE envelopes SET env_hash = ? WHERE id = ?`, u.hash, u.id); err != nil {
			return err
		}
	}
	return nil
}

// Open opens (creating if needed) the SQLite database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Save stores an envelope and returns its id. If an identical envelope
// (same canonical hash, v0.6.11 F3) was already stored — a replayed POST —
// it returns the existing id with stored=false instead of duplicating
// the message. Replays are acknowledged, not redelivered.
func (s *Store) Save(e *Envelope) (id int64, stored bool, err error) {
	h := envelope.DedupHash(e.To, e.From, e.Eph, e.Nonce, e.SentAt, e.Ct, e.Sig)
	res, err := s.db.Exec(
		`INSERT INTO envelopes (recipient, sender, eph, nonce, ct, sent_at, sig, env_hash, kind, key_epoch)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(env_hash) DO NOTHING`,
		e.To, e.From, e.Eph, e.Nonce, e.Ct, e.SentAt, e.Sig, h, e.Kind, e.KeyEpoch,
	)
	if err != nil {
		return 0, false, fmt.Errorf("insert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("insert: %w", err)
	}
	if n == 0 {
		var existing int64
		if err := s.db.QueryRow(`SELECT id FROM envelopes WHERE env_hash = ?`, h).Scan(&existing); err != nil {
			return 0, false, fmt.Errorf("lookup duplicate: %w", err)
		}
		return existing, false, nil
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("insert: %w", err)
	}
	return id, true, nil
}

// List returns up to limit envelopes for recipient with id > after,
// oldest first.
func (s *Store) List(recipient string, after int64, limit int) ([]Envelope, error) {
	rows, err := s.db.Query(
		`SELECT id, recipient, sender, eph, nonce, ct, sent_at, received_at, sig, kind, key_epoch
		 FROM envelopes WHERE recipient = ? AND id > ?
		 ORDER BY id ASC LIMIT ?`,
		recipient, after, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var out []Envelope
	for rows.Next() {
		var e Envelope
		if err := rows.Scan(&e.ID, &e.To, &e.From, &e.Eph, &e.Nonce, &e.Ct, &e.SentAt, &e.ReceivedAt, &e.Sig, &e.Kind, &e.KeyEpoch); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Prune deletes envelopes received more than retainDays ago.
// Returns the number of rows deleted.
func (s *Store) Prune(retainDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retainDays).Unix()
	res, err := s.db.Exec(`DELETE FROM envelopes WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune: %w", err)
	}
	return res.RowsAffected()
}

// Count returns the total number of stored envelopes (for health checks).
func (s *Store) Count() (int64, error) {
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM envelopes`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ---- Attachment blobs ----

// SaveBlob stores an attachment blob. Blob ids are client-generated
// random 256-bit values, so a re-upload of the same blob is idempotent:
// the existing row wins and stored=false is reported, mirroring the
// envelope replay behavior.
func (s *Store) SaveBlob(b *Blob) (stored bool, err error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO blobs (blob_id, recipient, uploader, size, data)
		 VALUES (?, ?, ?, ?, ?)`,
		b.BlobID, b.Recipient, b.Uploader, b.Size, b.Data,
	)
	if err != nil {
		return false, fmt.Errorf("insert blob: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("insert blob: %w", err)
	}
	return n > 0, nil
}

// GetBlob returns a blob by id, or sql.ErrNoRows if unknown.
func (s *Store) GetBlob(blobID string) (*Blob, error) {
	var b Blob
	err := s.db.QueryRow(
		`SELECT blob_id, recipient, uploader, size, data FROM blobs WHERE blob_id = ?`,
		blobID,
	).Scan(&b.BlobID, &b.Recipient, &b.Uploader, &b.Size, &b.Data)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// PruneBlobs deletes blobs received more than retainDays ago, reusing
// the envelope retention policy. Returns the number of rows deleted.
func (s *Store) PruneBlobs(retainDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retainDays).Unix()
	res, err := s.db.Exec(`DELETE FROM blobs WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune blobs: %w", err)
	}
	return res.RowsAffected()
}

// KeyAnnouncement is one published encryption key for an address.
type KeyAnnouncement struct {
	Address   string
	X25519Pub string // base64url 32-byte X25519 public key
	Epoch     int64  // unix seconds of rotation; strictly increasing
	Sig       string // base64url Ed25519 signature over the announcement
}

// SaveKey stores a key announcement atomically: the row is inserted or
// replaced only when the announcement's epoch is strictly greater than
// the stored one (v0.6.11 F9). A single upsert — no SELECT-then-write
// race — decides; RowsAffected reports whether this announcement won.
// Returns false for stale or replayed announcements.
func (s *Store) SaveKey(k *KeyAnnouncement) (bool, error) {
	res, err := s.db.Exec(
		`INSERT INTO keys (address, x25519_pub, epoch, signature) VALUES (?, ?, ?, ?)
		 ON CONFLICT(address) DO UPDATE SET x25519_pub = excluded.x25519_pub, epoch = excluded.epoch, signature = excluded.signature
		 WHERE excluded.epoch > keys.epoch`,
		k.Address, k.X25519Pub, k.Epoch, k.Sig,
	)
	if err != nil {
		return false, fmt.Errorf("save key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("save key: %w", err)
	}
	return n > 0, nil // 0 rows: stale announcement, nothing changed
}

// GetKey returns the current key announcement for an address, or
// sql.ErrNoRows if the owner never published one.
func (s *Store) GetKey(address string) (*KeyAnnouncement, error) {
	var k KeyAnnouncement
	err := s.db.QueryRow(
		`SELECT address, x25519_pub, epoch, signature FROM keys WHERE address = ?`,
		address,
	).Scan(&k.Address, &k.X25519Pub, &k.Epoch, &k.Sig)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ---- contact discovery directory (issue #39) ----

// DirectoryEntry is one handle registration: a signed binding of a
// handle to an Ed25519 identity. The relay stores only the allowed
// fields (§7 of the design); no PII fields exist in the schema.
type DirectoryEntry struct {
	Handle          string
	Address         string   // ed25519:<base64url> owner identity
	Capabilities    []string // bounded free-form tokens
	ContactPolicy   string   // "open" | "contacts"
	Visibility      string   // "public" | "unlisted" | "private"
	Epoch           int64    // monotonic; strictly increasing updates only
	Sig             string   // base64url Ed25519 signature (see TransferFrom)
	TransferFrom    string   // previous holder, when Sig is a transfer signature; "" otherwise
	Tombstone       bool     // operator takedown marker (transparent, §11 Q3)
	TombstoneReason string   // published takedown reason
	RegisteredAt    int64
	UpdatedAt       int64
}

// directoryColumns lists the served columns in scan order.
const directoryColumns = `handle, address, capabilities, contact_policy,
	visibility, epoch, signature, transfer_from, tombstone, tombstone_reason,
	registered_at, updated_at`

func scanDirectoryRows(rows *sql.Rows) ([]DirectoryEntry, error) {
	var out []DirectoryEntry
	for rows.Next() {
		var e DirectoryEntry
		var caps string
		var tombstone int
		if err := rows.Scan(&e.Handle, &e.Address, &caps, &e.ContactPolicy,
			&e.Visibility, &e.Epoch, &e.Sig, &e.TransferFrom, &tombstone, &e.TombstoneReason,
			&e.RegisteredAt, &e.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		if caps != "" {
			e.Capabilities = strings.Split(caps, "\x00")
		}
		e.Tombstone = tombstone != 0
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	return out, nil
}

// SaveDirectory inserts or updates a handle registration. Only the
// current holder's address with a strictly greater epoch is applied
// (F9 pattern); anything else is a no-op returning applied=false. The
// caller distinguishes stale-epoch / wrong-owner / tombstoned via
// GetDirectory before calling.
func (s *Store) SaveDirectory(d *DirectoryEntry) (applied bool, err error) {
	caps := strings.Join(d.Capabilities, "\x00")
	res, err := s.db.Exec(
		`INSERT INTO directory (handle, address, capabilities, contact_policy,
			visibility, epoch, signature, transfer_from, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, '', strftime('%s','now'))
		 ON CONFLICT(handle) DO UPDATE SET
			capabilities = excluded.capabilities,
			contact_policy = excluded.contact_policy,
			visibility = excluded.visibility,
			epoch = excluded.epoch,
			signature = excluded.signature,
			transfer_from = '',
			tombstone = 0,
			tombstone_reason = '',
			updated_at = strftime('%s','now')
		 WHERE excluded.epoch > directory.epoch
		   AND directory.address = excluded.address
		   AND directory.tombstone = 0`,
		d.Handle, d.Address, caps, d.ContactPolicy, d.Visibility, d.Epoch, d.Sig,
	)
	if err != nil {
		return false, fmt.Errorf("save directory: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("save directory: %w", err)
	}
	return n > 0, nil
}

// GetDirectory returns the entry for a handle (already normalized to
// lowercase by the caller), or sql.ErrNoRows.
func (s *Store) GetDirectory(handle string) (*DirectoryEntry, error) {
	rows, err := s.db.Query(
		`SELECT `+directoryColumns+` FROM directory WHERE handle = ?`, handle)
	if err != nil {
		return nil, err
	}
	entries, err := scanDirectoryRows(rows)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, sql.ErrNoRows
	}
	return &entries[0], nil
}

// DirectoryByAddress returns all non-tombstoned, non-private entries for
// an address, public first. Used by the signed reverse-lookup endpoint
// (dashboard handle display).
func (s *Store) DirectoryByAddress(address string) ([]DirectoryEntry, error) {
	rows, err := s.db.Query(
		`SELECT `+directoryColumns+` FROM directory
		 WHERE address = ? AND tombstone = 0 AND visibility != 'private'
		 ORDER BY CASE visibility WHEN 'public' THEN 0 ELSE 1 END, handle`,
		address)
	if err != nil {
		return nil, err
	}
	return scanDirectoryRows(rows)
}

// SearchDirectory returns public, non-tombstoned handles with the given
// lowercase prefix, ordered alphabetically, capped at limit. Prefix-only:
// no substring, no wildcards, no total counts (anti-enumeration, T2).
func (s *Store) SearchDirectory(prefix string, limit int) ([]DirectoryEntry, error) {
	esc := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(prefix, `\`, `\\`), `%`, `\%`), `_`, `\_`)
	rows, err := s.db.Query(
		`SELECT `+directoryColumns+` FROM directory
		 WHERE handle LIKE ? ESCAPE '\' AND visibility = 'public' AND tombstone = 0
		 ORDER BY handle LIMIT ?`, esc+`%`, limit)
	if err != nil {
		return nil, err
	}
	return scanDirectoryRows(rows)
}

// TransferDirectory moves a handle to a new owner address. The caller
// verifies the transfer signature (signed by the current holder) before
// calling; the epoch guard makes replays a no-op. The previous holder's
// address is recorded as transfer_from so clients can verify the
// transfer signature against the right key.
func (s *Store) TransferDirectory(handle, newAddress string, epoch int64, sig string) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE directory SET address = ?, epoch = ?, signature = ?,
			transfer_from = address,
			tombstone = 0, tombstone_reason = '',
			updated_at = strftime('%s','now')
		 WHERE handle = ? AND ? > epoch AND tombstone = 0`,
		newAddress, epoch, sig, handle, epoch,
	)
	if err != nil {
		return false, fmt.Errorf("transfer directory: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("transfer directory: %w", err)
	}
	return n > 0, nil
}

// DeregisterDirectory deletes a handle registration. Only the owning
// address may deregister its own handle (holder's choice; distinct from
// operator takedown, which leaves a visible tombstone).
func (s *Store) DeregisterDirectory(handle, address string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM directory WHERE handle = ? AND address = ?`,
		handle, address)
	if err != nil {
		return false, fmt.Errorf("deregister directory: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("deregister directory: %w", err)
	}
	return n > 0, nil
}

// TombstoneDirectory applies an operator takedown: the row stays so the
// handle cannot be re-registered and the removal is visible via lookup
// (transparent takedown under a published policy, §11 Q3). No silent
// removals: the reason is stored and served.
func (s *Store) TombstoneDirectory(handle, reason string) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE directory SET tombstone = 1, tombstone_reason = ?,
			updated_at = strftime('%s','now')
		 WHERE handle = ? AND tombstone = 0`,
		reason, handle,
	)
	if err != nil {
		return false, fmt.Errorf("tombstone directory: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("tombstone directory: %w", err)
	}
	return n > 0, nil
}

// UntombstoneDirectory lifts an operator takedown, restoring the entry
// to service. Used when a takedown is reversed on review.
func (s *Store) UntombstoneDirectory(handle string) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE directory SET tombstone = 0, tombstone_reason = '',
			updated_at = strftime('%s','now')
		 WHERE handle = ? AND tombstone = 1`, handle,
	)
	if err != nil {
		return false, fmt.Errorf("untombstone directory: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("untombstone directory: %w", err)
	}
	return n > 0, nil
}

// ---- spam / abuse reports (metadata-only filtering) ----

// EnvelopeByID returns one envelope by its id, or sql.ErrNoRows. Used to
// authorize spam reports: only the envelope's recipient may report it.
func (s *Store) EnvelopeByID(id int64) (*Envelope, error) {
	var e Envelope
	err := s.db.QueryRow(
		`SELECT id, recipient, sender, eph, nonce, ct, sent_at, received_at, sig
		 FROM envelopes WHERE id = ?`,
		id,
	).Scan(&e.ID, &e.To, &e.From, &e.Eph, &e.Nonce, &e.Ct, &e.SentAt, &e.ReceivedAt, &e.Sig)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// RecordSpamReport records that reporter flagged sender's message
// envelopeID as spam. It is idempotent per (sender, reporter): only
// distinct reporters count toward the throttle threshold, so one angry
// recipient cannot throttle a sender alone. The reporter must be the
// envelope's recipient — enforced by the caller.
func (s *Store) RecordSpamReport(sender, reporter string, envelopeID int64) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO spam_reports(sender, reporter, envelope_id)
		 VALUES (?, ?, ?)`,
		sender, reporter, envelopeID,
	)
	return err
}

// DistinctReporterCount counts the distinct reporters who flagged sender
// within the last windowSecs seconds. Reports age out of the window, so
// a sender's throttle decays over time once they stop spamming.
func (s *Store) DistinctReporterCount(sender string, windowSecs int64) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(DISTINCT reporter) FROM spam_reports
		 WHERE sender = ? AND reported_at >= strftime('%s','now') - ?`,
		sender, windowSecs,
	).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ---- v0.6.0: dashboard ----

// DashboardUser is one web-dashboard account.
type DashboardUser struct {
	ID             int64
	Username       string
	PasswordHash   string
	MustChange     bool
	CourierAddress string
	APITokenHash   string
	CreatedAt      int64
	// BCTUserID is the linked Black Candle authd user id, 0 when the
	// dashboard user has not linked a Black Candle account. BCTEmail is
	// the linked account's email (display only).
	BCTUserID int64
	BCTEmail  string
}

// CreateDashboardUser inserts a dashboard user. The caller hashes the
// password (bcrypt) and the API token (SHA256) first.
func (s *Store) CreateDashboardUser(username, passwordHash, courierAddress, apiTokenHash string) (*DashboardUser, error) {
	res, err := s.db.Exec(
		`INSERT INTO dashboard_users (username, password_hash, must_change, courier_address, api_token_hash)
		 VALUES (?, ?, 1, ?, ?)`,
		username, passwordHash, courierAddress, apiTokenHash,
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	id, _ := res.LastInsertId()
	return &DashboardUser{ID: id, Username: username, PasswordHash: passwordHash,
		MustChange: true, CourierAddress: courierAddress, APITokenHash: apiTokenHash}, nil
}

func scanDashboardUser(row *sql.Row) (*DashboardUser, error) {
	var u DashboardUser
	var mustChange int
	var bctUserID sql.NullInt64
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange,
		&u.CourierAddress, &u.APITokenHash, &u.CreatedAt, &bctUserID, &u.BCTEmail)
	if err != nil {
		return nil, err
	}
	u.MustChange = mustChange != 0
	if bctUserID.Valid {
		u.BCTUserID = bctUserID.Int64
	}
	return &u, nil
}

// DashboardUserByName looks up a user by username.
func (s *Store) DashboardUserByName(username string) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT id, username, password_hash, must_change, courier_address, api_token_hash, created_at, bct_user_id, bct_email
		 FROM dashboard_users WHERE username = ?`, username))
}

// DashboardUserByTokenHash looks up a user by the SHA256 of their API token.
func (s *Store) DashboardUserByTokenHash(tokenHash string) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT id, username, password_hash, must_change, courier_address, api_token_hash, created_at, bct_user_id, bct_email
		 FROM dashboard_users WHERE api_token_hash = ?`, tokenHash))
}

// DashboardUserByBCTUserID looks up the dashboard user linked to a Black
// Candle authd account, or sql.ErrNoRows when no user linked it.
func (s *Store) DashboardUserByBCTUserID(bctUserID int64) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT id, username, password_hash, must_change, courier_address, api_token_hash, created_at, bct_user_id, bct_email
		 FROM dashboard_users WHERE bct_user_id = ?`, bctUserID))
}

// LinkBCTAccount binds a dashboard user to a Black Candle authd account.
// The caller must have verified the BCT credentials first. One BCT
// account links to at most one dashboard user: the unique index rejects
// a second binding.
func (s *Store) LinkBCTAccount(userID, bctUserID int64, bctEmail string) error {
	_, err := s.db.Exec(`UPDATE dashboard_users SET bct_user_id = ?, bct_email = ? WHERE id = ?`,
		bctUserID, bctEmail, userID)
	return err
}

// UnlinkBCTAccount removes the Black Candle account binding. The
// dashboard username/password keeps working unchanged.
func (s *Store) UnlinkBCTAccount(userID int64) error {
	_, err := s.db.Exec(`UPDATE dashboard_users SET bct_user_id = NULL, bct_email = '' WHERE id = ?`, userID)
	return err
}

// ChangeDashboardPassword replaces the password hash, clears must_change,
// and revokes ALL sessions for the user, atomically (F6). A password
// change — forced or not — must not leave old sessions alive. The caller
// issues a fresh session for the requester afterwards so they stay
// logged in.
func (s *Store) ChangeDashboardPassword(userID int64, passwordHash string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE dashboard_users SET password_hash = ?, must_change = 0 WHERE id = ?`,
		passwordHash, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dashboard_sessions WHERE user_id = ?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSession stores a login session token (by its SHA256 hash).
func (s *Store) CreateSession(tokenHash string, userID int64, ttl time.Duration) error {
	_, err := s.db.Exec(
		`INSERT INTO dashboard_sessions (token_hash, user_id, expires_at)
		 VALUES (?, ?, strftime('%s','now') + ?)`,
		tokenHash, userID, int64(ttl.Seconds()))
	return err
}

// SessionUser returns the user for a session token hash, or sql.ErrNoRows.
func (s *Store) SessionUser(tokenHash string) (*DashboardUser, error) {
	var u DashboardUser
	var mustChange int
	var bctUserID sql.NullInt64
	err := s.db.QueryRow(
		`SELECT u.id, u.username, u.password_hash, u.must_change, u.courier_address, u.api_token_hash, u.created_at, u.bct_user_id, u.bct_email
		 FROM dashboard_sessions s JOIN dashboard_users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > strftime('%s','now')`,
		tokenHash).Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange,
		&u.CourierAddress, &u.APITokenHash, &u.CreatedAt, &bctUserID, &u.BCTEmail)
	if err != nil {
		return nil, err
	}
	u.MustChange = mustChange != 0
	if bctUserID.Valid {
		u.BCTUserID = bctUserID.Int64
	}
	return &u, nil
}

// DeleteSession removes one session token.
func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(`DELETE FROM dashboard_sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DashboardMessage is one decrypted agent message forwarded for the user.
type DashboardMessage struct {
	ID         int64
	CourierID  int64
	Sender     string
	Recipient  string // other side of an outbound message; '' for inbound
	Body       string
	SentAt     int64
	ReceivedAt int64
	// ReplyTo is the parent relay envelope id (issue #51); 0 when the
	// message is not a reply. Quote is the agent-provided parent
	// snippet for display ("" when unknown).
	ReplyTo int64
	Quote   string
	// ExpiresAt is the issue #53 disappearing-message expiry (0 =
	// never). Read paths filter expired rows; the push sweep deletes
	// them.
	ExpiresAt int64
}

// SaveDashboardMessage stores a pushed message; duplicates (same user +
// courier id) are ignored. It reports whether the row was actually
// inserted. peer is the counterparty address: the sender for inbound
// messages, the recipient for outbound ones. replyTo/quote carry
// reply threading metadata (issue #51); expiresAt is the issue #53
// disappearing-message expiry, 0 for messages that never expire.
func (s *Store) SaveDashboardMessage(userID, courierID int64, sender, recipient, peer, body string, sentAt, receivedAt, replyTo int64, quote string, expiresAt int64) (bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO dashboard_messages
		 (user_id, courier_id, sender, recipient, peer, body, sent_at, received_at, reply_to, quote, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, courierID, sender, recipient, peer, body, sentAt, receivedAt, replyTo, quote, expiresAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// PruneExpiredDashboardMessages deletes disappeared messages (issue
// #53): rows whose expires_at has passed. It returns the number of rows
// deleted. Called on every dashboard push; read paths also filter
// expired rows so a message never surfaces after its expiry even
// between pushes.
func (s *Store) PruneExpiredDashboardMessages() (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM dashboard_messages
		 WHERE expires_at != 0 AND expires_at <= strftime('%s','now')`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// peerExpr resolves the counterparty of a message row. Rows written before
// v0.6.5 have no peer value; those are all inbound, so sender is the peer.
const peerExpr = `COALESCE(NULLIF(peer,''), sender)`

// liveMessageExpr is the issue #53 disappearing-message read predicate:
// rows that never expire, or whose expiry is still in the future. alias
// is the table alias ("" when the query has no alias).
func liveMessageExpr(alias string) string {
	col := "expires_at"
	if alias != "" {
		col = alias + ".expires_at"
	}
	return `(` + col + ` = 0 OR ` + col + ` > strftime('%s','now'))`
}

// DashboardThread is one conversation: all messages exchanged with a
// single counterparty address. Handle is the peer's listed directory
// handle when the agent has resolved one ("" otherwise).
type DashboardThread struct {
	Peer     string
	Handle   string // "@handle" display label, "" when unknown
	Verified string // "verified"|"stale"|"": contact trust badge (issue #48)
	Count    int64
	LastTS   int64
	LastBody string
	LastOut  bool  // the latest message was sent by the user
	Unread   int64 // inbound messages newer than the user's last visit
}

// DashboardThreads returns the user's threads, most recently active first.
//
// v0.6.11 (F7): the unread count used to be a correlated subquery
// evaluated once per message row — quadratic work on SQLite's single
// connection. It is now aggregated once per peer with a single GROUP BY
// and joined to the latest-message rows in Go.
func (s *Store) DashboardThreads(userID int64, userAddr string, limit int) ([]DashboardThread, error) {
	// Unread inbound messages per peer, computed in one pass. The peer
	// expression matches the thread key: stored peer, else the sender
	// for rows predating threading. Qualified with m. because
	// dashboard_seen also has a peer column.
	const peer = `COALESCE(NULLIF(m.peer,''), m.sender)`
	unreadByPeer := map[string]int64{}
	urows, err := s.db.Query(
		`SELECT `+peer+` AS p, COUNT(*)
		 FROM dashboard_messages m
		 LEFT JOIN dashboard_seen s
		   ON s.user_id = m.user_id AND s.peer = `+peer+`
		 WHERE m.user_id = ? AND m.sender != ?
		   AND m.id > COALESCE(s.last_seen_id, 0)
		   AND `+liveMessageExpr("m")+`
		 GROUP BY p`,
		userID, userAddr)
	if err != nil {
		return nil, err
	}
	for urows.Next() {
		var p string
		var n int64
		if err := urows.Scan(&p, &n); err != nil {
			urows.Close()
			return nil, err
		}
		unreadByPeer[p] = n
	}
	if err := urows.Err(); err != nil {
		urows.Close()
		return nil, err
	}
	urows.Close()

	// Peer handle labels, fetched before the next query: the store
	// holds a single SQLite connection, so a second query cannot run
	// while rows from the first are still open.
	handles, _ := s.PeerHandles(userID, peerHandleTTL)

	// issue #48: peer verification badges, same pattern as handles.
	verified, _ := s.PeerVerified(userID, peerVerifiedTTL)

	// Latest message per peer.
	const tpeer = `COALESCE(NULLIF(t.peer,''), t.sender)`
	lrows, err := s.db.Query(
		`SELECT p, body, sender, cnt, ts FROM (
		   SELECT `+tpeer+` AS p, t.body AS body, t.sender AS sender,
		          COUNT(*) OVER (PARTITION BY `+tpeer+`) AS cnt,
		          COALESCE(t.sent_at, t.received_at) AS ts,
		          ROW_NUMBER() OVER (PARTITION BY `+tpeer+`
		                             ORDER BY COALESCE(t.sent_at, t.received_at) DESC, t.id DESC) AS rn
		   FROM dashboard_messages t WHERE t.user_id = ?
		     AND `+liveMessageExpr("t")+`
		 ) WHERE rn = 1 ORDER BY ts DESC, p ASC LIMIT ?`,
		userID, limit)
	if err != nil {
		return nil, err
	}
	defer lrows.Close()
	var out []DashboardThread
	for lrows.Next() {
		var th DashboardThread
		var sender string
		if err := lrows.Scan(&th.Peer, &th.LastBody, &sender, &th.Count, &th.LastTS); err != nil {
			return nil, err
		}
		th.LastOut = sender == userAddr
		th.Unread = unreadByPeer[th.Peer]
		th.Handle = handles[th.Peer]
		th.Verified = verified[th.Peer]
		out = append(out, th)
	}
	return out, lrows.Err()
}

// peerHandleTTL is how long a pushed peer-handle label stays valid for
// display. Handles are refreshed by the agent's push (24h client cache);
// entries older than this are ignored so unregistered handles fade
// rather than lingering forever.
const peerHandleTTL = 7 * 24 * time.Hour

// peerVerifiedTTL is the display TTL for pushed contact-verification
// states (issue #48). Same refresh cadence as handle labels: the agent
// re-pushes at most every 24h, and verification changes force an early
// refresh.
const peerVerifiedTTL = 7 * 24 * time.Hour

// verifiedStatuses are the only peer-verification states the dashboard
// accepts from an agent push.
var verifiedStatuses = map[string]bool{"verified": true, "stale": true}

// SavePeerHandle records the agent-resolved directory handle for a peer
// (upsert). handle must already be normalized; empty clears the label.
func (s *Store) SavePeerHandle(userID int64, peer, handle string) error {
	if handle == "" {
		_, err := s.db.Exec(`DELETE FROM dashboard_peer_handles WHERE user_id = ? AND peer = ?`,
			userID, peer)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO dashboard_peer_handles(user_id, peer, handle, updated_at)
		VALUES(?, ?, ?, strftime('%s','now'))
		ON CONFLICT(user_id, peer) DO UPDATE SET handle = excluded.handle,
		updated_at = excluded.updated_at`, userID, peer, handle)
	return err
}

// PeerHandles returns fresh (within ttl) peer→handle labels for a user.
func (s *Store) PeerHandles(userID int64, ttl time.Duration) (map[string]string, error) {
	out := map[string]string{}
	cutoff := time.Now().Add(-ttl).Unix()
	rows, err := s.db.Query(`SELECT peer, handle FROM dashboard_peer_handles
		WHERE user_id = ? AND updated_at >= ?`, userID, cutoff)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var peer, handle string
		if err := rows.Scan(&peer, &handle); err != nil {
			return out, err
		}
		out[peer] = handle
	}
	return out, rows.Err()
}

// SavePeerVerified records the agent-reported verification state for a
// peer (upsert). status must be "verified" or "stale"; anything else is
// rejected by the caller. An empty status clears the badge.
func (s *Store) SavePeerVerified(userID int64, peer, status string) error {
	if status == "" {
		_, err := s.db.Exec(`DELETE FROM dashboard_peer_verified WHERE user_id = ? AND peer = ?`,
			userID, peer)
		return err
	}
	if !verifiedStatuses[status] {
		return fmt.Errorf("bad verification status %q", status)
	}
	_, err := s.db.Exec(`INSERT INTO dashboard_peer_verified(user_id, peer, status, updated_at)
		VALUES(?, ?, ?, strftime('%s','now'))
		ON CONFLICT(user_id, peer) DO UPDATE SET status = excluded.status,
		updated_at = excluded.updated_at`, userID, peer, status)
	return err
}

// PeerVerified returns fresh (within ttl) peer→status verification
// states for a user.
func (s *Store) PeerVerified(userID int64, ttl time.Duration) (map[string]string, error) {
	out := map[string]string{}
	cutoff := time.Now().Add(-ttl).Unix()
	rows, err := s.db.Query(`SELECT peer, status FROM dashboard_peer_verified
		WHERE user_id = ? AND updated_at >= ?`, userID, cutoff)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var peer, status string
		if err := rows.Scan(&peer, &status); err != nil {
			return out, err
		}
		out[peer] = status
	}
	return out, rows.Err()
}

// MarkThreadSeen records that the user has viewed a thread up to lastID.
func (s *Store) MarkThreadSeen(userID int64, peer string, lastID int64) error {
	_, err := s.db.Exec(
		`INSERT INTO dashboard_seen(user_id, peer, last_seen_id) VALUES(?, ?, ?)
		 ON CONFLICT(user_id, peer) DO UPDATE SET last_seen_id = MAX(last_seen_id, excluded.last_seen_id)`,
		userID, peer, lastID)
	return err
}

// ThreadSeenID returns the last_seen_id watermark for a thread, or 0 if
// the thread was never opened.
func (s *Store) ThreadSeenID(userID int64, peer string) (int64, error) {
	var id sql.NullInt64
	err := s.db.QueryRow(
		`SELECT last_seen_id FROM dashboard_seen WHERE user_id = ? AND peer = ?`,
		userID, peer).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return id.Int64, nil
}

// escapeLike escapes LIKE metacharacters in a user search string.
func escapeLike(q string) string {
	q = strings.ReplaceAll(q, `\`, `\\`)
	q = strings.ReplaceAll(q, `%`, `\%`)
	q = strings.ReplaceAll(q, `_`, `\_`)
	return q
}

// SearchThreadPeers returns the distinct thread peers having any message
// whose body, sender, or peer contains q (case-insensitive).
func (s *Store) SearchThreadPeers(userID int64, q string) ([]string, error) {
	like := "%" + escapeLike(q) + "%"
	rows, err := s.db.Query(
		`SELECT DISTINCT `+peerExpr+` FROM dashboard_messages
		 WHERE user_id = ?
		   AND `+liveMessageExpr("")+`
		   AND (body LIKE ? ESCAPE '\'
		        OR sender LIKE ? ESCAPE '\'
		        OR COALESCE(NULLIF(peer,''), '') LIKE ? ESCAPE '\')`,
		userID, like, like, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DashboardThreadMessages returns one thread's messages, oldest first.
// DashboardThreadMessages returns the NEWEST limit messages of a thread in
// chronological (oldest-first) display order. F12: the query fetches the
// newest rows first and the results are reversed in Go, so a long thread
// shows recent history instead of the oldest 500 messages.
func (s *Store) DashboardThreadMessages(userID int64, peer string, limit int) ([]DashboardMessage, error) {
	rows, err := s.db.Query(
		`SELECT id, courier_id, sender, recipient, body, sent_at, received_at, reply_to, quote, expires_at
		 FROM dashboard_messages
		 WHERE user_id = ? AND `+peerExpr+` = ?
		   AND `+liveMessageExpr("")+`
		 ORDER BY COALESCE(sent_at, received_at) DESC, id DESC LIMIT ?`,
		userID, peer, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DashboardMessage
	for rows.Next() {
		var m DashboardMessage
		if err := rows.Scan(&m.ID, &m.CourierID, &m.Sender, &m.Recipient, &m.Body, &m.SentAt, &m.ReceivedAt, &m.ReplyTo, &m.Quote, &m.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse to chronological display order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// ---- Group messaging (issue #32) ----

// Group is a group's relay-side record.
type Group struct {
	ID          string
	Name        string
	Admin       string
	MemberEpoch int64
}

// GroupControlRecord is one stored membership-control message.
type GroupControlRecord struct {
	Action string
	Target string
	Admin  string
	Epoch  int64
	Sig    string
}

// GetGroup returns the group record, or (nil, nil) if it does not exist.
func (s *Store) GetGroup(groupID string) (*Group, error) {
	var g Group
	err := s.db.QueryRow(
		`SELECT group_id, name, admin, member_epoch FROM groups WHERE group_id = ?`,
		groupID,
	).Scan(&g.ID, &g.Name, &g.Admin, &g.MemberEpoch)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}
	return &g, nil
}

// IsGroupMember reports whether member is currently in the group roster.
func (s *Store) IsGroupMember(groupID, member string) (bool, error) {
	var one int
	err := s.db.QueryRow(
		`SELECT 1 FROM group_members WHERE group_id = ? AND member = ?`,
		groupID, member,
	).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("group member lookup: %w", err)
	}
	return true, nil
}

// GroupRoster returns the group's current member addresses, sorted.
func (s *Store) GroupRoster(groupID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT member FROM group_members WHERE group_id = ? ORDER BY member`,
		groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("group roster: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, fmt.Errorf("group roster scan: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ApplyGroupControl validates and applies one membership-control message
// in a transaction. Rules:
//
//   - create: the group must not exist; the signer becomes the initial
//     admin and sole member. epoch must be 1.
//   - add/remove/transfer-admin: the group must exist, the signer must be
//     the current admin, and epoch must be exactly member_epoch+1
//     (strict monotonicity; replays and reorderings are rejected).
//   - remove: target must be a current member and not the admin (transfer
//     adminship first).
//   - transfer-admin: target must be a current member.
func (s *Store) ApplyGroupControl(groupID, name, action, target, admin string, epoch int64, sig string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("group control tx: %w", err)
	}
	defer tx.Rollback()
	if action == envelope.GroupControlCreate {
		var exists int
		err := tx.QueryRow(`SELECT 1 FROM groups WHERE group_id = ?`, groupID).Scan(&exists)
		if err == nil {
			return fmt.Errorf("group %q already exists", groupID)
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("group lookup: %w", err)
		}
		if epoch != 1 {
			return fmt.Errorf("create control must have epoch 1, got %d", epoch)
		}
		if _, err := tx.Exec(
			`INSERT INTO groups(group_id, name, admin, member_epoch) VALUES (?, ?, ?, ?)`,
			groupID, name, admin, epoch,
		); err != nil {
			return fmt.Errorf("create group: %w", err)
		}
		if _, err := tx.Exec(
			`INSERT INTO group_members(group_id, member) VALUES (?, ?)`,
			groupID, admin,
		); err != nil {
			return fmt.Errorf("seed member: %w", err)
		}
	} else {
		var curAdmin string
		var curEpoch int64
		err := tx.QueryRow(
			`SELECT admin, member_epoch FROM groups WHERE group_id = ?`,
			groupID,
		).Scan(&curAdmin, &curEpoch)
		if err == sql.ErrNoRows {
			return fmt.Errorf("group %q does not exist", groupID)
		}
		if err != nil {
			return fmt.Errorf("group lookup: %w", err)
		}
		if admin != curAdmin {
			return fmt.Errorf("control must be signed by the group admin")
		}
		if epoch != curEpoch+1 {
			return fmt.Errorf("control epoch must be %d, got %d", curEpoch+1, epoch)
		}
		var one int
		targetMember := tx.QueryRow(
			`SELECT 1 FROM group_members WHERE group_id = ? AND member = ?`,
			groupID, target,
		).Scan(&one) == nil
		switch action {
		case envelope.GroupControlAdd:
			if targetMember {
				return fmt.Errorf("member %q is already in the group", target)
			}
			if _, err := tx.Exec(
				`INSERT INTO group_members(group_id, member) VALUES (?, ?)`,
				groupID, target,
			); err != nil {
				return fmt.Errorf("add member: %w", err)
			}
		case envelope.GroupControlRemove:
			if !targetMember {
				return fmt.Errorf("member %q is not in the group", target)
			}
			if target == curAdmin {
				return fmt.Errorf("cannot remove the admin; transfer adminship first")
			}
			if _, err := tx.Exec(
				`DELETE FROM group_members WHERE group_id = ? AND member = ?`,
				groupID, target,
			); err != nil {
				return fmt.Errorf("remove member: %w", err)
			}
		case envelope.GroupControlTransferAdmin:
			if !targetMember {
				return fmt.Errorf("member %q is not in the group", target)
			}
			if _, err := tx.Exec(
				`UPDATE groups SET admin = ? WHERE group_id = ?`,
				target, groupID,
			); err != nil {
				return fmt.Errorf("transfer admin: %w", err)
			}
		default:
			return fmt.Errorf("unknown group control action %q", action)
		}
		if _, err := tx.Exec(
			`UPDATE groups SET member_epoch = ? WHERE group_id = ?`,
			epoch, groupID,
		); err != nil {
			return fmt.Errorf("bump member epoch: %w", err)
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO group_controls(group_id, action, target, admin, epoch, sig)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		groupID, action, target, admin, epoch, sig,
	); err != nil {
		return fmt.Errorf("record control: %w", err)
	}
	return tx.Commit()
}

// GroupControls returns the group's membership-control feed in epoch
// order (capped at maxControls; controls are small but unbounded in
// principle).
func (s *Store) GroupControls(groupID string) ([]GroupControlRecord, error) {
	rows, err := s.db.Query(
		`SELECT action, target, admin, epoch, sig FROM group_controls
		 WHERE group_id = ? ORDER BY epoch ASC LIMIT 10000`,
		groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("group controls: %w", err)
	}
	defer rows.Close()
	var out []GroupControlRecord
	for rows.Next() {
		var c GroupControlRecord
		if err := rows.Scan(&c.Action, &c.Target, &c.Admin, &c.Epoch, &c.Sig); err != nil {
			return nil, fmt.Errorf("group controls scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GroupMaxEnvelopeID returns the highest envelope id stored for the
// group, or 0 if the group has no messages yet. Used as the join cursor
// handed to a newly added member.
func (s *Store) GroupMaxEnvelopeID(groupID string) (int64, error) {
	var id sql.NullInt64
	if err := s.db.QueryRow(
		`SELECT MAX(id) FROM envelopes WHERE recipient = ?`, groupID,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("group max id: %w", err)
	}
	if !id.Valid {
		return 0, nil
	}
	return id.Int64, nil
}
