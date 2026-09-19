// Package store persists encrypted envelopes for the Courier relay.
// The relay never sees plaintext: it stores opaque ciphertext addressed
// by recipient public key.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Envelope is one stored message, ciphertext only.
type Envelope struct {
	ID         int64
	To         string // v0.2.0+ "ed25519:<base64url>" address
	From       string // sender address (signature-authenticated in v0.2.0+)
	Eph        string // base64url ephemeral X25519 public key
	Nonce      string // base64url nonce
	Ct         string // base64url ciphertext
	SentAt     int64  // unix seconds, sender's clock
	ReceivedAt int64  // unix seconds, relay's clock
	Sig        string // base64url Ed25519 signature (v0.2.0+)
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
	sig         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_envelopes_recipient ON envelopes(recipient, id);

-- v0.5.0: signed encryption-key announcements. One row per address: the
-- current X25519 encryption key the owner published (courier rotate).
-- Senders look this up before sealing; if absent they fall back to the
-- address-derived key.
CREATE TABLE IF NOT EXISTS keys (
	address    TEXT PRIMARY KEY,
	x25519_pub TEXT NOT NULL,
	epoch      INTEGER NOT NULL
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
	UNIQUE(user_id, courier_id)
);
CREATE INDEX IF NOT EXISTS idx_dashboard_messages_user ON dashboard_messages(user_id, courier_id);
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
	// v0.6.9: per-thread read state for unread badges.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS dashboard_seen(
		user_id      INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
		peer         TEXT NOT NULL,
		last_seen_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, peer))`); err != nil {
		return err
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

// Save stores an envelope and returns its id.
func (s *Store) Save(e *Envelope) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO envelopes (recipient, sender, eph, nonce, ct, sent_at, sig)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.To, e.From, e.Eph, e.Nonce, e.Ct, e.SentAt, e.Sig,
	)
	if err != nil {
		return 0, fmt.Errorf("insert: %w", err)
	}
	return res.LastInsertId()
}

// List returns up to limit envelopes for recipient with id > after,
// oldest first.
func (s *Store) List(recipient string, after int64, limit int) ([]Envelope, error) {
	rows, err := s.db.Query(
		`SELECT id, recipient, sender, eph, nonce, ct, sent_at, received_at, sig
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
		if err := rows.Scan(&e.ID, &e.To, &e.From, &e.Eph, &e.Nonce, &e.Ct, &e.SentAt, &e.ReceivedAt, &e.Sig); err != nil {
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

// KeyAnnouncement is one published encryption key for an address.
type KeyAnnouncement struct {
	Address   string
	X25519Pub string // base64url 32-byte X25519 public key
	Epoch     int64  // unix seconds of rotation; strictly increasing
}

// SaveKey stores a key announcement, replacing the previous one only if the
// epoch is strictly greater. Returns false if the announcement was stale.
func (s *Store) SaveKey(k *KeyAnnouncement) (bool, error) {
	var cur int64
	err := s.db.QueryRow(`SELECT epoch FROM keys WHERE address = ?`, k.Address).Scan(&cur)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("query key: %w", err)
	}
	if err == nil && k.Epoch <= cur {
		return false, nil // stale or replayed announcement
	}
	if _, err := s.db.Exec(
		`INSERT INTO keys (address, x25519_pub, epoch) VALUES (?, ?, ?)
		 ON CONFLICT(address) DO UPDATE SET x25519_pub = excluded.x25519_pub, epoch = excluded.epoch`,
		k.Address, k.X25519Pub, k.Epoch,
	); err != nil {
		return false, fmt.Errorf("save key: %w", err)
	}
	return true, nil
}

// GetKey returns the current key announcement for an address, or
// sql.ErrNoRows if the owner never published one.
func (s *Store) GetKey(address string) (*KeyAnnouncement, error) {
	var k KeyAnnouncement
	err := s.db.QueryRow(
		`SELECT address, x25519_pub, epoch FROM keys WHERE address = ?`,
		address,
	).Scan(&k.Address, &k.X25519Pub, &k.Epoch)
	if err != nil {
		return nil, err
	}
	return &k, nil
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
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange,
		&u.CourierAddress, &u.APITokenHash, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.MustChange = mustChange != 0
	return &u, nil
}

// DashboardUserByName looks up a user by username.
func (s *Store) DashboardUserByName(username string) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT id, username, password_hash, must_change, courier_address, api_token_hash, created_at
		 FROM dashboard_users WHERE username = ?`, username))
}

// DashboardUserByTokenHash looks up a user by the SHA256 of their API token.
func (s *Store) DashboardUserByTokenHash(tokenHash string) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT id, username, password_hash, must_change, courier_address, api_token_hash, created_at
		 FROM dashboard_users WHERE api_token_hash = ?`, tokenHash))
}

// SetDashboardPassword replaces the password hash and clears must_change.
func (s *Store) SetDashboardPassword(userID int64, passwordHash string) error {
	_, err := s.db.Exec(
		`UPDATE dashboard_users SET password_hash = ?, must_change = 0 WHERE id = ?`,
		passwordHash, userID)
	return err
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
	err := s.db.QueryRow(
		`SELECT u.id, u.username, u.password_hash, u.must_change, u.courier_address, u.api_token_hash, u.created_at
		 FROM dashboard_sessions s JOIN dashboard_users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > strftime('%s','now')`,
		tokenHash).Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange,
		&u.CourierAddress, &u.APITokenHash, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.MustChange = mustChange != 0
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
}

// SaveDashboardMessage stores a pushed message; duplicates (same user +
// courier id) are ignored. It reports whether the row was actually
// inserted. peer is the counterparty address: the sender for inbound
// messages, the recipient for outbound ones.
func (s *Store) SaveDashboardMessage(userID, courierID int64, sender, recipient, peer, body string, sentAt, receivedAt int64) (bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO dashboard_messages
		 (user_id, courier_id, sender, recipient, peer, body, sent_at, received_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, courierID, sender, recipient, peer, body, sentAt, receivedAt)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// peerExpr resolves the counterparty of a message row. Rows written before
// v0.6.5 have no peer value; those are all inbound, so sender is the peer.
const peerExpr = `COALESCE(NULLIF(peer,''), sender)`

// DashboardThread is one conversation: all messages exchanged with a
// single counterparty address.
type DashboardThread struct {
	Peer     string
	Count    int64
	LastTS   int64
	LastBody string
	LastOut  bool  // the latest message was sent by the user
	Unread   int64 // inbound messages newer than the user's last visit
}

// DashboardThreads returns the user's threads, most recently active first.
func (s *Store) DashboardThreads(userID int64, userAddr string, limit int) ([]DashboardThread, error) {
	// tpeer is the thread key qualified for the inner table alias.
	const tpeer = `COALESCE(NULLIF(t.peer,''), t.sender)`
	rows, err := s.db.Query(
		`SELECT p, body, sender, cnt, ts, unread FROM (
		   SELECT `+tpeer+` AS p, t.body AS body, t.sender AS sender,
		          COUNT(*) OVER (PARTITION BY `+tpeer+`) AS cnt,
		          COALESCE(t.sent_at, t.received_at) AS ts,
		          COALESCE((SELECT COUNT(*) FROM dashboard_messages m
		                    WHERE m.user_id = ?
		                      AND COALESCE(NULLIF(m.peer,''), m.sender) = `+tpeer+`
		                      AND m.sender != ?
		                      AND m.id > COALESCE((SELECT s.last_seen_id FROM dashboard_seen s
		                                          WHERE s.user_id = ? AND s.peer = `+tpeer+`), 0)), 0) AS unread,
		          ROW_NUMBER() OVER (PARTITION BY `+tpeer+`
		                             ORDER BY COALESCE(t.sent_at, t.received_at) DESC, t.id DESC) AS rn
		   FROM dashboard_messages t WHERE t.user_id = ?
		 ) WHERE rn = 1 ORDER BY ts DESC, p ASC LIMIT ?`,
		userID, userAddr, userID, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DashboardThread
	for rows.Next() {
		var th DashboardThread
		var sender string
		if err := rows.Scan(&th.Peer, &th.LastBody, &sender, &th.Count, &th.LastTS, &th.Unread); err != nil {
			return nil, err
		}
		th.LastOut = sender == userAddr
		out = append(out, th)
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
func (s *Store) DashboardThreadMessages(userID int64, peer string, limit int) ([]DashboardMessage, error) {
	rows, err := s.db.Query(
		`SELECT id, courier_id, sender, recipient, body, sent_at, received_at
		 FROM dashboard_messages
		 WHERE user_id = ? AND `+peerExpr+` = ?
		 ORDER BY COALESCE(sent_at, received_at) ASC, id ASC LIMIT ?`,
		userID, peer, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DashboardMessage
	for rows.Next() {
		var m DashboardMessage
		if err := rows.Scan(&m.ID, &m.CourierID, &m.Sender, &m.Recipient, &m.Body, &m.SentAt, &m.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
