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
`

// migrate adds columns introduced after the table was first created.
// Old rows keep empty defaults; v0.2.0+ always writes sig.
func migrate(db *sql.DB) error {
	_, err := db.Exec(`ALTER TABLE envelopes ADD COLUMN sig TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
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
