// Package store persists encrypted envelopes for the Courier relay.
// The relay never sees plaintext: it stores opaque ciphertext addressed
// by recipient public key.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Suite      string // crypto suite id (issue #138); "" reads as SuiteV1
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
	key_epoch   INTEGER NOT NULL DEFAULT 0,
	suite       TEXT NOT NULL DEFAULT 'ed25519-x25519-naclbox-v1'
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
	signature  TEXT NOT NULL DEFAULT '',
	suite      TEXT NOT NULL DEFAULT 'ed25519-x25519-naclbox-v1'
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
	created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	-- issue #108: per-account login backoff (also added via migrate()
	-- for databases created before these columns existed).
	failed_logins     INTEGER NOT NULL DEFAULT 0,
	lock_until        INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dashboard_sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	expires_at INTEGER NOT NULL,
	-- issue #111: the session's raw synchronizer CSRF token
	-- (also added via migrate() for pre-existing databases).
	csrf_token TEXT NOT NULL DEFAULT ''
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

// ---------------------------------------------------------------------------
// Schema migrations (issue #104).
//
// The schema evolves through numbered, idempotent migrations recorded in the
// schema_migrations ledger table. Each migration runs inside its own
// transaction (BEGIN IMMEDIATE, via the _txlock=immediate DSN parameter, with
// rollback on failure), so a crash can only leave a migration fully applied
// or fully unapplied: reopening the database resumes and converges.
//
// Databases migrated by the pre-ledger code are adopted, never re-migrated:
// every migration declares how to detect its own completion (complete), and
// the runner records — without running — any migration whose effects are
// already present. A healthy database is therefore never failed closed and
// never has completed work re-applied.
//
// A ledger newer than this build (downgrade) fails closed: running against a
// schema the binary does not understand risks silent corruption.
//
// Conventions for adding a migration:
//   - append to the migrations list with the next version number;
//   - complete must accurately detect the post-state (tables, columns,
//     indexes, backfilled data);
//   - up must be idempotent: guard every step with the same existence checks
//     complete uses; never match error strings;
//   - set destructive=true only for migrations that drop or delete data: the
//     runner takes a VACUUM INTO backup first (see backupDatabase).
// ---------------------------------------------------------------------------

// schemaMigrationsDDL creates the ledger. It is installed by the migration
// runner preamble — not as a numbered migration — so adoption inspection can
// read and write it before any migration runs.
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations(
	version    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	source     TEXT NOT NULL DEFAULT 'ran', -- 'ran' | 'adopted'
	applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);`

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// execer is satisfied by *sql.DB and *sql.Tx.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func tableExists(q querier, table string) (bool, error) {
	var n int
	if err := q.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func columnExists(q querier, table, column string) (bool, error) {
	rows, err := q.Query(`PRAGMA table_info(` + quoteIdent(table) + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func indexExists(q querier, name string) (bool, error) {
	var n int
	if err := q.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// quoteIdent quotes a SQLite identifier. Table names here are internal
// constants, but quoting keeps the PRAGMA/ALTER statements safe by
// construction.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// migration is one numbered schema change.
type migration struct {
	version     int
	name        string
	destructive bool
	// complete reports whether the migration's effects are already present
	// (fresh installs report false; databases migrated by the pre-ledger
	// code or a partially applied migration being resumed report true).
	complete func(q querier) (bool, error)
	// up applies the change inside the runner's transaction. It must be
	// idempotent: guard every step with the same existence checks complete
	// uses. Never match error strings.
	up func(e execer, q querier) error
}

// addColumnMigration builds a migration that adds a single column.
// columnDef is the full column definition, e.g. "sig TEXT NOT NULL DEFAULT ”".
func addColumnMigration(version int, name, table, column, columnDef string) migration {
	return migration{
		version: version,
		name:    name,
		complete: func(q querier) (bool, error) {
			return columnExists(q, table, column)
		},
		up: func(e execer, q querier) error {
			has, err := columnExists(q, table, column)
			if err != nil {
				return err
			}
			if has {
				return nil
			}
			_, err = e.Exec(`ALTER TABLE ` + quoteIdent(table) + ` ADD COLUMN ` + columnDef)
			return err
		},
	}
}

// createTablesMigration builds a migration that creates tables and indexes.
func createTablesMigration(version int, name string, tables []string, ddls ...string) migration {
	return migration{
		version: version,
		name:    name,
		complete: func(q querier) (bool, error) {
			for _, t := range tables {
				ok, err := tableExists(q, t)
				if err != nil || !ok {
					return false, err
				}
			}
			return true, nil
		},
		up: func(e execer, _ querier) error {
			for _, ddl := range ddls {
				if _, err := e.Exec(ddl); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// migrations is the full ordered history. v1 is the base schema (the schema
// constant); v2+ are the incremental changes the old unversioned migrate()
// applied, in the same order, with identical DDL.
var migrations = []migration{
	{
		version: 1,
		name:    "base schema",
		complete: func(q querier) (bool, error) {
			for _, t := range []string{"envelopes", "keys", "dashboard_users", "dashboard_sessions", "dashboard_messages", "blobs"} {
				ok, err := tableExists(q, t)
				if err != nil || !ok {
					return false, err
				}
			}
			return true, nil
		},
		up: func(e execer, _ querier) error {
			_, err := e.Exec(schema)
			return err
		},
	},
	addColumnMigration(2, "envelopes.sig (v0.2.0+)", "envelopes", "sig", `sig TEXT NOT NULL DEFAULT ''`),
	addColumnMigration(3, "dashboard_messages.recipient (v0.6.5 threads)", "dashboard_messages", "recipient", `recipient TEXT NOT NULL DEFAULT ''`),
	addColumnMigration(4, "dashboard_messages.peer (v0.6.5 threads)", "dashboard_messages", "peer", `peer TEXT NOT NULL DEFAULT ''`),
	addColumnMigration(5, "dashboard_messages.reply_to (issue #51)", "dashboard_messages", "reply_to", `reply_to INTEGER NOT NULL DEFAULT 0`),
	addColumnMigration(6, "dashboard_messages.quote (issue #51)", "dashboard_messages", "quote", `quote TEXT NOT NULL DEFAULT ''`),
	addColumnMigration(7, "dashboard_messages.expires_at (issue #53)", "dashboard_messages", "expires_at", `expires_at INTEGER NOT NULL DEFAULT 0`),
	addColumnMigration(8, "keys.signature (v0.6.11 F1)", "keys", "signature", `signature TEXT NOT NULL DEFAULT ''`),
	{
		// v0.6.11 (F3): replay dedup. env_hash covers every
		// sender-controlled envelope field; the UNIQUE index makes
		// re-POSTed envelopes idempotent instead of duplicating delivery.
		version: 9,
		name:    "envelopes.env_hash replay-dedup (v0.6.11 F3)",
		complete: func(q querier) (bool, error) {
			has, err := columnExists(q, "envelopes", "env_hash")
			if err != nil || !has {
				return false, err
			}
			idx, err := indexExists(q, "idx_envelopes_env_hash")
			if err != nil || !idx {
				return false, err
			}
			var n int
			if err := q.QueryRow(`SELECT COUNT(*) FROM envelopes WHERE env_hash IS NULL`).Scan(&n); err != nil {
				return false, err
			}
			return n == 0, nil
		},
		up: func(e execer, q querier) error {
			has, err := columnExists(q, "envelopes", "env_hash")
			if err != nil {
				return err
			}
			if !has {
				if _, err := e.Exec(`ALTER TABLE "envelopes" ADD COLUMN env_hash TEXT`); err != nil {
					return err
				}
			}
			if err := backfillEnvelopeHashes(e, q); err != nil {
				return err
			}
			// Collapse pre-existing true duplicates (the identical envelope
			// stored twice before F3, e.g. a retried POST) before the UNIQUE
			// index goes on. Two rows with the same env_hash are the same
			// envelope — DedupHash covers every sender-controlled field, and
			// eph/nonce are random per message, so distinct messages cannot
			// share a hash short of breaking SHA-256. Keep the earliest copy
			// and drop the replay, exactly what Save's ON CONFLICT(env_hash)
			// DO NOTHING would have done had F3 existed at insert time. No
			// distinct message is lost. Failing here instead would brick the
			// upgrade: the migration rolls back and Open refuses to start.
			if err := dedupEnvelopeHashes(e); err != nil {
				return err
			}
			_, err = e.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_envelopes_env_hash ON envelopes(env_hash)`)
			return err
		},
	},
	addColumnMigration(10, "envelopes.kind (issue #32 groups)", "envelopes", "kind", `kind TEXT NOT NULL DEFAULT ''`),
	addColumnMigration(11, "envelopes.key_epoch (issue #32 groups)", "envelopes", "key_epoch", `key_epoch INTEGER NOT NULL DEFAULT 0`),
	createTablesMigration(12, "group messaging tables (issue #32)", []string{"groups", "group_members", "group_controls"},
		`CREATE TABLE IF NOT EXISTS groups(
			group_id     TEXT PRIMARY KEY,
			name         TEXT NOT NULL DEFAULT '',
			admin        TEXT NOT NULL,
			member_epoch INTEGER NOT NULL DEFAULT 1,
			created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')))`,
		`CREATE TABLE IF NOT EXISTS group_members(
			group_id TEXT NOT NULL,
			member   TEXT NOT NULL,
			PRIMARY KEY (group_id, member))`,
		`CREATE TABLE IF NOT EXISTS group_controls(
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			group_id   TEXT NOT NULL,
			action     TEXT NOT NULL,
			target     TEXT NOT NULL DEFAULT '',
			admin      TEXT NOT NULL,
			epoch      INTEGER NOT NULL,
			sig        TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
			UNIQUE(group_id, epoch))`,
	),
	createTablesMigration(13, "dashboard_seen per-thread read state (v0.6.9)", []string{"dashboard_seen"},
		`CREATE TABLE IF NOT EXISTS dashboard_seen(
			user_id      INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
			peer         TEXT NOT NULL,
			last_seen_id INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, peer))`,
	),
	{
		version: 14,
		name:    "spam_reports abuse metadata",
		complete: func(q querier) (bool, error) {
			ok, err := tableExists(q, "spam_reports")
			if err != nil || !ok {
				return false, err
			}
			return indexExists(q, "idx_spam_reports_sender")
		},
		up: func(e execer, _ querier) error {
			// Spam/abuse reports (metadata-only filtering). One row per
			// (sender, reporter) pair: only distinct reporters count toward
			// the throttle threshold, and re-reports are idempotent.
			// reported_at implements decay: only reports inside the
			// throttle window count.
			if _, err := e.Exec(`CREATE TABLE IF NOT EXISTS spam_reports(
				sender      TEXT NOT NULL,
				reporter    TEXT NOT NULL,
				envelope_id INTEGER NOT NULL,
				reported_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
				PRIMARY KEY (sender, reporter))`); err != nil {
				return err
			}
			_, err := e.Exec(`CREATE INDEX IF NOT EXISTS idx_spam_reports_sender
				ON spam_reports(sender, reported_at)`)
			return err
		},
	},
	{
		version: 15,
		name:    "directory contact-discovery (issue #39)",
		complete: func(q querier) (bool, error) {
			ok, err := tableExists(q, "directory")
			if err != nil || !ok {
				return false, err
			}
			return indexExists(q, "idx_directory_address")
		},
		up: func(e execer, _ querier) error {
			// Contact-discovery directory. One row per handle (handle is
			// the primary key: first-come-first-served). capabilities are
			// 0x00-joined tokens. tombstone marks an operator takedown: the
			// row stays so the handle cannot be re-registered and the
			// removal is visible (transparent takedown).
			if _, err := e.Exec(`CREATE TABLE IF NOT EXISTS directory(
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
			_, err := e.Exec(`CREATE INDEX IF NOT EXISTS idx_directory_address
				ON directory(address)`)
			return err
		},
	},
	// v0.8.0 (issue #39): transfer proof. When a handle is transferred, the
	// stored signature is the previous holder's transfer signature (not a
	// registration signature by the new owner), so the previous holder's
	// address is kept alongside it.
	addColumnMigration(16, "directory.transfer_from (v0.8.0, issue #39)", "directory", "transfer_from", `transfer_from TEXT NOT NULL DEFAULT ''`),
	createTablesMigration(17, "dashboard_peer_handles (issue #39)", []string{"dashboard_peer_handles"},
		`CREATE TABLE IF NOT EXISTS dashboard_peer_handles(
			user_id    INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
			peer       TEXT NOT NULL,
			handle     TEXT NOT NULL,
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
			PRIMARY KEY (user_id, peer))`,
	),
	createTablesMigration(18, "dashboard_peer_verified (issue #48)", []string{"dashboard_peer_verified"},
		`CREATE TABLE IF NOT EXISTS dashboard_peer_verified(
			user_id    INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
			peer       TEXT NOT NULL,
			status     TEXT NOT NULL,
			updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
			PRIMARY KEY (user_id, peer))`,
	),
	{
		// Optional Black Candle account linking (config-gated, off unless
		// the dashboard is started with the auth service configured).
		// bct_user_id is the authd user id, NULL when the dashboard user is
		// not linked. The unique index enforces one dashboard user per BCT
		// account; SQLite treats NULLs as distinct, so any number of
		// unlinked users is fine.
		version: 19,
		name:    "dashboard_users Black Candle account linking",
		complete: func(q querier) (bool, error) {
			for _, c := range []string{"bct_user_id", "bct_email"} {
				ok, err := columnExists(q, "dashboard_users", c)
				if err != nil || !ok {
					return false, err
				}
			}
			return indexExists(q, "idx_dashboard_users_bct_user_id")
		},
		up: func(e execer, q querier) error {
			for _, cc := range []struct{ column, def string }{
				{"bct_user_id", `bct_user_id INTEGER`},
				{"bct_email", `bct_email TEXT NOT NULL DEFAULT ''`},
			} {
				has, err := columnExists(q, "dashboard_users", cc.column)
				if err != nil {
					return err
				}
				if !has {
					if _, err := e.Exec(`ALTER TABLE "dashboard_users" ADD COLUMN ` + cc.def); err != nil {
						return err
					}
				}
			}
			_, err := e.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_users_bct_user_id ON dashboard_users(bct_user_id)`)
			return err
		},
	},
	{
		version: 20,
		name:    "dashboard login backoff columns and session CSRF token",
		complete: func(q querier) (bool, error) {
			for _, cc := range []struct{ table, column string }{
				{"dashboard_users", "failed_logins"},
				{"dashboard_users", "lock_until"},
				{"dashboard_sessions", "csrf_token"},
			} {
				ok, err := columnExists(q, cc.table, cc.column)
				if err != nil || !ok {
					return false, err
				}
			}
			return true, nil
		},
		up: func(e execer, q querier) error {
			for _, cc := range []struct{ table, column, def string }{
				{"dashboard_users", "failed_logins", `failed_logins INTEGER NOT NULL DEFAULT 0`},
				{"dashboard_users", "lock_until", `lock_until INTEGER NOT NULL DEFAULT 0`},
				{"dashboard_sessions", "csrf_token", `csrf_token TEXT NOT NULL DEFAULT ''`},
			} {
				has, err := columnExists(q, cc.table, cc.column)
				if err != nil {
					return err
				}
				if !has {
					if _, err := e.Exec(`ALTER TABLE "` + cc.table + `" ADD COLUMN ` + cc.def); err != nil {
						return err
					}
				}
			}
			// An early unreleased draft stored a SHA-256 digest in
			// csrf_hash; drop it best-effort if some dev database
			// still has it. Table/column are internal constants.
			if has, err := columnExists(q, "dashboard_sessions", "csrf_hash"); err != nil {
				return err
			} else if has {
				_, _ = e.Exec(`ALTER TABLE "dashboard_sessions" DROP COLUMN csrf_hash`)
			}
			return nil
		},
	},
	// issues #96/#97: bridged-message attribution. bridged is 1 when
	// the pushing agent derived the message as bridged in its inbox
	// path (pin list, payload metadata, or body banner); the dashboard
	// only displays it, like the other agent-reported fields. Old rows
	// default to 0; the dashboard view ORs the stored flag with the
	// body banner so pre-change pushes keep their badge.
	addColumnMigration(21, "dashboard_messages.bridged (issues #96/#97)", "dashboard_messages", "bridged", `bridged INTEGER NOT NULL DEFAULT 0`),
	// issue #95: dashboard admins may view the bridge audit log. The
	// column defaults to 0 (non-admin); the operator grants admin with
	// `courier dashboard set-admin <username>`.
	addColumnMigration(22, "dashboard_users.is_admin (issue #95)", "dashboard_users", "is_admin", `is_admin INTEGER NOT NULL DEFAULT 0`),
	// v23 (issue #138): the key directory records the crypto suite each
	// announcement belongs to. Existing rows predate suite tagging and are
	// SuiteV1 by construction (the relay only ever accepted v1 keys).
	addColumnMigration(23, "key directory crypto suite", "keys", "suite", `suite TEXT NOT NULL DEFAULT 'ed25519-x25519-naclbox-v1'`),
	// v24 (issue #138): envelopes record the crypto suite they were sealed
	// under, so recipients can dispatch to the right opener. Existing rows
	// predate suite tagging and are SuiteV1 by construction.
	addColumnMigration(24, "envelope crypto suite", "envelopes", "suite", `suite TEXT NOT NULL DEFAULT 'ed25519-x25519-naclbox-v1'`),
	createTablesMigration(25, "vhl_enrollments (issue #142)",
		[]string{"vhl_enrollments"},
		`CREATE TABLE IF NOT EXISTS vhl_enrollments(
			address        TEXT PRIMARY KEY,
			credential_id  TEXT NOT NULL,
			credential_pub TEXT NOT NULL,
			rp_id          TEXT NOT NULL,
			aaguid         TEXT NOT NULL DEFAULT '',
			epoch          INTEGER NOT NULL,
			signature      TEXT NOT NULL,
			published_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')))`,
	),
	{
		// v26 (issue #142 review): per-credential enrollment
		// publication. The v25 table keyed the whole publication on
		// (address), so publishing a second credential replaced the
		// first — one credential per identity, and revocation was
		// all-or-nothing. The new primary key is
		// (address, credential_id): each binding carries its own
		// strictly increasing epoch and its own revoked flag, so
		// credentials are published, rotated, and revoked
		// independently. Existing single rows migrate into
		// (address, credential_id) form with revoked=0. The old table
		// is dropped and renamed, so this migration is marked
		// destructive (the framework takes a pre-migration backup)
		// even though rows are preserved.
		version:     26,
		destructive: true,
		name:        "vhl_enrollments per-credential publication (issue #142)",
		complete: func(q querier) (bool, error) {
			return vhlEnrollmentsPerCredential(q)
		},
		up: func(e execer, q querier) error {
			done, err := vhlEnrollmentsPerCredential(q)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			if ok, err := tableExists(q, "vhl_enrollments"); err != nil {
				return err
			} else if !ok {
				// No table at all (v25 never ran): create the new
				// shape directly.
				_, err := e.Exec(`CREATE TABLE IF NOT EXISTS vhl_enrollments(
					address        TEXT NOT NULL,
					credential_id  TEXT NOT NULL,
					credential_pub TEXT NOT NULL,
					rp_id          TEXT NOT NULL,
					aaguid         TEXT NOT NULL DEFAULT '',
					epoch          INTEGER NOT NULL,
					signature      TEXT NOT NULL,
					published_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
					revoked        INTEGER NOT NULL DEFAULT 0,
					PRIMARY KEY (address, credential_id))`)
				return err
			}
			if _, err := e.Exec(`CREATE TABLE IF NOT EXISTS vhl_enrollments_new(
				address        TEXT NOT NULL,
				credential_id  TEXT NOT NULL,
				credential_pub TEXT NOT NULL,
				rp_id          TEXT NOT NULL,
				aaguid         TEXT NOT NULL DEFAULT '',
				epoch          INTEGER NOT NULL,
				signature      TEXT NOT NULL,
				published_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
				revoked        INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (address, credential_id))`); err != nil {
				return err
			}
			// Preserve every published binding; old rows predate
			// revocation and migrate as not revoked. Column lists
			// are explicit so the copy is exact either way.
			// NOTE: `has` is declared with := but `err` reuses the
			// outer variable — declaring err in the if-init would
			// scope it to the if/else chain and silently drop the
			// INSERT errors below (staticcheck SA4006).
			has, err := columnExists(q, "vhl_enrollments", "revoked")
			if err != nil {
				return err
			}
			if has {
				_, err = e.Exec(`INSERT OR IGNORE INTO vhl_enrollments_new
					(address, credential_id, credential_pub, rp_id, aaguid, epoch, signature, published_at, revoked)
					SELECT address, credential_id, credential_pub, rp_id, aaguid, epoch, signature, published_at, revoked
					FROM vhl_enrollments`)
			} else {
				_, err = e.Exec(`INSERT OR IGNORE INTO vhl_enrollments_new
					(address, credential_id, credential_pub, rp_id, aaguid, epoch, signature, published_at, revoked)
					SELECT address, credential_id, credential_pub, rp_id, aaguid, epoch, signature, published_at, 0
					FROM vhl_enrollments`)
			}
			if err != nil {
				return err
			}
			if _, err := e.Exec(`DROP TABLE vhl_enrollments`); err != nil {
				return err
			}
			_, err = e.Exec(`ALTER TABLE vhl_enrollments_new RENAME TO vhl_enrollments`)
			return err
		},
	},
}

// latestSchemaVersion is the newest migration version this build knows.
func latestSchemaVersion() int {
	return migrations[len(migrations)-1].version
}

// readLedger returns the set of migration versions recorded as applied.
func readLedger(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// testCrashAfterMigration is a test seam (cf. bridge.appendAuditFail): when
// non-zero, applyMigration aborts with errTestCrash after executing that
// migration's statements but before recording and committing it —
// simulating a kill mid-migration. Production code never sets it.
var testCrashAfterMigration int

var errTestCrash = errors.New("test seam: simulated crash mid-migration")

// runMigrations brings the database at path to the latest schema version.
// path is used for pre-destructive-migration backups.
func runMigrations(db *sql.DB, path string) error {
	return runMigrationsWith(db, path, migrations)
}

// runMigrationsWith applies migs in order. It takes the migration list so
// tests can exercise the runner (backups, interruption) with synthetic
// migrations; production always passes the global migrations list.
func runMigrationsWith(db *sql.DB, path string, migs []migration) error {
	if _, err := db.Exec(schemaMigrationsDDL); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := readLedger(db)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	latest := migs[len(migs)-1].version
	for v := range applied {
		if v > latest {
			return fmt.Errorf("database schema version %d is newer than this build supports (%d): refusing to open (downgrade is not supported)", v, latest)
		}
	}
	ranAny := false
	for i := range migs {
		m := &migs[i]
		if applied[m.version] {
			continue
		}
		done, err := m.complete(db)
		if err != nil {
			return fmt.Errorf("migration %d (%s) completion check: %w", m.version, m.name, err)
		}
		if m.destructive && !done {
			if err := backupDatabase(db, path); err != nil {
				return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
			}
		}
		if err := applyMigration(db, m, done); err != nil {
			return err
		}
		ranAny = true
	}
	// Integrity check after migrations changed something (issue #104).
	// PRAGMA quick_check validates b-tree structure without a full scan.
	if ranAny {
		if err := checkIntegrity(db); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration runs one migration inside its own transaction (BEGIN
// IMMEDIATE via the _txlock=immediate DSN parameter; rollback on failure).
// alreadyDone comes from the pre-transaction completion check and lets the
// runner adopt a migration without re-running it; the check is repeated
// inside the transaction so a concurrent migrator cannot cause a duplicate
// apply. The ledger row commits atomically with the migration, so a crash
// can only leave a migration fully applied or fully unapplied.
func applyMigration(db *sql.DB, m *migration, alreadyDone bool) error {
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("migration %d (%s) begin: %w", m.version, m.name, err)
	}
	defer tx.Rollback() // no-op after Commit
	done := alreadyDone
	if !done {
		done, err = m.complete(tx)
		if err != nil {
			return fmt.Errorf("migration %d (%s) completion check: %w", m.version, m.name, err)
		}
	}
	source := "adopted"
	if !done {
		source = "ran"
		if err := m.up(tx, tx); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
		if testCrashAfterMigration == m.version {
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, errTestCrash)
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, name, source) VALUES(?,?,?)`,
		m.version, m.name, source); err != nil {
		return fmt.Errorf("migration %d (%s) ledger: %w", m.version, m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %d (%s) commit: %w", m.version, m.name, err)
	}
	return nil
}

// backupDatabase writes a consistent snapshot of the database with VACUUM
// INTO (safe under WAL, requires no open transaction) before a destructive
// migration runs. The backup holds the same secrets as the live database:
// it is chmodded 0600 and covered by the same backup-permissions discipline
// as the live file (see enforceFilePerms). Backups are never deleted
// automatically; operators rotate them.
func backupDatabase(db *sql.DB, path string) error {
	backupPath := fmt.Sprintf("%s.bak-%d", path, time.Now().UnixNano())
	literal := "'" + strings.ReplaceAll(backupPath, "'", "''") + "'"
	if _, err := db.Exec(`VACUUM INTO ` + literal); err != nil {
		return fmt.Errorf("backup to %s: %w", backupPath, err)
	}
	if err := os.Chmod(backupPath, 0o600); err != nil {
		return fmt.Errorf("chmod backup %s: %w", backupPath, err)
	}
	return nil
}

// checkIntegrity fails closed unless PRAGMA quick_check reports a clean
// database.
func checkIntegrity(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA quick_check`)
	if err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return fmt.Errorf("integrity check: %w", err)
		}
		if msg != "ok" {
			return fmt.Errorf("integrity check failed: %s", msg)
		}
	}
	return rows.Err()
}

// dedupEnvelopeHashes drops replayed envelope copies ahead of the v0.6.11
// (F3) UNIQUE index: for each env_hash keep the earliest row (MIN(id)).
// A duplicate env_hash means a bit-identical envelope — DedupHash covers
// every sender-controlled field, and eph/nonce are random per message, so
// distinct messages cannot share a hash short of breaking SHA-256. The
// surviving row is the message; the dropped rows are replay copies the
// dedup feature would have refused at insert time. Idempotent: after one
// run no duplicates remain.
func dedupEnvelopeHashes(e execer) error {
	_, err := e.Exec(`DELETE FROM envelopes
		WHERE env_hash IS NOT NULL
		  AND id NOT IN (
		      SELECT MIN(id) FROM envelopes
		      WHERE env_hash IS NOT NULL
		      GROUP BY env_hash
		  )`)
	return err
}

// backfillEnvelopeHashes computes env_hash for envelopes stored before the
// v0.6.11 (F3) replay-dedup migration, so old messages are covered too.
func backfillEnvelopeHashes(e execer, q querier) error {
	rows, err := q.Query(`SELECT id, recipient, sender, eph, nonce, ct, sent_at, sig
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
		if _, err := e.Exec(`UPDATE envelopes SET env_hash = ? WHERE id = ?`, u.hash, u.id); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// File permissions (issue #103).
//
// The database holds dashboard password hashes, sessions, routing metadata
// and ciphertext blobs. It must never be readable by other local users:
//   - the parent directory is created (and kept) at 0700;
//   - the database file (and WAL sidecars) are kept at 0600;
//   - ownership is verified: a non-root process refuses a database owned by
//     someone else, since it could neither tighten its permissions nor trust
//     its current mode;
//   - anything that cannot be enforced fails closed with an actionable error
//     instead of running insecurely.
//
// Directory enforcement is deliberately conservative: a pre-existing
// directory with broad permissions fails closed rather than being chmodded
// unless every file in it belongs to this database (the file itself, its WAL
// sidecars, or its backups) — a shared directory may hold other users' files
// that a chmod would silently break. Keep the database in a dedicated
// directory (the relay and dashboard defaults do).
// The file itself is always tightened: it is unambiguously ours.
// ---------------------------------------------------------------------------

// prepareDatabaseDir creates the parent directory of path with 0700 and
// enforces the directory permissions policy. It runs before the database is
// opened so nothing sensitive is ever touched while reachable by others.
func prepareDatabaseDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create db dir %s: %w", dir, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat db dir %s: %w", dir, err)
	}
	if !ownedByProcess(fi) {
		return fmt.Errorf("db dir %s is not owned by the current user: refusing to open (issue #103)", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		onlyOurs, err := dirHoldsOnlyDatabaseFiles(dir, filepath.Base(path))
		if err != nil {
			return fmt.Errorf("stat db dir %s: %w", dir, err)
		}
		if !onlyOurs {
			return fmt.Errorf("db dir %s has overly broad permissions (%o): refusing to open — chmod it to 0700 or move the database to a dedicated directory (issue #103)", dir, fi.Mode().Perm())
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("db dir %s has overly broad permissions and chmod failed: %w", dir, err)
		}
	}
	return nil
}

// precreateDatabaseFile creates an empty database file with 0600 before
// SQLite first touches it, so a permissive umask can never leave even a
// momentary world-readable window. Existing files are left alone:
// enforceFilePerms tightens them after open.
func precreateDatabaseFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("create db file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create db file %s: %w", path, err)
	}
	return nil
}

// enforceFilePerms tightens the database file and any WAL sidecars to 0600
// after migrations, and verifies ownership. It runs after migrations so
// files SQLite creates along the way are covered too.
func enforceFilePerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat db file %s: %w", path, err)
	}
	if !ownedByProcess(fi) {
		return fmt.Errorf("db file %s is not owned by the current user: refusing to open (issue #103)", path)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := tightenFile(p); err != nil {
			return err
		}
	}
	return nil
}

func tightenFile(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", p, err)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(p, 0o600); err != nil {
		return fmt.Errorf("%s has overly broad permissions and chmod failed: %w", p, err)
	}
	return nil
}

// dirHoldsOnlyDatabaseFiles reports whether every entry in dir belongs to
// the database named base: the file itself, its WAL sidecars, or its
// pre-migration backups.
func dirHoldsOnlyDatabaseFiles(dir, base string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		n := e.Name()
		if n == base || n == base+"-wal" || n == base+"-shm" || strings.HasPrefix(n, base+".bak-") {
			continue
		}
		return false, nil
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Connection pragmas (issue #105).
//
// The relay and the dashboard are separate processes sharing one database
// file. WAL mode lets dashboard reads proceed while the relay writes (and
// vice versa); busy_timeout makes lock contention wait up to 5s instead of
// failing fast. Both are set on the DSN (like internal/bridge.OpenStore) and
// validated after open: running without them would silently reintroduce the
// database-locked stalls this fixes, so validation fails closed.
//
// Transactions are BEGIN IMMEDIATE (via _txlock) and kept short: every
// migration is its own transaction, and all statement paths are single
// statements or short read-modify-write sequences.
//
// Deeper work — isolating dashboard plaintext and moving blobs out of the
// hot database file (object storage), plus a PostgreSQL/sharded path — is
// tracked as follow-up in issue #105 and intentionally not built here.
// ---------------------------------------------------------------------------

// dsnFor builds the SQLite DSN for path: WAL journal mode, a 5s busy
// timeout, and immediate transaction locking.
func dsnFor(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate"
}

// validatePragmas fails closed unless WAL mode and the busy timeout actually
// took effect on the live connection.
func validatePragmas(db *sql.DB) error {
	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		return fmt.Errorf("read journal_mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("journal_mode is %q, want \"wal\": refusing to open (issue #105)", journalMode)
	}
	var busyTimeout int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		return fmt.Errorf("read busy_timeout: %w", err)
	}
	if busyTimeout != 5000 {
		return fmt.Errorf("busy_timeout is %d, want 5000: refusing to open (issue #105)", busyTimeout)
	}
	return nil
}

// Open opens (creating if needed) the SQLite database at path.
//
//   - #103: the parent directory is created/enforced at 0700 and the
//     database file (plus WAL sidecars) at 0600; ownership is verified and
//     anything unenforceable fails closed. Keep the database in a dedicated
//     directory.
//   - #104: the schema is brought current by numbered, idempotent,
//     transactional migrations recorded in schema_migrations. Databases
//     migrated by the pre-ledger code are adopted via schema inspection —
//     never re-migrated, never failed closed for being healthy.
//   - #105: the connection runs in WAL mode with a 5s busy timeout (both
//     validated); transactions are BEGIN IMMEDIATE and kept short.
func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve db path: %w", err)
	}
	if err := prepareDatabaseDir(abs); err != nil {
		return nil, err
	}
	if err := precreateDatabaseFile(abs); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsnFor(abs))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := runMigrations(db, abs); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrations: %w", err)
	}
	if err := enforceFilePerms(abs); err != nil {
		db.Close()
		return nil, err
	}
	if err := validatePragmas(db); err != nil {
		db.Close()
		return nil, err
	}
	// Issue #100: the blob quota ledger lives in blobquota.go so it
	// evolves independently of the core migrations (see #104, which is
	// reworking migrate() on another branch). This single call creates
	// and reconciles it.
	if err := ensureBlobQuotaSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("blob quota schema: %w", err)
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
		`INSERT INTO envelopes (recipient, sender, suite, eph, nonce, ct, sent_at, sig, env_hash, kind, key_epoch)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(env_hash) DO NOTHING`,
		e.To, e.From, e.Suite, e.Eph, e.Nonce, e.Ct, e.SentAt, e.Sig, h, e.Kind, e.KeyEpoch,
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
		`SELECT id, recipient, sender, suite, eph, nonce, ct, sent_at, received_at, sig, kind, key_epoch
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
		if err := rows.Scan(&e.ID, &e.To, &e.From, &e.Suite, &e.Eph, &e.Nonce, &e.Ct, &e.SentAt, &e.ReceivedAt, &e.Sig, &e.Kind, &e.KeyEpoch); err != nil {
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
// the envelope retention policy, and returns the freed bytes to the
// per-uploader quota ledger (issue #100). The quota-aware
// implementation lives in blobquota.go next to the ledger it updates;
// this wrapper keeps the signature stable for existing callers.
// Returns the number of rows deleted.
func (s *Store) PruneBlobs(retainDays int) (int64, error) {
	return pruneBlobsWithQuota(s.db, retainDays)
}

// KeyAnnouncement is one published encryption key for an address.
type KeyAnnouncement struct {
	Address   string
	Suite     string // crypto suite id (issue #138); "" reads as SuiteV1
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
		`INSERT INTO keys (address, suite, x25519_pub, epoch, signature) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(address) DO UPDATE SET suite = excluded.suite, x25519_pub = excluded.x25519_pub, epoch = excluded.epoch, signature = excluded.signature
		 WHERE excluded.epoch > keys.epoch`,
		k.Address, k.Suite, k.X25519Pub, k.Epoch, k.Sig,
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
		`SELECT address, suite, x25519_pub, epoch, signature FROM keys WHERE address = ?`,
		address,
	).Scan(&k.Address, &k.Suite, &k.X25519Pub, &k.Epoch, &k.Sig)
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
	// FailedLogins counts consecutive failed password logins; LockUntil
	// is the unix time until which password login is rejected (issue
	// #108 per-account exponential backoff).
	FailedLogins int
	LockUntil    int64
	// IsAdmin marks dashboard admins (issue #95). Admins may view the
	// bridge audit log at /admin/bridge/audit. Granted by the operator
	// with `courier dashboard set-admin <username>`; never self-serve.
	IsAdmin bool
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
	var isAdmin int
	var bctUserID sql.NullInt64
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange,
		&u.CourierAddress, &u.APITokenHash, &u.CreatedAt, &bctUserID, &u.BCTEmail,
		&u.FailedLogins, &u.LockUntil, &isAdmin)
	if err != nil {
		return nil, err
	}
	u.MustChange = mustChange != 0
	u.IsAdmin = isAdmin != 0
	if bctUserID.Valid {
		u.BCTUserID = bctUserID.Int64
	}
	return &u, nil
}

// dashboardUserColumns is the SELECT list for dashboard_users, kept in
// the scanDashboardUser order.
const dashboardUserColumns = `id, username, password_hash, must_change, courier_address, api_token_hash, created_at, bct_user_id, bct_email, failed_logins, lock_until, is_admin`

// DashboardUserByName looks up a user by username.
func (s *Store) DashboardUserByName(username string) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT `+dashboardUserColumns+` FROM dashboard_users WHERE username = ?`, username))
}

// DashboardUserByTokenHash looks up a user by the SHA256 of their API token.
func (s *Store) DashboardUserByTokenHash(tokenHash string) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT `+dashboardUserColumns+` FROM dashboard_users WHERE api_token_hash = ?`, tokenHash))
}

// DashboardUserByBCTUserID looks up the dashboard user linked to a Black
// Candle authd account, or sql.ErrNoRows when no user linked it.
func (s *Store) DashboardUserByBCTUserID(bctUserID int64) (*DashboardUser, error) {
	return scanDashboardUser(s.db.QueryRow(
		`SELECT `+dashboardUserColumns+` FROM dashboard_users WHERE bct_user_id = ?`, bctUserID))
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

// SetDashboardAdmin grants or revokes dashboard admin rights (issue
// #95). Admins may view the bridge audit log. Admin rights are never
// self-serve: only the operator (via `courier dashboard set-admin`)
// can grant them. It returns false when no user has that username.
func (s *Store) SetDashboardAdmin(username string, admin bool) (bool, error) {
	v := 0
	if admin {
		v = 1
	}
	res, err := s.db.Exec(`UPDATE dashboard_users SET is_admin = ? WHERE username = ?`, v, username)
	if err != nil {
		return false, fmt.Errorf("set admin: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("set admin: %w", err)
	}
	return n > 0, nil
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

// CreateSession stores a login session token (by its SHA256 hash) along
// with the raw synchronizer CSRF token issued for it (issue #111).
func (s *Store) CreateSession(tokenHash string, userID int64, ttl time.Duration, csrfToken string) error {
	_, err := s.db.Exec(
		`INSERT INTO dashboard_sessions (token_hash, user_id, expires_at, csrf_token)
		 VALUES (?, ?, strftime('%s','now') + ?, ?)`,
		tokenHash, userID, int64(ttl.Seconds()), csrfToken)
	return err
}

// SessionCSRFToken returns the raw synchronizer CSRF token stored on a
// session, or sql.ErrNoRows when the session does not exist. Empty when
// the session predates CSRF tokens.
func (s *Store) SessionCSRFToken(tokenHash string) (string, error) {
	var t string
	err := s.db.QueryRow(`SELECT csrf_token FROM dashboard_sessions WHERE token_hash = ?`,
		tokenHash).Scan(&t)
	return t, err
}

// LoginBackoff returns the account lockout after n consecutive failed
// logins: base * 2^(n-1), capped at max. Pure function, unit-tested via
// the dashboard package.
func LoginBackoff(n int, base, max time.Duration) time.Duration {
	if n < 1 {
		n = 1
	}
	d := base
	for i := 1; i < n; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	if d > max {
		return max
	}
	return d
}

// NoteLoginFailure records one failed password login for username: the
// consecutive-failure counter grows by one and the account locks for
// the exponential backoff (issue #108). The read-modify-write runs in
// one transaction so concurrent failures cannot clobber each other's
// counters. Unknown usernames are a no-op — the row simply does not
// exist.
func (s *Store) NoteLoginFailure(username string, base, max time.Duration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var failures int
	err = tx.QueryRow(`SELECT failed_logins FROM dashboard_users WHERE username = ?`,
		username).Scan(&failures)
	if err == sql.ErrNoRows {
		return nil // unknown username: no-op
	}
	if err != nil {
		return err
	}
	failures++
	lockUntil := time.Now().Add(LoginBackoff(failures, base, max)).Unix()
	if _, err := tx.Exec(`UPDATE dashboard_users SET failed_logins = ?, lock_until = ?
		WHERE username = ?`, failures, lockUntil, username); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearLoginFailures resets the backoff counters after a successful
// login.
func (s *Store) ClearLoginFailures(userID int64) error {
	_, err := s.db.Exec(
		`UPDATE dashboard_users SET failed_logins = 0, lock_until = 0 WHERE id = ?`,
		userID)
	return err
}

// SessionUser returns the user for a session token hash, or sql.ErrNoRows.
func (s *Store) SessionUser(tokenHash string) (*DashboardUser, error) {
	var u DashboardUser
	var mustChange int
	var isAdmin int
	var bctUserID sql.NullInt64
	err := s.db.QueryRow(
		`SELECT u.id, u.username, u.password_hash, u.must_change, u.courier_address, u.api_token_hash, u.created_at, u.bct_user_id, u.bct_email, u.failed_logins, u.lock_until, u.is_admin
		 FROM dashboard_sessions s JOIN dashboard_users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > strftime('%s','now')`,
		tokenHash).Scan(&u.ID, &u.Username, &u.PasswordHash, &mustChange,
		&u.CourierAddress, &u.APITokenHash, &u.CreatedAt, &bctUserID, &u.BCTEmail,
		&u.FailedLogins, &u.LockUntil, &isAdmin)
	if err != nil {
		return nil, err
	}
	u.MustChange = mustChange != 0
	u.IsAdmin = isAdmin != 0
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
	// Bridged marks messages the pushing agent derived as bridged
	// (issues #96/#97): arrived via a non-E2E bridge, untrusted input.
	// Stored at push time; read paths surface it for the badge.
	Bridged bool
}

// SaveDashboardMessage stores a pushed message; duplicates (same user +
// courier id) are ignored. It reports whether the row was actually
// inserted. peer is the counterparty address: the sender for inbound
// messages, the recipient for outbound ones. replyTo/quote carry
// reply threading metadata (issue #51); expiresAt is the issue #53
// disappearing-message expiry, 0 for messages that never expire;
// bridged marks messages the agent derived as bridged (issues #96/#97)
// — the dashboard displays it, never derives it.
func (s *Store) SaveDashboardMessage(userID, courierID int64, sender, recipient, peer, body string, sentAt, receivedAt, replyTo int64, quote string, expiresAt int64, bridged bool) (bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO dashboard_messages
		 (user_id, courier_id, sender, recipient, peer, body, sent_at, received_at, reply_to, quote, expires_at, bridged)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, courierID, sender, recipient, peer, body, sentAt, receivedAt, replyTo, quote, expiresAt, bridged)
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
	// LastBridged marks threads whose latest message arrived via a
	// non-E2E bridge (issues #96/#97), as reported by the pushing
	// agent. The dashboard view ORs it with the body banner.
	LastBridged bool
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
		`SELECT p, body, sender, cnt, ts, bridged FROM (
		   SELECT `+tpeer+` AS p, t.body AS body, t.sender AS sender,
		          COUNT(*) OVER (PARTITION BY `+tpeer+`) AS cnt,
		          COALESCE(t.sent_at, t.received_at) AS ts,
		          t.bridged AS bridged,
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
		var bridged int64
		if err := lrows.Scan(&th.Peer, &th.LastBody, &sender, &th.Count, &th.LastTS, &bridged); err != nil {
			return nil, err
		}
		th.LastBridged = bridged != 0
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
		`SELECT id, courier_id, sender, recipient, body, sent_at, received_at, reply_to, quote, expires_at, bridged
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
		var bridged int64
		if err := rows.Scan(&m.ID, &m.CourierID, &m.Sender, &m.Recipient, &m.Body, &m.SentAt, &m.ReceivedAt, &m.ReplyTo, &m.Quote, &m.ExpiresAt, &bridged); err != nil {
			return nil, err
		}
		m.Bridged = bridged != 0
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
