package store

// Tests for issues #103 (file permissions), #104 (versioned migrations) and
// #105 (WAL + busy_timeout).

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/black-candle-technologies/courier/internal/envelope"
	_ "modernc.org/sqlite"
)

func ledgerRows(t *testing.T, s *Store) map[int]string {
	t.Helper()
	rows, err := s.db.Query(`SELECT version, source FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var v int
		var src string
		if err := rows.Scan(&v, &src); err != nil {
			t.Fatal(err)
		}
		out[v] = src
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMigrationsNumberedContiguously(t *testing.T) {
	for i, m := range migrations {
		if m.version != i+1 {
			t.Fatalf("migrations[%d] has version %d, want %d", i, m.version, i+1)
		}
		if m.name == "" {
			t.Fatalf("migration %d has no name", m.version)
		}
	}
	if latestSchemaVersion() != len(migrations) {
		t.Fatalf("latestSchemaVersion() = %d, want %d", latestSchemaVersion(), len(migrations))
	}
}

func TestFreshOpenRunsAllMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ledger := ledgerRows(t, s)
	if len(ledger) != len(migrations) {
		t.Fatalf("ledger has %d rows, want %d", len(ledger), len(migrations))
	}
	// v1 (base schema) always runs on a fresh database. Other migrations
	// either run or are adopted when the base schema already carries their
	// effects — both are recorded honestly.
	if src := ledger[1]; src != "ran" {
		t.Fatalf("migration 1 source = %q, want %q", src, "ran")
	}
	for _, m := range migrations {
		src, ok := ledger[m.version]
		if !ok {
			t.Fatalf("migration %d not recorded", m.version)
		}
		if src != "ran" && src != "adopted" {
			t.Fatalf("migration %d source = %q, want ran|adopted", m.version, src)
		}
		// Every migration's post-state holds after open: the schema converged.
		done, err := m.complete(s.db)
		if err != nil {
			t.Fatal(err)
		}
		if !done {
			t.Fatalf("migration %d (%s) incomplete after open", m.version, m.name)
		}
	}
	// The database is usable.
	id, stored, err := s.Save(testEnvelope())
	if err != nil || !stored || id == 0 {
		t.Fatalf("save after fresh open: id=%d stored=%v err=%v", id, stored, err)
	}
	s.Close()

	// A second open is a no-op: the ledger is unchanged, nothing re-runs.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if ledger2 := ledgerRows(t, s2); len(ledger2) != len(ledger) {
		t.Fatalf("second open changed ledger: %d -> %d rows", len(ledger), len(ledger2))
	}
}

func TestInterruptedMigrationConverges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interrupt.db")

	// Simulate a kill after migration 9's statements executed but before
	// its commit: the transaction must roll back.
	testCrashAfterMigration = 9
	_, err := Open(path)
	testCrashAfterMigration = 0
	if !errors.Is(err, errTestCrash) {
		t.Fatalf("expected simulated crash, got: %v", err)
	}

	// The crashed migration left no trace: its unique index is absent and no
	// ledger row was recorded. (The env_hash column itself comes from v1's
	// base schema, not from v9 — v9's own work is the index.)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := indexExists(raw, "idx_envelopes_env_hash")
	if err != nil {
		t.Fatal(err)
	}
	if idx {
		t.Fatal("interrupted migration must roll back: unique index must be absent")
	}
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 9`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("interrupted migration must roll back: ledger row must be absent")
	}
	// Migrations 1-8 did commit with their ledger rows.
	if err := raw.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("ledger has %d rows after crash, want 8", n)
	}
	raw.Close()

	// "Restart": the new code resumes from the ledger and converges.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after interrupted migration: %v", err)
	}
	defer s.Close()
	ledger := ledgerRows(t, s)
	if len(ledger) != len(migrations) {
		t.Fatalf("ledger has %d rows after resume, want %d", len(ledger), len(migrations))
	}
	if src := ledger[9]; src != "ran" {
		t.Fatalf("migration 9 source after resume = %q, want %q", src, "ran")
	}
	if _, _, err := s.Save(testEnvelope()); err != nil {
		t.Fatalf("save after resume: %v", err)
	}
}

func TestAdoptLegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build a database exactly the way the old code did: plain open, base
	// schema exec, unversioned migrate().
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if err := legacyMigrate(raw); err != nil {
		t.Fatal(err)
	}
	// Seed data the new code must preserve.
	if _, err := raw.Exec(`INSERT INTO envelopes(recipient, sender, eph, nonce, ct, sent_at, sig, env_hash)
		VALUES('ed25519:to','ed25519:from','e','n','c',1700000000,'s','legacyhash')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// The new code must open it without re-running migrations or failing.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open adopted legacy db: %v", err)
	}
	defer s.Close()

	ledger := ledgerRows(t, s)
	if len(ledger) != len(migrations) {
		t.Fatalf("ledger has %d rows, want %d (all adopted)", len(ledger), len(migrations))
	}
	for _, m := range migrations {
		if src := ledger[m.version]; src != "adopted" {
			t.Fatalf("migration %d source = %q, want %q", m.version, src, "adopted")
		}
	}
	// Seeded data survived.
	list, err := s.List("ed25519:to", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Ct != "c" {
		t.Fatalf("legacy envelope not preserved: %+v", list)
	}
	// New writes work and the dedup index is live.
	id, stored, err := s.Save(testEnvelope())
	if err != nil || !stored || id == 0 {
		t.Fatalf("save on adopted db: id=%d stored=%v err=%v", id, stored, err)
	}
	if _, stored, err := s.Save(testEnvelope()); err != nil || stored {
		t.Fatalf("dedup on adopted db: stored=%v err=%v, want stored=false", stored, err)
	}
}

func TestAdoptPartialLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial9.db")

	// Simulate an old-code crash between ADD COLUMN env_hash and the
	// backfill: the column exists, values are NULL, the unique index was
	// never created. (The schema constant already carries the column.)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO envelopes(recipient, sender, eph, nonce, ct, sent_at, sig)
		VALUES('ed25519:to','ed25519:from','e','n','c',1700000000,'s')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open partially migrated db: %v", err)
	}
	defer s.Close()

	// The backfill ran: no NULL hashes remain and the unique index exists.
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM envelopes WHERE env_hash IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d envelopes still lack env_hash after open", n)
	}
	ok, err := indexExists(s.db, "idx_envelopes_env_hash")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("idx_envelopes_env_hash missing after open")
	}
	var hash string
	if err := s.db.QueryRow(`SELECT env_hash FROM envelopes`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	want := envelope.DedupHash("ed25519:to", "ed25519:from", "e", "n", 1700000000, "c", "s")
	if hash != want {
		t.Fatalf("backfilled env_hash = %q, want %q", hash, want)
	}
}

// Migration 9 must not fail on pre-existing true duplicates (issue #134):
// two bit-identical envelopes collapse to the earliest copy, mirroring
// Save's ON CONFLICT(env_hash) DO NOTHING, and no distinct message is lost.
func TestMigration9DedupsReplayedEnvelopes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dupes9.db")

	// Pre-v0.6.11 shape: no env_hash column. Two bit-identical rows (an
	// exact replay, e.g. a retried POST) plus one distinct envelope.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE envelopes (
		id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL,
		sender TEXT NOT NULL, eph TEXT NOT NULL, nonce TEXT NOT NULL,
		ct TEXT NOT NULL, sent_at INTEGER NOT NULL,
		received_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		sig TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO envelopes(recipient, sender, eph, nonce, ct, sent_at, sig)
		VALUES('ed25519:to','ed25519:from','e','n',?,1700000000,'s')`
	for _, ct := range []string{"c", "c", "other"} {
		if _, err := raw.Exec(insert, ct); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	// Migration must succeed, not brick the upgrade on the replay.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open db with replayed envelopes: %v", err)
	}
	defer s.Close()

	// The replay collapsed to the earliest copy: rows 1 and 3 survive.
	type row struct {
		id   int64
		ct   string
		hash string
	}
	rows, err := s.db.Query(`SELECT id, ct, env_hash FROM envelopes ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ct, &r.hash); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		got = append(got, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].id != 1 || got[1].id != 3 {
		t.Fatalf("surviving rows = %+v, want ids [1 3]", got)
	}
	if got[0].hash == "" || got[1].hash == "" || got[0].hash == got[1].hash {
		t.Fatalf("bad backfilled hashes: %+v", got)
	}
	want := envelope.DedupHash("ed25519:to", "ed25519:from", "e", "n", 1700000000, "c", "s")
	if got[0].hash != want {
		t.Fatalf("survivor hash = %q, want %q", got[0].hash, want)
	}

	// Idempotent: a second open is a fixed point.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	s2.Close()
}

func TestDowngradeRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "downgrade.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	future := latestSchemaVersion() + 1
	if _, err := s.db.Exec(`INSERT INTO schema_migrations(version, name, source) VALUES(?,?,?)`,
		future, "future migration", "ran"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = Open(path)
	if err == nil || !strings.Contains(err.Error(), "newer than this build") {
		t.Fatalf("expected downgrade refusal, got: %v", err)
	}
}

func TestBackupBeforeDestructiveMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "destruct.db")
	synth := []migration{
		{
			version: 1,
			name:    "create sentinel table",
			complete: func(q querier) (bool, error) {
				return tableExists(q, "t_backup_sentinel")
			},
			up: func(e execer, _ querier) error {
				if _, err := e.Exec(`CREATE TABLE t_backup_sentinel(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
					return err
				}
				_, err := e.Exec(`INSERT INTO t_backup_sentinel(v) VALUES('sentinel')`)
				return err
			},
		},
		{
			version:     2,
			name:        "drop sentinel table",
			destructive: true,
			complete: func(q querier) (bool, error) {
				ok, err := tableExists(q, "t_backup_sentinel")
				return !ok, err
			},
			up: func(e execer, _ querier) error {
				_, err := e.Exec(`DROP TABLE t_backup_sentinel`)
				return err
			},
		},
	}
	db, err := sql.Open("sqlite", dsnFor(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := runMigrationsWith(db, path, synth); err != nil {
		t.Fatal(err)
	}
	// The destructive migration ran...
	if ok, _ := tableExists(db, "t_backup_sentinel"); ok {
		t.Fatal("destructive migration did not run")
	}
	// ...but a 0600 backup was taken first and it holds the data.
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("want exactly 1 backup file, got %d: %v", len(matches), matches)
	}
	fi, err := os.Stat(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup perms = %o, want 0600", fi.Mode().Perm())
	}
	bak, err := sql.Open("sqlite", matches[0])
	if err != nil {
		t.Fatal(err)
	}
	defer bak.Close()
	var v string
	if err := bak.QueryRow(`SELECT v FROM t_backup_sentinel`).Scan(&v); err != nil {
		t.Fatalf("backup missing sentinel data: %v", err)
	}
	if v != "sentinel" {
		t.Fatalf("backup sentinel = %q, want %q", v, "sentinel")
	}
}

func TestOpenEnforcesPermissionsUnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "sub", "db.sqlite") // sub does not exist yet
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if fi, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Fatalf("db dir perms = %o, want 0700", fi.Mode().Perm())
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("db file perms = %o, want 0600", fi.Mode().Perm())
	}
}

func TestOpenTightensExistingFileAndDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.sqlite")
	// Pre-existing file with broad permissions, as a permissive umask and
	// the old code would have left it.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Pre-existing dir holding only the database is tightened too.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("db file perms = %o, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Fatalf("db dir perms = %o, want 0700", fi.Mode().Perm())
	}
}

func TestOpenRefusesSharedWorldReadableDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.sqlite")
	// A directory shared with other files must not be chmodded out from
	// under them: fail closed instead.
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path)
	if err == nil || !strings.Contains(err.Error(), "overly broad permissions") {
		t.Fatalf("expected permissions refusal, got: %v", err)
	}
}

func TestWALAndBusyTimeoutEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var journalMode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	var busyTimeout int
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", busyTimeout)
	}
	// Exercise a write, then check any WAL sidecars are restricted too.
	if _, _, err := s.Save(testEnvelope()); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		fi, err := os.Stat(sidecar)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("sidecar %s perms = %o: group/other bits must be clear", sidecar, fi.Mode().Perm())
		}
	}
}

// legacyMigrate is a verbatim copy of the pre-ledger migrate() from
// internal/store/store.go (as of the parent commit of this change), kept to
// construct old-code databases in adoption tests. It is test-only code.
func legacyMigrate(db *sql.DB) error {
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
	// issues #96/#97: bridged-message attribution. bridged is 1 when
	// the pushing agent derived the message as bridged in its inbox
	// path (pin list, payload metadata, or body banner); the dashboard
	// only displays it, like the other agent-reported fields. Old rows
	// default to 0; the dashboard view ORs the stored flag with the
	// body banner so pre-change pushes keep their badge.
	if err := addColumn(`ALTER TABLE dashboard_messages ADD COLUMN bridged INTEGER NOT NULL DEFAULT 0`); err != nil {
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
	if err := backfillEnvelopeHashes(db, db); err != nil {
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
	// issue #95: dashboard admins may view the bridge audit log. The
	// column defaults to 0 (non-admin); the operator grants admin with
	// `courier dashboard set-admin <username>`.
	if err := addColumn(`ALTER TABLE dashboard_users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	// issue #142: VHL enrollment directory. One row per Courier
	// address: the signed identity→credential binding the agent
	// published after its WebAuthn enrollment ceremony. The epoch is
	// strictly increasing per address so stale re-publications are
	// no-ops (same pattern as the key directory).
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS vhl_enrollments(
		address        TEXT PRIMARY KEY,
		credential_id  TEXT NOT NULL,
		credential_pub TEXT NOT NULL,
		rp_id          TEXT NOT NULL,
		aaguid         TEXT NOT NULL DEFAULT '',
		epoch          INTEGER NOT NULL,
		signature      TEXT NOT NULL,
		published_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')))`); err != nil {
		return err
	}
	return nil
}

// Issue #138 / PR #141 review (P0): the suite migrations must be numbered
// 23/24, not 21/22 — current main already uses v21
// (dashboard_messages.bridged) and v22 (dashboard_users.is_admin). A
// database upgraded to current main carries ledger rows 21/22; had the
// suite migrations kept those numbers they would have been skipped as
// already-applied and the suite columns never added, while a merged list
// with duplicate versions would collide on the ledger primary key. This
// test builds a v22 database (suite columns and their ledger rows
// removed), inserts pre-suite rows, re-opens, and asserts both columns
// are added and backfilled with the SuiteV1 default.
func TestSuiteMigrationsUpgradeFromV22(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v22.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a database that stopped at current-main v22: drop the
	// suite columns the v23/v24 migrations add and remove their ledger
	// rows, so the re-open below exercises the real upgrade path.
	for _, ddl := range []string{
		`ALTER TABLE keys DROP COLUMN suite`,
		`ALTER TABLE envelopes DROP COLUMN suite`,
		`DELETE FROM schema_migrations WHERE version IN (23, 24)`,
	} {
		if _, err := s.db.Exec(ddl); err != nil {
			s.Close()
			t.Skipf("cannot simulate v22 schema: %v", err)
		}
	}
	// Pre-suite rows, written exactly as the v22 code wrote them (no
	// suite column involved).
	if _, err := s.db.Exec(
		`INSERT INTO keys (address, x25519_pub, epoch, signature)
		 VALUES ('ed25519:alice', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 1000, 'sig')`,
	); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO envelopes (recipient, sender, eph, nonce, ct, sent_at, sig)
		 VALUES ('ed25519:bob', 'ed25519:alice', 'eph', 'nonce', 'ct', 1000, 'sig')`,
	); err != nil {
		s.Close()
		t.Fatal(err)
	}
	s.Close()

	// Re-open: migrations 23/24 must run (not be skipped) and backfill.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open after v22: %v", err)
	}
	defer s2.Close()

	ledger := ledgerRows(t, s2)
	for _, v := range []int{23, 24} {
		if src := ledger[v]; src != "ran" {
			t.Fatalf("migration %d source = %q, want %q (must run, not be skipped as already-applied)", v, src, "ran")
		}
	}
	const wantSuite = "ed25519-x25519-naclbox-v1"
	var keySuite string
	if err := s2.db.QueryRow(`SELECT suite FROM keys WHERE address = 'ed25519:alice'`).Scan(&keySuite); err != nil {
		t.Fatal(err)
	}
	if keySuite != wantSuite {
		t.Fatalf("keys.suite backfill = %q, want %q", keySuite, wantSuite)
	}
	var envSuite string
	if err := s2.db.QueryRow(`SELECT suite FROM envelopes WHERE sender = 'ed25519:alice'`).Scan(&envSuite); err != nil {
		t.Fatal(err)
	}
	if envSuite != wantSuite {
		t.Fatalf("envelopes.suite backfill = %q, want %q", envSuite, wantSuite)
	}
}
