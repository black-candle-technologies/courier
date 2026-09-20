// Persistent state for the bridge gateway (issue #61): ingest tokens,
// the hash-chained audit log, and confirmation records. All in one
// SQLite database (bridge.db), following the internal/store pattern
// (modernc.org/sqlite, database/sql). The database file must be
// root/operator-only (0600); it holds token hashes (never raw tokens)
// and audit metadata (never message bodies).
package bridge

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// schemaVersion is the bridge.db schema version, stored in the kv
// table. Bumped if the schema ever changes incompatibly.
const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS kv(
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens(
  id          TEXT PRIMARY KEY,
  label       TEXT NOT NULL,
  token_hash  TEXT NOT NULL UNIQUE,
  allowlist   TEXT NOT NULL,            -- JSON array of ed25519:... addresses
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,        -- unix seconds; 0 = never expires
  revoked_at  INTEGER NOT NULL DEFAULT 0,
  rotated_from TEXT NOT NULL DEFAULT '', -- id of the token this replaces
  last_used_at INTEGER NOT NULL DEFAULT 0,
  send_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
CREATE TABLE IF NOT EXISTS audit(
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  token_id    TEXT NOT NULL,
  token_label TEXT NOT NULL,
  recipient   TEXT NOT NULL,
  body_sha256 TEXT NOT NULL,
  body_size   INTEGER NOT NULL,
  outcome     TEXT NOT NULL,           -- sent | rejected:<reason> | confirmation_requested
  envelope_id INTEGER NOT NULL DEFAULT 0,
  reason      TEXT NOT NULL DEFAULT '',
  prev_hash   TEXT NOT NULL,
  row_hash    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS confirmations(
  token_id    TEXT NOT NULL,
  recipient   TEXT NOT NULL,
  confirmed_at INTEGER NOT NULL,
  PRIMARY KEY(token_id, recipient)
);
CREATE TABLE IF NOT EXISTS pending_confirmations(
  token       TEXT PRIMARY KEY,        -- hex SHA-256 of the raw confirm token
  token_id    TEXT NOT NULL,
  recipient   TEXT NOT NULL,
  body_sha256 TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
`

// Store is the gateway's persistent state.
type Store struct {
	db *sql.DB
	// mu serializes audit-chain appends and finalizes so concurrent
	// ingests cannot read the same chain head and fork the chain (F2).
	// All Store users live in one process (the gateway; the CLI never
	// appends), so a process-local mutex is sufficient.
	mu sync.Mutex
}

// OpenStore opens (creating if needed) the bridge database at path.
// The parent directory is created with 0700 and the file is kept at
// 0600: it holds token hashes and audit metadata.
func OpenStore(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create bridge db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open bridge db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init bridge schema: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("chmod bridge db: %w", err)
	}
	s := &Store{db: db}
	if err := s.checkSchemaVersion(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) checkSchemaVersion() error {
	var v string
	err := s.db.QueryRow(`SELECT v FROM kv WHERE k='schema_version'`).Scan(&v)
	switch {
	case err == sql.ErrNoRows:
		_, err = s.db.Exec(`INSERT INTO kv(k,v) VALUES('schema_version',?)`, fmt.Sprint(schemaVersion))
		return err
	case err != nil:
		return fmt.Errorf("read schema version: %w", err)
	}
	if v != fmt.Sprint(schemaVersion) {
		return fmt.Errorf("bridge.db schema version %s: this build wants %d (no automatic migration)", v, schemaVersion)
	}
	return nil
}
