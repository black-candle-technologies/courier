package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/envelope"
)

// fuzzOldRow is one envelope row inserted into a simulated pre-migration
// database; fields carry arbitrary bytes.
type fuzzOldRow struct {
	to, from, eph, nonce, ct, sig string
	sentAt                        int64
}

// splitFuzzOldRows deterministically derives up to 4 envelope rows from
// the fuzz input: the first byte picks the row count, the rest is dealt
// round-robin across the six TEXT fields, and sent_at is derived from
// field lengths (covering negative, zero, and large values).
func splitFuzzOldRows(data []byte) []fuzzOldRow {
	nrows := 1
	rest := data
	if len(data) > 0 {
		nrows = 1 + int(data[0]%4)
		rest = data[1:]
	}
	bufs := make([][]byte, nrows*6)
	for i, b := range rest {
		bufs[i%len(bufs)] = append(bufs[i%len(bufs)], b)
	}
	rows := make([]fuzzOldRow, nrows)
	for r := 0; r < nrows; r++ {
		f := make([]string, 6)
		for c := 0; c < 6; c++ {
			f[c] = string(bufs[r*6+c])
		}
		rows[r] = fuzzOldRow{
			to: f[0], from: f[1], eph: f[2], nonce: f[3], ct: f[4], sig: f[5],
			sentAt: int64(len(bufs[r*6])) - int64(len(bufs[r*6+1])),
		}
	}
	return rows
}

// FuzzMigrateOldSchemaDB simulates pre-v0.6.11 relay databases (no
// env_hash column, the shape TestMigrateBackfillsEnvHash covers) filled
// with fuzzed envelope rows, then runs the production migration path via
// Open. Invariants: migration never fails and never panics on arbitrary
// row bytes; every row gets env_hash == DedupHash(...) backfilled;
// migration is idempotent (a second Open is a fixed point); no distinct
// envelope is lost — exact replays (identical rows) collapse to a single
// row, mirroring Save's ON CONFLICT(env_hash) DO NOTHING.
func FuzzMigrateOldSchemaDB(f *testing.F) {
	f.Add([]byte("hello")) // one row of short fields
	f.Add([]byte{})        // one row of empty fields
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "old.db")
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		// Old schema: no env_hash (also predates kind/key_epoch and the
		// group tables, exercising those migration branches too).
		if _, err := db.Exec(`CREATE TABLE envelopes (
			id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL,
			sender TEXT NOT NULL, eph TEXT NOT NULL, nonce TEXT NOT NULL,
			ct TEXT NOT NULL, sent_at INTEGER NOT NULL,
			received_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
			sig TEXT NOT NULL DEFAULT '')`); err != nil {
			t.Fatal(err)
		}
		rows := splitFuzzOldRows(data)
		for _, r := range rows {
			if _, err := db.Exec(`INSERT INTO envelopes
				(recipient, sender, eph, nonce, ct, sent_at, sig)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				r.to, r.from, r.eph, r.nonce, r.ct, r.sentAt, r.sig); err != nil {
				t.Fatal(err)
			}
		}
		db.Close()

		s, err := Open(path)
		if err != nil {
			t.Fatalf("migrate failed for %d fuzzed rows: %v", len(rows), err)
		}
		qrows, err := s.db.Query(`SELECT recipient, sender, eph, nonce, ct, sent_at, sig, env_hash
			FROM envelopes ORDER BY id`)
		if err != nil {
			s.Close()
			t.Fatal(err)
		}
		count := 0
		for qrows.Next() {
			var to, from, eph, nonce, ct, sig, hash string
			var sentAt int64
			if err := qrows.Scan(&to, &from, &eph, &nonce, &ct, &sentAt, &sig, &hash); err != nil {
				qrows.Close()
				s.Close()
				t.Fatal(err)
			}
			want := envelope.DedupHash(to, from, eph, nonce, sentAt, ct, sig)
			if hash != want {
				qrows.Close()
				s.Close()
				t.Fatalf("row %d: env_hash %q, want DedupHash %q", count, hash, want)
			}
			count++
		}
		qrows.Close()
		if err := qrows.Err(); err != nil {
			s.Close()
			t.Fatal(err)
		}
		// Exact replays collapse to one row (see migration 9), so the
		// expected row count is the number of distinct envelope hashes.
		distinct := make(map[string]struct{})
		for _, r := range rows {
			distinct[envelope.DedupHash(r.to, r.from, r.eph, r.nonce, r.sentAt, r.ct, r.sig)] = struct{}{}
		}
		if count != len(distinct) {
			s.Close()
			t.Fatalf("migration lost distinct envelopes: have %d, want %d (from %d rows)",
				count, len(distinct), len(rows))
		}
		s.Close()

		// Migration must be idempotent: a second Open is a fixed point.
		s2, err := Open(path)
		if err != nil {
			t.Fatalf("second migrate failed: %v", err)
		}
		s2.Close()
	})
}

// unescapeLike reverses escapeLike, for the round-trip property below.
func unescapeLike(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// FuzzEscapeLike feeds arbitrary strings to the LIKE-pattern escaper
// used by dashboard search (SearchThreadPeers) and the directory
// prefix search. Invariants: never panic; escaping round-trips
// (unescape(escape(s)) == s), so no input can smuggle a LIKE wildcard
// or the escape character itself past the ESCAPE '\' clause.
func FuzzEscapeLike(f *testing.F) {
	f.Add("hello")
	f.Add("100%")
	f.Add("under_score")
	f.Add(`back\slash`)
	f.Add(`\%_all`)
	f.Add("")
	f.Add("%%__\\\\")
	f.Add("trailing\\")
	f.Fuzz(func(t *testing.T, s string) {
		if unescapeLike(escapeLike(s)) != s {
			t.Fatalf("escapeLike(%q) = %q does not round-trip", s, escapeLike(s))
		}
	})
}

// fuzzSearchUser creates a dashboard user and a few messages with
// wildcard-hostile bodies for the SearchThreadPeers fuzz target.
func fuzzSearchUser(s *Store, t *testing.T) int64 {
	t.Helper()
	u, err := s.CreateDashboardUser("fuzzuser", "hash", "ed25519:addr", "tokenhash")
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{"hello world", "100% legit", "under_score test", `back\slash`, "prefix hello suffix"}
	for i, b := range bodies {
		if _, err := s.SaveDashboardMessage(u.ID, int64(i+1), "ed25519:sender", "", "ed25519:peer",
			b, 1780000000, 1780000000, 0, "", 0, false); err != nil {
			t.Fatal(err)
		}
	}
	return u.ID
}

// FuzzSearchThreadPeers feeds arbitrary search strings (the dashboard
// thread-search box) to SearchThreadPeers over a seeded message set.
// Invariants: never error, never panic, results are a subset of the
// seeded peers, and the search is deterministic.
func FuzzSearchThreadPeers(f *testing.F) {
	f.Add("hello")
	f.Add("100%")
	f.Add("_")
	f.Add(`\`)
	f.Add("")
	f.Add("%hello%")
	f.Fuzz(func(t *testing.T, q string) {
		s, err := Open(t.TempDir() + "/test.db")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		uid := fuzzSearchUser(s, t)
		got1, err := s.SearchThreadPeers(uid, q)
		if err != nil {
			t.Fatalf("SearchThreadPeers(%q) error: %v", q, err)
		}
		for _, p := range got1 {
			if p != "ed25519:peer" {
				t.Fatalf("SearchThreadPeers(%q) returned unexpected peer %q", q, p)
			}
		}
		got2, err := s.SearchThreadPeers(uid, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(got1) != len(got2) {
			t.Fatalf("SearchThreadPeers(%q) not deterministic: %v vs %v", q, got1, got2)
		}
	})
}
