// Hash-chained audit log for the bridge gateway (issue #61).
//
// Every ingest — sent or rejected — appends one or more metadata-only
// rows: who (token label), what (recipient, body SHA-256, size), when,
// and the outcome. Message bodies are NEVER logged; the log is a
// metadata record, not a message archive.
//
// Rows are IMMUTABLE once appended: the chain writer (AppendAudit) is
// the only mutator, and it only ever inserts. A send is recorded as a
// pair of chained events — send_reserved (appended before the relay
// round-trip so the wire metadata can reference its row id) and then
// sent or rejected:send_failed (appended after, linked to the reserved
// row via send_ref). Immutability is what keeps the chain correct
// under concurrency: the old reserve-then-rewrite design let a
// concurrent append link prev_hash to a reserved row_hash that
// finalization then rewrote, forking the chain (issue #81). Mutable
// operational state (in-flight sends) lives outside the chained
// record entirely — in memory in the gateway, never in the audit
// table.
//
// Each row stores prev_hash (the previous row's hash) and row_hash =
// SHA-256 over the full row content, so `courier bridge audit --verify`
// detects tampering or gaps. Retention pruning (default 1 year, per the
// user-confirmed plan) deletes old rows; the verifier reports the prune
// point explicitly instead of crying "gap."
//
// Threat model (F3): the chain detects accidental corruption and
// tampering by anyone who cannot rewrite the whole database. It does
// NOT defend against a privileged attacker with write access to
// bridge.db — they can recompute a consistent chain and `audit
// --verify` will pass. Treat verification as tamper-evidence against
// unsophisticated tampering, not as proof against a compromised host.
// A future improvement is anchoring the chain head somewhere external
// (even a log line shipped off-host) on a schedule.
package bridge

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// Audit outcomes.
const (
	OutcomeSent                 = "sent"
	OutcomeConfirmationRequired = "confirmation_requested"
	// OutcomeSendReserved is the immutable event appended before the
	// relay round-trip. The wire message's BridgeMeta.AuditID references
	// this row. After the round-trip the gateway appends a second
	// immutable event (OutcomeSent, or rejected:send_failed) linked to
	// this one via SendRef.
	OutcomeSendReserved = "send_reserved"
)

// RejectedOutcome builds the outcome string for a rejected ingest.
func RejectedOutcome(reason string) string { return "rejected:" + reason }

// Rejection reasons (logged, never echoed with secrets).
const (
	RejectUnauthorized = "unauthorized" // bad/expired/revoked token
	RejectTooLarge     = "body_too_large"
	RejectForbidden    = "not_allowlisted"
	RejectBadRequest   = "bad_request"
	RejectRateLimited  = "rate_limited"
	RejectSendFailed   = "send_failed"
)

// DefaultAuditRetention is the user-confirmed 1-year retention.
const DefaultAuditRetention = 365 * 24 * time.Hour

// AuditEntry is one audit row. Rows are immutable once appended:
// AppendAudit is the only writer and it only inserts. SendRef links a
// send's completion event (sent / rejected:send_failed) back to its
// send_reserved row; it is operational metadata and is deliberately
// NOT part of row_hash, so linking never affects chain verification.
type AuditEntry struct {
	ID         int64
	Ts         int64
	TokenID    string
	TokenLabel string
	Recipient  string
	BodySHA256 string
	BodySize   int64
	Outcome    string
	EnvelopeID int64
	Reason     string
	SendRef    string
	PrevHash   string
	RowHash    string
}

// hashRow computes the chain hash over the row's content. The row id
// is deliberately excluded: it is assigned by the insert after the
// hash is computed, and chain order is already implicit in prev_hash
// links.
func hashRow(prevHash string, e *AuditEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%s|%s|%s|%d|%s|%d|%s",
		prevHash, e.Ts, e.TokenID, e.TokenLabel, e.Recipient,
		e.BodySHA256, e.BodySize, e.Outcome, e.EnvelopeID, e.Reason)
	return hex.EncodeToString(h.Sum(nil))
}

// lastHash returns the row_hash of the latest audit row, or "" if empty.
func (s *Store) lastHash() (string, error) {
	var h string
	err := s.db.QueryRow(`SELECT row_hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return h, err
}

// AppendAudit appends one IMMUTABLE audit row, chaining its hash to
// the previous row. It is the only writer of the audit table. Appends
// are serialized on the store mutex so two concurrent ingests cannot
// read the same chain head and fork the chain (F2). Because rows are
// never updated after insert, no interleaving of appends — however the
// gateway interleaves reserves, sends, and completion events — can
// break VerifyAudit (issue #81). It returns the new row id.
func (s *Store) AppendAudit(e *AuditEntry) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.appendAuditFail != nil {
		if err := s.appendAuditFail(e); err != nil {
			return 0, err
		}
	}
	prev, err := s.lastHash()
	if err != nil {
		return 0, fmt.Errorf("audit chain head: %w", err)
	}
	e.PrevHash = prev
	e.RowHash = hashRow(prev, e)
	res, err := s.db.Exec(
		`INSERT INTO audit(ts,token_id,token_label,recipient,body_sha256,body_size,outcome,envelope_id,reason,send_ref,prev_hash,row_hash)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Ts, e.TokenID, e.TokenLabel, e.Recipient, e.BodySHA256, e.BodySize,
		e.Outcome, e.EnvelopeID, e.Reason, e.SendRef, e.PrevHash, e.RowHash,
	)
	if err != nil {
		return 0, fmt.Errorf("append audit: %w", err)
	}
	return res.LastInsertId()
}

// VerifyAudit walks the whole chain and reports whether every row's
// hash recomputes and every prev_hash links to its predecessor. It
// returns the number of rows checked and the lowest row id present (so
// callers can see a prune point: firstID > 1 means old rows were
// pruned, which is expected, not tampering).
func (s *Store) VerifyAudit() (ok bool, checked int64, firstID int64, err error) {
	rows, err := s.db.Query(
		`SELECT id,ts,token_id,token_label,recipient,body_sha256,body_size,outcome,envelope_id,reason,send_ref,prev_hash,row_hash
		 FROM audit ORDER BY id ASC`,
	)
	if err != nil {
		return false, 0, 0, fmt.Errorf("read audit: %w", err)
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Ts, &e.TokenID, &e.TokenLabel, &e.Recipient, &e.BodySHA256,
			&e.BodySize, &e.Outcome, &e.EnvelopeID, &e.Reason, &e.SendRef, &e.PrevHash, &e.RowHash); err != nil {
			return false, checked, firstID, fmt.Errorf("scan audit: %w", err)
		}
		if checked == 0 {
			firstID = e.ID
			// A pruned chain starts mid-history; the first surviving
			// row's prev_hash points at a deleted row, which is
			// expected. Only link-check from the second row on.
		} else if e.PrevHash != prev {
			return false, checked, firstID, nil
		}
		if hashRow(e.PrevHash, &e) != e.RowHash {
			return false, checked, firstID, nil
		}
		prev = e.RowHash
		checked++
	}
	return true, checked, firstID, rows.Err()
}

// PruneAudit deletes audit rows older than olderThan (unix seconds)
// and returns how many were removed. The next VerifyAudit reports the
// prune point via firstID.
func (s *Store) PruneAudit(olderThan int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit WHERE ts < ?`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("prune audit: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// AuditFilter filters audit listing.
type AuditFilter struct {
	TokenLabel string
	Outcome    string // exact match, e.g. "sent" or "rejected:rate_limited"
	Limit      int
}

// ListAudit returns audit rows, newest first, honoring the filter.
func (s *Store) ListAudit(f AuditFilter) ([]*AuditEntry, error) {
	q := `SELECT id,ts,token_id,token_label,recipient,body_sha256,body_size,outcome,envelope_id,reason,send_ref,prev_hash,row_hash
	      FROM audit WHERE 1=1`
	var args []any
	if f.TokenLabel != "" {
		q += ` AND token_label=?`
		args = append(args, f.TokenLabel)
	}
	if f.Outcome != "" {
		q += ` AND outcome=?`
		args = append(args, f.Outcome)
	}
	q += ` ORDER BY id DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Ts, &e.TokenID, &e.TokenLabel, &e.Recipient, &e.BodySHA256,
			&e.BodySize, &e.Outcome, &e.EnvelopeID, &e.Reason, &e.SendRef, &e.PrevHash, &e.RowHash); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// SHA256Hex is the body-hash helper for audit rows.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
