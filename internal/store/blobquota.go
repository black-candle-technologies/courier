package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// This file implements the durable per-uploader blob storage quota for
// issue #100: total stored blob bytes per uploader identity within the
// retention window, enforced atomically at upload time and released
// when retention pruning deletes blobs.
//
// The quota ledger lives in its own table (blob_quotas), declared and
// applied here — deliberately NOT in the shared schema const or
// migrate() in store.go — so quota storage evolves independently of the
// core envelope/key/dashboard migrations (issue #104 is reworking those
// migrations on another branch; store.go carries only a one-line
// ensureBlobQuotaSchema call in Open plus a PruneBlobs delegation).
// The ledger is always a cache of SUM(blobs.size) per uploader: charges
// happen in the same transaction as the blob insert, releases in the
// same transaction as the prune delete, and Open reconciles the ledger
// against the blobs actually stored, so the quota survives relay
// restarts against databases that predate it.

// ErrBlobQuotaExceeded is returned by SaveBlobWithQuota when storing the
// blob would push the uploader's stored bytes past their quota. Handlers
// should surface it as an explicit 429: the uploader's bytes free up as
// retention pruning deletes their expired blobs.
var ErrBlobQuotaExceeded = errors.New("blob storage quota exceeded")

const blobQuotaSchema = `
CREATE TABLE IF NOT EXISTS blob_quotas (
	uploader   TEXT PRIMARY KEY,
	used_bytes INTEGER NOT NULL DEFAULT 0
);`

// ensureBlobQuotaSchema creates the quota ledger and reconciles it with
// the blobs actually stored, so a relay restarted against an old
// database adopts the true stored bytes per uploader instead of
// granting everyone a fresh allowance. Uploaders already tracked keep
// their counters only insofar as they match reality: the ledger is
// rewritten from the blobs table, which is the durable source of truth.
func ensureBlobQuotaSchema(db *sql.DB) error {
	if _, err := db.Exec(blobQuotaSchema); err != nil {
		return fmt.Errorf("create blob_quotas: %w", err)
	}
	if _, err := db.Exec(`
		INSERT INTO blob_quotas (uploader, used_bytes)
		SELECT uploader, COALESCE(SUM(size), 0) FROM blobs GROUP BY uploader
		ON CONFLICT(uploader) DO UPDATE SET used_bytes = excluded.used_bytes`); err != nil {
		return fmt.Errorf("reconcile blob_quotas: %w", err)
	}
	return nil
}

// BlobQuotaUsage returns the uploader's currently stored blob bytes, or
// 0 for an uploader with no quota row yet.
func (s *Store) BlobQuotaUsage(uploader string) (int64, error) {
	var used int64
	err := s.db.QueryRow(`SELECT used_bytes FROM blob_quotas WHERE uploader = ?`, uploader).Scan(&used)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("blob quota usage: %w", err)
	}
	return used, nil
}

// SaveBlobWithQuota stores a blob and charges its size against the
// uploader's quota in one transaction, so concurrent uploads cannot
// overdraw the quota between the check and the insert. The duplicate
// check comes first: idempotent re-uploads of an existing blob_id
// return stored=false without touching the quota — even when the
// uploader is over quota, since those bytes were already charged. Only
// genuinely new blobs are quota-gated, and a rejected upload stores
// nothing: the blob row and the quota charge are one atomic unit. The
// rejection error wraps ErrBlobQuotaExceeded.
func (s *Store) SaveBlobWithQuota(b *Blob, quotaBytes int64) (stored bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("blob quota tx: %w", err)
	}
	// Rollback is a no-op after a successful Commit; it also undoes the
	// blob insert when the quota check below rejects the upload.
	defer tx.Rollback()

	res, err := tx.Exec(
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
	if n == 0 {
		// Duplicate blob_id: an idempotent replay, not a second
		// blob — acknowledge it without charging the quota.
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("blob quota tx: %w", err)
		}
		return false, nil
	}
	var used int64
	qerr := tx.QueryRow(`SELECT used_bytes FROM blob_quotas WHERE uploader = ?`, b.Uploader).Scan(&used)
	switch {
	case qerr == sql.ErrNoRows:
		used = 0
	case qerr != nil:
		return false, fmt.Errorf("read blob quota: %w", qerr)
	}
	if used+b.Size > quotaBytes {
		return false, fmt.Errorf("%w: uploader has %d of %d bytes stored",
			ErrBlobQuotaExceeded, used, quotaBytes)
	}
	if _, err := tx.Exec(
		`INSERT INTO blob_quotas (uploader, used_bytes) VALUES (?, ?)
		 ON CONFLICT(uploader) DO UPDATE SET used_bytes = used_bytes + excluded.used_bytes`,
		b.Uploader, b.Size,
	); err != nil {
		return false, fmt.Errorf("charge blob quota: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("blob quota tx: %w", err)
	}
	return true, nil
}

// pruneBlobsWithQuota deletes blobs received more than retainDays ago
// and returns their bytes to the uploader quotas in the same
// transaction, so pruning can never leak quota. It is the quota-aware
// backend for Store.PruneBlobs; store.go delegates to it so the pruning
// logic lives next to the ledger it updates.
func pruneBlobsWithQuota(db *sql.DB, retainDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retainDays).Unix()
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("prune blobs tx: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT uploader, SUM(size) FROM blobs WHERE received_at < ? GROUP BY uploader`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune blobs: %w", err)
	}
	freed := make(map[string]int64)
	for rows.Next() {
		var uploader string
		var bytes int64
		if err := rows.Scan(&uploader, &bytes); err != nil {
			rows.Close()
			return 0, fmt.Errorf("prune blobs: %w", err)
		}
		freed[uploader] += bytes
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("prune blobs: %w", err)
	}
	rows.Close()

	res, err := tx.Exec(`DELETE FROM blobs WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune blobs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune blobs: %w", err)
	}
	for uploader, bytes := range freed {
		// Clamp at zero: defensive against any path that ever
		// releases without a matching charge.
		if _, err := tx.Exec(
			`UPDATE blob_quotas
			 SET used_bytes = CASE WHEN used_bytes < ? THEN 0 ELSE used_bytes - ? END
			 WHERE uploader = ?`,
			bytes, bytes, uploader,
		); err != nil {
			return 0, fmt.Errorf("release blob quota: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("prune blobs tx: %w", err)
	}
	return n, nil
}
