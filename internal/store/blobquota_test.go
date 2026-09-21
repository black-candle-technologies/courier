package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// quotaBlob builds a Blob with deterministic ids for quota tests. The
// store layer does not validate address formats.
func quotaBlob(id, uploader string, size int64) *Blob {
	return &Blob{
		BlobID:    id,
		Recipient: "recipient-A",
		Uploader:  uploader,
		Size:      size,
		Data:      make([]byte, size),
	}
}

func quotaUsage(t *testing.T, s *Store, uploader string) int64 {
	t.Helper()
	used, err := s.BlobQuotaUsage(uploader)
	if err != nil {
		t.Fatalf("BlobQuotaUsage: %v", err)
	}
	return used
}

// The quota is charged on insert and enforced before the insert: the
// second blob would overdraw, so it is rejected and the ledger and the
// blobs table are unchanged.
func TestSaveBlobWithQuotaChargesAndEnforces(t *testing.T) {
	s := testStore(t)
	const quota = 100

	stored, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 60), quota)
	if err != nil || !stored {
		t.Fatalf("first save: stored=%v err=%v", stored, err)
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 60 {
		t.Fatalf("usage after first save = %d, want 60", got)
	}

	_, err = s.SaveBlobWithQuota(quotaBlob("b2", "uploader-A", 60), quota)
	if !errors.Is(err, ErrBlobQuotaExceeded) {
		t.Fatalf("overdraw: got err=%v, want ErrBlobQuotaExceeded", err)
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 60 {
		t.Fatalf("usage after rejected save = %d, want 60 (unchanged)", got)
	}
	if _, err := s.GetBlob("b2"); err != sql.ErrNoRows {
		t.Fatalf("rejected blob persisted: GetBlob err=%v", err)
	}
}

// The quota is per-uploader: one uploader's bytes never count against
// another's.
func TestSaveBlobWithQuotaIsPerUploader(t *testing.T) {
	s := testStore(t)
	const quota = 100

	if _, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 80), quota); err != nil {
		t.Fatalf("uploader-A save: %v", err)
	}
	if _, err := s.SaveBlobWithQuota(quotaBlob("b2", "uploader-B", 80), quota); err != nil {
		t.Fatalf("uploader-B save at same usage: %v (quotas must be independent)", err)
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 80 {
		t.Fatalf("uploader-A usage = %d, want 80", got)
	}
	if got := quotaUsage(t, s, "uploader-B"); got != 80 {
		t.Fatalf("uploader-B usage = %d, want 80", got)
	}
}

// Re-uploading the same blob_id is idempotent and must not double-
// charge the quota — otherwise a client retrying an upload it already
// completed would burn its own budget.
func TestSaveBlobWithQuotaDuplicateNotCharged(t *testing.T) {
	s := testStore(t)
	const quota = 100

	stored, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 80), quota)
	if err != nil || !stored {
		t.Fatalf("first save: stored=%v err=%v", stored, err)
	}
	stored, err = s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 80), quota)
	if err != nil {
		t.Fatalf("duplicate save: %v", err)
	}
	if stored {
		t.Fatal("duplicate save reported stored=true, want false")
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 80 {
		t.Fatalf("usage after duplicate = %d, want 80 (not double-charged)", got)
	}
}

// Pruning expired blobs returns their bytes to the quota ledger in the
// same transaction as the delete.
func TestPruneBlobsReleasesQuota(t *testing.T) {
	s := testStore(t)
	const quota = 1 << 20

	if _, err := s.SaveBlobWithQuota(quotaBlob("old-1", "uploader-A", 100), quota); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveBlobWithQuota(quotaBlob("old-2", "uploader-A", 200), quota); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveBlobWithQuota(quotaBlob("new-1", "uploader-A", 300), quota); err != nil {
		t.Fatal(err)
	}
	// Age two blobs past the retention window; new-1 stays fresh.
	if _, err := s.db.Exec(
		`UPDATE blobs SET received_at = strftime('%s','now','-40 days') WHERE blob_id IN ('old-1','old-2')`); err != nil {
		t.Fatal(err)
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 600 {
		t.Fatalf("usage before prune = %d, want 600", got)
	}

	n, err := s.PruneBlobs(30)
	if err != nil {
		t.Fatalf("PruneBlobs: %v", err)
	}
	if n != 2 {
		t.Fatalf("PruneBlobs deleted %d rows, want 2", n)
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 300 {
		t.Fatalf("usage after prune = %d, want 300 (only new-1 remains)", got)
	}
	if _, err := s.GetBlob("new-1"); err != nil {
		t.Fatalf("fresh blob deleted by prune: %v", err)
	}
}

// A duplicate re-upload is acknowledged even when the uploader is at
// quota: those bytes were already charged, so the replay must not be
// rejected for a quota its own first upload paid for.
func TestSaveBlobWithQuotaDuplicateAllowedAtQuota(t *testing.T) {
	s := testStore(t)
	const quota = 100

	if _, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 60), quota); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveBlobWithQuota(quotaBlob("b2", "uploader-A", 40), quota); err != nil {
		t.Fatal(err)
	}
	stored, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 60), quota)
	if err != nil {
		t.Fatalf("duplicate at quota: %v (replays must stay idempotent)", err)
	}
	if stored {
		t.Fatal("duplicate at quota reported stored=true, want false")
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 100 {
		t.Fatalf("usage after duplicate = %d, want 100 (unchanged)", got)
	}
}

// Uploads rejected at exactly the quota boundary: usage == quota is
// allowed (used+size > quota rejects), usage+1 byte is not.
func TestSaveBlobWithQuotaBoundary(t *testing.T) {
	s := testStore(t)

	if _, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 100), 100); err != nil {
		t.Fatalf("save filling quota exactly: %v", err)
	}
	if _, err := s.SaveBlobWithQuota(quotaBlob("b2", "uploader-A", 1), 100); !errors.Is(err, ErrBlobQuotaExceeded) {
		t.Fatalf("1 byte over quota: got err=%v, want ErrBlobQuotaExceeded", err)
	}
}

// A database that predates quotas — blobs stored through a path that
// never charged the ledger — is adopted on Open: the ledger reconciles
// to the bytes actually stored instead of granting a fresh allowance.
func TestEnsureBlobQuotaSchemaReconcilesExistingBlobs(t *testing.T) {
	s := testStore(t)

	// Insert directly, bypassing the quota path, to simulate a
	// pre-quota database.
	for _, b := range []*Blob{quotaBlob("old-1", "uploader-A", 111), quotaBlob("old-2", "uploader-A", 222)} {
		if _, err := s.db.Exec(
			`INSERT INTO blobs (blob_id, recipient, uploader, size, data) VALUES (?, ?, ?, ?, ?)`,
			b.BlobID, b.Recipient, b.Uploader, b.Size, b.Data); err != nil {
			t.Fatal(err)
		}
	}
	// The reconcile already ran once at Open (empty DB); run it again
	// over the pre-existing blobs and confirm it picks them up.
	if err := ensureBlobQuotaSchema(s.db); err != nil {
		t.Fatalf("ensureBlobQuotaSchema: %v", err)
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 333 {
		t.Fatalf("reconciled usage = %d, want 333", got)
	}
	// Reconcile is idempotent: it must not double-count on repeat runs.
	if err := ensureBlobQuotaSchema(s.db); err != nil {
		t.Fatalf("ensureBlobQuotaSchema (repeat): %v", err)
	}
	if got := quotaUsage(t, s, "uploader-A"); got != 333 {
		t.Fatalf("usage after repeat reconcile = %d, want 333", got)
	}
}

// Quota usage is durable: it survives closing and reopening the
// database (the ledger is in SQLite, never in-memory only).
func TestBlobQuotaSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 500), 1000); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() })
	if got := quotaUsage(t, s2, "uploader-A"); got != 500 {
		t.Fatalf("usage after reopen = %d, want 500", got)
	}
	// And enforcement still applies after the restart.
	if _, err := s2.SaveBlobWithQuota(quotaBlob("b2", "uploader-A", 600), 1000); !errors.Is(err, ErrBlobQuotaExceeded) {
		t.Fatalf("overdraw after reopen: got err=%v, want ErrBlobQuotaExceeded", err)
	}
}

// Unknown uploaders start at zero usage — new identities are never
// penalized for having no history.
func TestBlobQuotaUsageUnknownUploader(t *testing.T) {
	s := testStore(t)
	if got := quotaUsage(t, s, "nobody"); got != 0 {
		t.Fatalf("unknown uploader usage = %d, want 0", got)
	}
}

// Sanity: the error message carries the uploader's usage for operators.
func TestErrBlobQuotaExceededMessage(t *testing.T) {
	s := testStore(t)
	if _, err := s.SaveBlobWithQuota(quotaBlob("b1", "uploader-A", 10), 1000); err != nil {
		t.Fatal(err)
	}
	_, err := s.SaveBlobWithQuota(quotaBlob("b2", "uploader-A", 2000), 1000)
	if !errors.Is(err, ErrBlobQuotaExceeded) {
		t.Fatalf("got %v, want ErrBlobQuotaExceeded", err)
	}
	msg := err.Error()
	for _, want := range []string{"10", "1000"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("quota error %q does not mention %q", msg, want)
		}
	}
}
