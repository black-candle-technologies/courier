package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/store"
)

// signedBlobUploadURL and randomBlobID are defined in blob_test.go.

// testServerWithConfig mirrors testServer but lets the test tune the
// abuse-control config and keeps the store handle for quota assertions.
func testServerWithConfig(t *testing.T, cfg Config) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return NewWithConfig(st, cfg), st
}

// doBlobUpload POSTs data as uploader and returns the recorder.
func doBlobUpload(t *testing.T, srv *Server, uploader *crypto.Identity, to, blobID string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST",
		signedBlobUploadURL(t, uploader, to, blobID, int64(len(data)), time.Now().Unix()),
		bytes.NewReader(data))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func decodeBlobResp(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("decode blob response: %v (body %q)", err, rec.Body.String())
	}
	return v
}

// The byte bucket is checked after signature verification: a burst of
// uploads that fits the bucket succeeds, the next one 429s. The clock
// is frozen so the tiny test bucket cannot refill mid-test.
func TestBlobUploadByteLimiter(t *testing.T) {
	srv, _ := testServerWithConfig(t, Config{
		BlobUploadBurstBytes:      48,
		BlobUploadRateBytesPerSec: 1 << 20,
	})
	fc := &fakeClock{t: time.Now()}
	srv.blobUploadLimiter.now = fc.now

	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	data := make([]byte, 32) // 48-byte burst: first fits, second does not

	if rec := doBlobUpload(t, srv, alice, bobAddr, randomBlobID(t), data); rec.Code != http.StatusCreated {
		t.Fatalf("first upload: got %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	rec := doBlobUpload(t, srv, alice, bobAddr, randomBlobID(t), data)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second upload: got %d, want 429 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rate limit") {
		t.Fatalf("429 body %q does not mention the rate limit", rec.Body.String())
	}
	// A different uploader has its own bucket: unaffected.
	carol, _ := crypto.GenerateIdentity()
	if rec := doBlobUpload(t, srv, carol, bobAddr, randomBlobID(t), data); rec.Code != http.StatusCreated {
		t.Fatalf("other uploader: got %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
}

// The durable quota is enforced at upload time: once the uploader's
// stored bytes would exceed it, uploads 429 until pruning frees bytes.
func TestBlobUploadQuotaEnforced(t *testing.T) {
	srv, st := testServerWithConfig(t, Config{BlobQuotaBytes: 64})

	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	aliceAddr := crypto.FormatAddress(alice.EdPub[:])

	if rec := doBlobUpload(t, srv, alice, bobAddr, randomBlobID(t), make([]byte, 40)); rec.Code != http.StatusCreated {
		t.Fatalf("first upload: got %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	if used, err := st.BlobQuotaUsage(aliceAddr); err != nil || used != 40 {
		t.Fatalf("quota usage = %d, %v; want 40", used, err)
	}
	rec := doBlobUpload(t, srv, alice, bobAddr, randomBlobID(t), make([]byte, 40))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-quota upload: got %d, want 429 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "quota") {
		t.Fatalf("429 body %q does not mention the quota", rec.Body.String())
	}
	// The rejected upload stored nothing.
	if used, err := st.BlobQuotaUsage(aliceAddr); err != nil || used != 40 {
		t.Fatalf("quota usage after rejection = %d, %v; want 40 (unchanged)", used, err)
	}
}

// An idempotent re-upload (same blob_id) must not double-charge the
// quota: after the duplicate, the uploader's remaining budget is what
// a single charge leaves, not two.
func TestBlobUploadDuplicateNotChargedTwice(t *testing.T) {
	srv, st := testServerWithConfig(t, Config{BlobQuotaBytes: 120})

	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	aliceAddr := crypto.FormatAddress(alice.EdPub[:])
	data := make([]byte, 60)
	blobID := randomBlobID(t)

	if rec := doBlobUpload(t, srv, alice, bobAddr, blobID, data); rec.Code != http.StatusCreated {
		t.Fatalf("first upload: got %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	rec := doBlobUpload(t, srv, alice, bobAddr, blobID, data)
	if rec.Code != http.StatusCreated {
		t.Fatalf("duplicate upload: got %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	if v := decodeBlobResp(t, rec); v["duplicate"] != true {
		t.Fatalf("duplicate upload response %v, want duplicate=true", v)
	}
	if used, err := st.BlobQuotaUsage(aliceAddr); err != nil || used != 60 {
		t.Fatalf("quota usage after duplicate = %d, %v; want 60 (single charge)", used, err)
	}
	// 60 (used) + 60 (new) == 120 (quota): fits exactly, proving the
	// duplicate was not charged a second time.
	if rec := doBlobUpload(t, srv, alice, bobAddr, randomBlobID(t), data); rec.Code != http.StatusCreated {
		t.Fatalf("exact-fit upload: got %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
}

// Zero-valued blob tuning inherits the defaults, so configs built with
// only the pre-#100 fields keep working.
func TestBlobConfigDefaultsFilled(t *testing.T) {
	srv, _ := testServerWithConfig(t, Config{})
	def := DefaultConfig()
	if srv.cfg.BlobUploadBurstBytes != def.BlobUploadBurstBytes {
		t.Fatalf("BlobUploadBurstBytes = %v, want default %v", srv.cfg.BlobUploadBurstBytes, def.BlobUploadBurstBytes)
	}
	if srv.cfg.BlobUploadRateBytesPerSec != def.BlobUploadRateBytesPerSec {
		t.Fatalf("BlobUploadRateBytesPerSec = %v, want default %v", srv.cfg.BlobUploadRateBytesPerSec, def.BlobUploadRateBytesPerSec)
	}
	if srv.cfg.BlobQuotaBytes != def.BlobQuotaBytes {
		t.Fatalf("BlobQuotaBytes = %d, want default %d", srv.cfg.BlobQuotaBytes, def.BlobQuotaBytes)
	}
	if srv.blobUploadLimiter == nil {
		t.Fatal("blobUploadLimiter is nil")
	}
	if def.BlobUploadBurstBytes <= 0 || def.BlobUploadRateBytesPerSec <= 0 || def.BlobQuotaBytes <= 0 {
		t.Fatal("blob defaults must be positive")
	}
}

// Custom blob tuning is honored, not overwritten by the defaults.
func TestBlobConfigCustomHonored(t *testing.T) {
	srv, _ := testServerWithConfig(t, Config{
		BlobUploadBurstBytes:      12345,
		BlobUploadRateBytesPerSec: 678,
		BlobQuotaBytes:            91011,
	})
	if srv.cfg.BlobUploadBurstBytes != 12345 || srv.cfg.BlobUploadRateBytesPerSec != 678 || srv.cfg.BlobQuotaBytes != 91011 {
		t.Fatalf("custom blob config not honored: %+v", srv.cfg)
	}
}
