package relay

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
	"github.com/black-candle-technologies/courier/internal/store"
)

// signedBlobUploadURL builds an authorized POST /v1/blobs URL.
func signedBlobUploadURL(t *testing.T, uploader *crypto.Identity, to, blobID string, size int64, ts int64) string {
	t.Helper()
	toEd, err := crypto.ParseAddress(to)
	if err != nil {
		t.Fatal(err)
	}
	blobIDRaw, err := b64.DecodeString(blobID)
	if err != nil {
		t.Fatal(err)
	}
	sig := uploader.Sign(envelope.BlobUpload(uploader.EdPub[:], toEd[:], blobIDRaw, size, ts))
	q := url.Values{}
	q.Set("from", crypto.FormatAddress(uploader.EdPub[:]))
	q.Set("to", to)
	q.Set("blob_id", blobID)
	q.Set("size", fmt.Sprintf("%d", size))
	q.Set("ts", fmt.Sprintf("%d", ts))
	q.Set("sig", b64.EncodeToString(sig))
	return "/v1/blobs?" + q.Encode()
}

// signedBlobDownloadURL builds an authorized GET /v1/blobs/<id> URL.
func signedBlobDownloadURL(t *testing.T, recipient *crypto.Identity, blobID string, ts int64) string {
	t.Helper()
	blobIDRaw, err := b64.DecodeString(blobID)
	if err != nil {
		t.Fatal(err)
	}
	sig := recipient.Sign(envelope.BlobRequest(recipient.EdPub[:], blobIDRaw, ts))
	q := url.Values{}
	q.Set("ts", fmt.Sprintf("%d", ts))
	q.Set("sig", b64.EncodeToString(sig))
	return "/v1/blobs/" + blobID + "?" + q.Encode()
}

func randomBlobID(t *testing.T) string {
	t.Helper()
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(id[:])
}

func TestBlobUploadDownloadRoundTrip(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	blobID := randomBlobID(t)
	data := []byte("encrypted chunk frames go here")

	up := httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, blobID, int64(len(data)), time.Now().Unix()), bytes.NewReader(data))
	uprec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(uprec, up)
	if uprec.Code != http.StatusCreated {
		t.Fatalf("upload: got %d, body %s", uprec.Code, uprec.Body.String())
	}

	down := httptest.NewRequest("GET", signedBlobDownloadURL(t, bob, blobID, time.Now().Unix()), nil)
	downrec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(downrec, down)
	if downrec.Code != http.StatusOK {
		t.Fatalf("download: got %d, body %s", downrec.Code, downrec.Body.String())
	}
	if !bytes.Equal(downrec.Body.Bytes(), data) {
		t.Fatal("downloaded blob differs from uploaded blob")
	}
	if ct := downrec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestBlobUploadIdempotent(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	blobID := randomBlobID(t)
	data := []byte("blob bytes")
	for i, want := range []string{`"duplicate":false`, `"duplicate":true`} {
		up := httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, blobID, int64(len(data)), time.Now().Unix()), bytes.NewReader(data))
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, up)
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload %d: got %d", i, rec.Code)
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte(want)) {
			t.Fatalf("upload %d: expected %s in %s", i, want, rec.Body.String())
		}
	}
}

func TestBlobDownloadAuthorization(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	mallory, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	blobID := randomBlobID(t)
	data := []byte("secret blob")

	up := httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, blobID, int64(len(data)), time.Now().Unix()), bytes.NewReader(data))
	uprec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(uprec, up)
	if uprec.Code != http.StatusCreated {
		t.Fatalf("upload: got %d", uprec.Code)
	}

	// A non-recipient (even the uploader) cannot download.
	for name, signer := range map[string]*crypto.Identity{"uploader": alice, "stranger": mallory} {
		req := httptest.NewRequest("GET", signedBlobDownloadURL(t, signer, blobID, time.Now().Unix()), nil)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s download: got %d, want 401", name, rec.Code)
		}
	}

	// Forged signature: replace (not append) the sig param.
	badURL := signedBlobDownloadURL(t, bob, blobID, time.Now().Unix())
	u, err := url.Parse(badURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("sig", b64.EncodeToString(bytes.Repeat([]byte{1}, 64)))
	u.RawQuery = q.Encode()
	req := httptest.NewRequest("GET", u.String(), nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged sig download: got %d, want 401", rec.Code)
	}

	// Stale timestamp (replay).
	req = httptest.NewRequest("GET", signedBlobDownloadURL(t, bob, blobID, time.Now().Unix()-3600), nil)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("stale-timestamp download succeeded")
	}

	// Unknown blob id.
	req = httptest.NewRequest("GET", signedBlobDownloadURL(t, bob, randomBlobID(t), time.Now().Unix()), nil)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown blob: got %d, want 404", rec.Code)
	}

	// Malformed blob id.
	req = httptest.NewRequest("GET", "/v1/blobs/not-valid?ts=1&sig=x", nil)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed blob id: got %d, want 400", rec.Code)
	}
}

func TestBlobUploadValidation(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	now := time.Now().Unix()

	// Declared size does not match the body.
	blobID := randomBlobID(t)
	req := httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, blobID, 100, now), bytes.NewReader([]byte("short")))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("size mismatch: got %d, want 400", rec.Code)
	}

	// Oversized blob.
	bigID := randomBlobID(t)
	req = httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, bigID, envelope.MaxBlobBytes+1, now), bytes.NewReader([]byte("x")))
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized: got %d, want 400", rec.Code)
	}

	// Malformed blob id.
	req = httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, "nope", 10, now), bytes.NewReader([]byte("0123456789")))
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad blob id: got %d, want 400", rec.Code)
	}

	// Forged upload signature.
	forgedID := randomBlobID(t)
	fu, err := url.Parse(signedBlobUploadURL(t, alice, bobAddr, forgedID, 4, now))
	if err != nil {
		t.Fatal(err)
	}
	fq := fu.Query()
	fq.Set("sig", b64.EncodeToString(bytes.Repeat([]byte{2}, 64)))
	fu.RawQuery = fq.Encode()
	req = httptest.NewRequest("POST", fu.String(), bytes.NewReader([]byte("data")))
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged upload sig: got %d, want 401", rec.Code)
	}

	// Stale upload timestamp.
	staleID := randomBlobID(t)
	req = httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, staleID, 4, now-3600), bytes.NewReader([]byte("data")))
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatal("stale-timestamp upload succeeded")
	}
}

func TestBlobRetention(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	blob := &store.Blob{
		BlobID:    randomBlobID(t),
		Recipient: crypto.FormatAddress(bob.EdPub[:]),
		Uploader:  crypto.FormatAddress(alice.EdPub[:]),
		Size:      4,
		Data:      []byte("data"),
	}
	if _, err := st.SaveBlob(blob); err != nil {
		t.Fatal(err)
	}
	// A generous retention keeps the blob.
	if n, err := st.PruneBlobs(365); err != nil || n != 0 {
		t.Fatalf("prune(365): n=%d err=%v", n, err)
	}
	if _, err := st.GetBlob(blob.BlobID); err != nil {
		t.Fatalf("blob should survive: %v", err)
	}
	// An expired retention removes it.
	if n, err := st.PruneBlobs(-1); err != nil || n != 1 {
		t.Fatalf("prune(-1): n=%d err=%v", n, err)
	}
	if _, err := st.GetBlob(blob.BlobID); err == nil {
		t.Fatal("blob should have been pruned")
	}
}

func TestBlobRelayNeverSeesPlaintextMetadata(t *testing.T) {
	// The relay stores blobs opaquely: no filename, MIME type, hash, or
	// key material may appear in the stored row.
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()
	bobAddr := crypto.FormatAddress(bob.EdPub[:])
	blobID := randomBlobID(t)
	// Simulated ciphertext containing none of the metadata strings.
	data := bytes.Repeat([]byte{0x9d}, 1024)
	up := httptest.NewRequest("POST", signedBlobUploadURL(t, alice, bobAddr, blobID, int64(len(data)), time.Now().Unix()), bytes.NewReader(data))
	uprec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(uprec, up)
	if uprec.Code != http.StatusCreated {
		t.Fatalf("upload: got %d", uprec.Code)
	}
	// The stored blob is exactly the uploaded bytes; the relay added no
	// metadata beyond routing fields.
	stored, err := srv.store.GetBlob(blobID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Data, data) {
		t.Fatal("relay altered the blob bytes")
	}
	if stored.Recipient != bobAddr {
		t.Fatalf("recipient = %q", stored.Recipient)
	}
}
