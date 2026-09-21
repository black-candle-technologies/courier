package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewerThan(t *testing.T) {
	cases := []struct {
		current, tag string
		want         bool
	}{
		{"0.5.0", "v0.5.1", true},
		{"v0.5.0", "v0.5.1", true},
		{"0.5.0", "0.5.0", false},
		{"v0.5.1", "v0.5.0", false},
		{"0.5.0", "v0.6.0", true},
		{"0.5.0", "v1.0.0", true},
		{"0.5.10", "v0.5.9", false}, // numeric, not lexicographic
		{"0.5.9", "v0.5.10", true},
		{"1.0", "v1.0.1", true},
		{"bogus", "v0.5.1", false},
		{"0.5.0", "bogus", false},
	}
	for _, c := range cases {
		if got := NewerThan(c.current, c.tag); got != c.want {
			t.Errorf("NewerThan(%q, %q) = %v, want %v", c.current, c.tag, got, c.want)
		}
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return pub, priv
}

const testSums = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  courier-linux-amd64\n"

func TestVerifyChecksumsSignature(t *testing.T) {
	pub, priv := testKey(t)
	sums := []byte(testSums)
	sig := ed25519.Sign(priv, sums)

	t.Run("valid", func(t *testing.T) {
		if err := verifyChecksumsSignature(sums, sig, pub); err != nil {
			t.Fatalf("valid signature rejected: %v", err)
		}
	})

	t.Run("tampered checksums", func(t *testing.T) {
		tampered := append([]byte{}, sums...)
		tampered[0] ^= 0x01 // flip a bit in the checksums file
		if err := verifyChecksumsSignature(tampered, sig, pub); err == nil {
			t.Fatal("tampered checksums accepted")
		} else if !strings.Contains(err.Error(), "invalid release signature") {
			t.Fatalf("unexpected error for tampered checksums: %v", err)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		bad := append([]byte{}, sig...)
		bad[ed25519.SignatureSize-1] ^= 0x01
		if err := verifyChecksumsSignature(sums, bad, pub); err == nil {
			t.Fatal("tampered signature accepted")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other, _ := testKey(t)
		if err := verifyChecksumsSignature(sums, sig, other); err == nil {
			t.Fatal("signature from a different key accepted")
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		if err := verifyChecksumsSignature(sums, nil, pub); err == nil {
			t.Fatal("missing signature accepted")
		} else if !strings.Contains(err.Error(), "wrong size") {
			t.Fatalf("unexpected error for missing signature: %v", err)
		}
	})

	t.Run("short signature", func(t *testing.T) {
		if err := verifyChecksumsSignature(sums, sig[:32], pub); err == nil {
			t.Fatal("truncated signature accepted")
		}
	})

	t.Run("bad public key", func(t *testing.T) {
		if err := verifyChecksumsSignature(sums, sig, ed25519.PublicKey{}); err == nil {
			t.Fatal("empty public key accepted")
		}
	})
}

// fakeReleaseServer serves a minimal GitHub releases API for one release,
// with configurable sums/signature content.
func fakeReleaseServer(t *testing.T, sums []byte, sig []byte, withSigAsset bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		assets := fmt.Sprintf(`[{"name":%q,"browser_download_url":%q}]`, SumsAsset, srv.URL+"/"+SumsAsset)
		if withSigAsset {
			assets = fmt.Sprintf(`[{"name":%q,"browser_download_url":%q},{"name":%q,"browser_download_url":%q}]`,
				SumsAsset, srv.URL+"/"+SumsAsset, SumsSigAsset, srv.URL+"/"+SumsSigAsset)
		}
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":%s}`, assets)
	})
	mux.HandleFunc("/"+SumsAsset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(sums)
	})
	mux.HandleFunc("/"+SumsSigAsset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(sig)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLatestFromSignatureEnforcement(t *testing.T) {
	pub, priv := testKey(t)
	sums := []byte(testSums)

	t.Run("valid signature populates sums", func(t *testing.T) {
		sig := ed25519.Sign(priv, sums)
		srv := fakeReleaseServer(t, sums, sig, true)
		rel, err := latestFrom(srv.URL, pub)
		if err != nil {
			t.Fatalf("latestFrom: %v", err)
		}
		if got := rel.Sums["courier-linux-amd64"]; got != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
			t.Fatalf("sums not parsed after valid signature: %v", rel.Sums)
		}
	})

	t.Run("missing signature fails closed", func(t *testing.T) {
		// Pre-signing-era release: SHA256SUMS present, no .sig asset.
		srv := fakeReleaseServer(t, sums, nil, false)
		_, err := latestFrom(srv.URL, pub)
		if err == nil {
			t.Fatal("unsigned release accepted")
		}
		if !strings.Contains(err.Error(), "not signed") {
			t.Fatalf("error should say the release is not signed, got: %v", err)
		}
	})

	t.Run("wrong key rejected", func(t *testing.T) {
		_, otherPriv := testKey(t)
		sig := ed25519.Sign(otherPriv, sums)
		srv := fakeReleaseServer(t, sums, sig, true)
		if _, err := latestFrom(srv.URL, pub); err == nil {
			t.Fatal("signature from wrong key accepted")
		} else if !strings.Contains(err.Error(), "invalid release signature") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("tampered checksums rejected", func(t *testing.T) {
		sig := ed25519.Sign(priv, sums) // signature over the ORIGINAL sums
		tampered := append([]byte{}, sums...)
		tampered[len(tampered)-2] = 'X'
		srv := fakeReleaseServer(t, tampered, sig, true)
		if _, err := latestFrom(srv.URL, pub); err == nil {
			t.Fatal("tampered checksums accepted")
		}
	})

	t.Run("truncated signature rejected", func(t *testing.T) {
		sig := ed25519.Sign(priv, sums)[:32]
		srv := fakeReleaseServer(t, sums, sig, true)
		if _, err := latestFrom(srv.URL, pub); err == nil {
			t.Fatal("truncated signature accepted")
		}
	})
}
