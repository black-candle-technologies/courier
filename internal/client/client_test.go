package client

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testTLSServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)
	sum := sha256.Sum256(ts.Certificate().Raw)
	return ts, hex.EncodeToString(sum[:])
}

func TestPinnedTransportAcceptsCorrectPin(t *testing.T) {
	ts, fp := testTLSServer(t)
	c := New(&Config{RelayURL: ts.URL, RelayFingerprint: fp})
	hc, err := c.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Get(ts.URL)
	if err != nil {
		t.Fatalf("request with correct pin failed: %v", err)
	}
	resp.Body.Close()
}

func TestPinnedTransportRejectsWrongPin(t *testing.T) {
	ts, _ := testTLSServer(t)
	wrong := strings.Repeat("0", 64)
	c := New(&Config{RelayURL: ts.URL, RelayFingerprint: wrong})
	hc, err := c.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	_, err = hc.Get(ts.URL)
	if err == nil {
		t.Fatal("request with wrong pin succeeded")
	}
	if !strings.Contains(err.Error(), "certificate mismatch") {
		t.Fatalf("want certificate mismatch error, got: %v", err)
	}
}

func TestPinnedTransportRequiresPin(t *testing.T) {
	ts, _ := testTLSServer(t)
	c := New(&Config{RelayURL: ts.URL})
	_, err := c.httpClient()
	if err == nil {
		t.Fatal("expected error when no fingerprint is pinned")
	}
	if !strings.Contains(err.Error(), "no pinned certificate") {
		t.Fatalf("want no-pinned-certificate error, got: %v", err)
	}
}

func TestHTTPTransportSkipsPinning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	c := New(&Config{RelayURL: ts.URL})
	if _, err := c.httpClient(); err != nil {
		t.Fatalf("plain http should not require pinning: %v", err)
	}
	if fp, err := FetchRelayFingerprint(ts.URL); err != nil || fp != "" {
		t.Fatalf("FetchRelayFingerprint(http) = %q, %v; want empty", fp, err)
	}
}
