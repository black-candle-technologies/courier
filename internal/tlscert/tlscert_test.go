package tlscert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureGeneratesAndIsStable(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "tls.crt")
	key := filepath.Join(dir, "tls.key")

	fp1, err := Ensure(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp1) != 64 {
		t.Fatalf("fingerprint should be 64 hex chars, got %q", fp1)
	}
	// Key must not be world-readable.
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", fi.Mode().Perm())
	}
	// Second call must reuse the existing cert, not regenerate.
	fp2, err := Ensure(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatal("fingerprint changed between Ensure calls")
	}
	if fp3, err := Fingerprint(cert); err != nil || fp3 != fp1 {
		t.Fatalf("Fingerprint=%q,%v want %q", fp3, err, fp1)
	}
}
