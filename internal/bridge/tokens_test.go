package bridge

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir() + "/bridge.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// testAddr returns a deterministic well-formed Courier address.
func testAddr(seed byte) string {
	var b [32]byte
	for i := range b {
		b[i] = seed + byte(i)
	}
	return crypto.FormatAddress(b[:])
}

func TestIssueStoresHashNotRaw(t *testing.T) {
	s := testStore(t)
	raw, tok, err := s.IssueToken("t1", []string{testAddr(1)}, 0, "pepper")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, TokenPrefix) {
		t.Fatalf("raw token %q lacks prefix", raw)
	}
	// The raw token must not appear anywhere in the DB.
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE token_hash=?`, raw).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("raw token stored in db")
	}
	// Lookup by hash works.
	got, err := s.LookupToken(HashToken(raw, "pepper"))
	if err != nil || got == nil {
		t.Fatalf("lookup: %v %v", got, err)
	}
	if got.ID != tok.ID || got.Label != "t1" {
		t.Fatalf("lookup mismatch: %+v", got)
	}
	// Wrong pepper does not match.
	got, err = s.LookupToken(HashToken(raw, "wrong"))
	if err != nil || got != nil {
		t.Fatalf("wrong pepper matched: %v %v", got, err)
	}
	// Default expiry is ~1 year out.
	if tok.ExpiresAt-time.Now().Unix() < 364*24*3600 {
		t.Fatal("default expiry not ~1 year")
	}
}

func TestIssueValidation(t *testing.T) {
	s := testStore(t)
	if _, _, err := s.IssueToken("", []string{testAddr(1)}, 0, "p"); err == nil {
		t.Fatal("empty label accepted")
	}
	if _, _, err := s.IssueToken("x", nil, 0, "p"); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	if _, _, err := s.IssueToken("x", []string{"bogus"}, 0, "p"); err == nil {
		t.Fatal("bad address accepted")
	}
	if _, _, err := s.IssueToken("x", []string{testAddr(1)}, 0, ""); err == nil {
		t.Fatal("empty pepper accepted")
	}
}

func TestRevokeImmediate(t *testing.T) {
	s := testStore(t)
	raw, tok, err := s.IssueToken("r1", []string{testAddr(2)}, 0, "p")
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.RevokeToken("r1")
	if err != nil || n != 1 {
		t.Fatalf("revoke: %v %d", err, n)
	}
	got, err := s.LookupToken(HashToken(raw, "p"))
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.Active(time.Now().Unix()) {
		t.Fatal("revoked token still active")
	}
	if got.Status(time.Now().Unix()) != "revoked" {
		t.Fatalf("status = %q", got.Status(time.Now().Unix()))
	}
	_ = tok
}

func TestExpiry(t *testing.T) {
	s := testStore(t)
	raw, _, err := s.IssueToken("e1", []string{testAddr(3)}, time.Hour, "p")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.LookupToken(HashToken(raw, "p"))
	if !got.Active(time.Now().Unix()) {
		t.Fatal("fresh token not active")
	}
	if got.Active(time.Now().Add(2 * time.Hour).Unix()) {
		t.Fatal("expired token still active")
	}
}

func TestRotateGraceAndConfirmationCarryover(t *testing.T) {
	s := testStore(t)
	raw, tok, err := s.IssueToken("rot", []string{testAddr(4)}, 48*time.Hour, "p")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkConfirmed(tok.ID, testAddr(4), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	newRaw, newTok, err := s.RotateToken("rot", 24*time.Hour, "p")
	if err != nil {
		t.Fatal(err)
	}
	// Old token still active during grace.
	old, _ := s.LookupToken(HashToken(raw, "p"))
	if !old.Active(time.Now().Unix()) {
		t.Fatal("old token not active during grace")
	}
	if old.Status(time.Now().Unix()) != "grace-period" {
		t.Fatalf("old status = %q", old.Status(time.Now().Unix()))
	}
	// New token works and inherited the confirmation.
	nu, _ := s.LookupToken(HashToken(newRaw, "p"))
	if !nu.Active(time.Now().Unix()) {
		t.Fatal("new token not active")
	}
	ok, err := s.IsConfirmed(newTok.ID, testAddr(4))
	if err != nil || !ok {
		t.Fatal("confirmation not carried to rotated token")
	}
	// New token keeps the original expiry (rotation is not extension).
	if newTok.ExpiresAt != tok.ExpiresAt {
		t.Fatal("rotation extended expiry")
	}
}

func TestRevokeAll(t *testing.T) {
	s := testStore(t)
	for _, l := range []string{"a", "b"} {
		if _, _, err := s.IssueToken(l, []string{testAddr(5)}, 0, "p"); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.RevokeAll()
	if err != nil || n != 2 {
		t.Fatalf("revoke all: %v %d", err, n)
	}
	toks, err := s.ListTokens()
	if err != nil || len(toks) != 2 {
		t.Fatal(err)
	}
	for _, tk := range toks {
		if tk.Active(time.Now().Unix()) {
			t.Fatal("token still active after revoke-all")
		}
	}
}

// TestRevokeWildcardLabelEscaped (F5): a label containing LIKE
// wildcards must be matched literally. `revoke --name "%"` must not
// revoke every token.
func TestRevokeWildcardLabelEscaped(t *testing.T) {
	s := testStore(t)
	_, tok1, err := s.IssueToken("100%", []string{testAddr(1)}, 0, "pepper")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.IssueToken("other", []string{testAddr(2)}, 0, "pepper"); err != nil {
		t.Fatal(err)
	}
	// findToken("100%") resolves the literal label.
	id, err := s.findToken("100%")
	if err != nil {
		t.Fatal(err)
	}
	if id != tok1.ID {
		t.Fatalf("findToken(%q) = %q, want %q", "100%", id, tok1.ID)
	}
	// RevokeToken("100%") revokes exactly the one token.
	n, err := s.RevokeToken("100%")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("revoked %d tokens, want 1", n)
	}
	// A bare "%" matches nothing (no id starts with a literal %).
	n, err = s.RevokeToken("%")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf(`RevokeToken("%%") revoked %d tokens, want 0`, n)
	}
}

// errReader is an io.Reader that always fails; used to simulate
// crypto/rand failure.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestTokenIDRNGFailureFailsClosed (#86): when the randomness source
// fails, newTokenID must return an error and IssueToken must issue
// nothing — a predictable all-zero id must never be assigned.
func TestTokenIDRNGFailureFailsClosed(t *testing.T) {
	s := testStore(t)
	old := randReader
	randReader = errReader{err: errors.New("simulated rand failure")}
	defer func() { randReader = old }()

	if _, err := newTokenID(); err == nil {
		t.Fatal("newTokenID: expected error on RNG failure, got nil")
	}
	countTokens := func() int {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := countTokens()
	if _, _, err := s.IssueToken("t-rngfail", []string{testAddr(9)}, 0, "pepper"); err == nil {
		t.Fatal("IssueToken: expected error on RNG failure, got nil")
	}
	if got := countTokens(); got != before {
		t.Fatalf("IssueToken created a token on RNG failure: count %d -> %d", before, got)
	}
}
