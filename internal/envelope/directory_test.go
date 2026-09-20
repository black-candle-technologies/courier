// Contact-discovery protocol primitive tests (issue #39).
package envelope

import (
	"strings"
	"testing"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

func TestNormalizeHandle(t *testing.T) {
	cases := map[string]string{
		"Alice_99":              "alice_99",
		"  BOB  ":               "bob",
		"a-b_c":                 "a-b_c",
		"abc":                   "abc",
		strings.Repeat("a", 32): strings.Repeat("a", 32),
	}
	for in, want := range cases {
		got, err := NormalizeHandle(in)
		if err != nil {
			t.Fatalf("NormalizeHandle(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("NormalizeHandle(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{
		"", "ab", "has space", "dot.name", "a/b", "@alice",
		strings.Repeat("a", 33), "-lead", "_lead",
	} {
		if _, err := NormalizeHandle(bad); err == nil {
			t.Fatalf("NormalizeHandle(%q) should fail", bad)
		}
	}
	// Uppercase is normalized, not rejected.
	if got, err := NormalizeHandle("UPPER"); err != nil || got != "upper" {
		t.Fatalf("NormalizeHandle(UPPER) = %q, %v", got, err)
	}
}

func TestValidateCapabilities(t *testing.T) {
	if err := ValidateCapabilities(nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCapabilities([]string{"chat", "file-share", "a", strings.Repeat("x", 32)}); err != nil {
		t.Fatal(err)
	}
	// Capabilities are case-normalized by the caller, so "Chat" is fine.
	if err := ValidateCapabilities([]string{"Chat"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{
		{"has space"}, {""}, {strings.Repeat("x", 33)},
		{"a", "b", "c", "d", "e", "f", "g", "h", "i"},
	} {
		if err := ValidateCapabilities(bad); err == nil {
			t.Fatalf("ValidateCapabilities(%v) should fail", bad)
		}
	}
}

// TestDirectoryCanonicalDomainSeparation signs each operation's canonical
// bytes and verifies that no signature verifies under a different
// operation's canonical form.
func TestDirectoryCanonicalDomainSeparation(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	epoch := int64(1000)
	forms := map[string][]byte{
		"register":   DirectoryRegister("alice", id.EdPub[:], epoch, "public", "open", []string{"chat"}),
		"transfer":   DirectoryTransfer("alice", id.EdPub[:], epoch),
		"deregister": DirectoryDeregister("alice", id.EdPub[:], epoch),
		"query":      DirectoryQuery(id.EdPub[:], "lookup", "alice", epoch),
		"introReq":   IntroductionRequest(id.EdPub[:], id.EdPub[:], "alice", epoch),
		"intro":      Introduction(id.EdPub[:], id.EdPub[:], id.EdPub[:], epoch),
	}
	sigs := map[string][]byte{}
	for name, canon := range forms {
		sigs[name] = id.Sign(canon)
		if !crypto.Verify(id.EdPub[:], canon, sigs[name]) {
			t.Fatalf("%s: self-verification failed", name)
		}
	}
	// Cross-verification must fail everywhere: identical field values
	// must not make one operation's signature valid for another.
	for a, ca := range forms {
		for b := range forms {
			if a == b {
				continue
			}
			if crypto.Verify(id.EdPub[:], ca, sigs[b]) {
				t.Fatalf("signature for %s verifies as %s: missing domain separation", b, a)
			}
		}
	}
	// Canonical forms are deterministic.
	if string(forms["register"]) != string(DirectoryRegister("alice", id.EdPub[:], epoch, "public", "open", []string{"chat"})) {
		t.Fatal("register canonical form not deterministic")
	}
}

func TestIntroductionRequestBindsParties(t *testing.T) {
	a, _ := crypto.GenerateIdentity()
	b, _ := crypto.GenerateIdentity()
	canon := IntroductionRequest(a.EdPub[:], b.EdPub[:], "alice", 1000)
	sig := a.Sign(canon)
	if !crypto.Verify(a.EdPub[:], canon, sig) {
		t.Fatal("valid request signature rejected")
	}
	// Swapping introducer/requester changes the canonical bytes.
	swapped := IntroductionRequest(b.EdPub[:], a.EdPub[:], "alice", 1000)
	if crypto.Verify(a.EdPub[:], swapped, sig) {
		t.Fatal("request signature valid after party swap")
	}
}
