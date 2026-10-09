package envelope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	couriercrypto "github.com/black-candle-technologies/courier/internal/crypto"
)

func teamTestLimits() TeamLimits {
	return TeamLimits{MaxObjectBytes: 262144, MaxStringBytes: 512, MaxArrayItems: 256, MaxMembers: 256, MaxChainObjects: 1024, MaxChainBytes: 8 << 20, InvitationLifetimeSeconds: 86400}
}
func teamTestKey(n byte) (string, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{n}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	return couriercrypto.FormatAddress(key.Public().(ed25519.PublicKey)), key
}
func teamTestRoot(t testing.TB) TeamRoot {
	t.Helper()
	owner, _ := teamTestKey(1)
	r, e := NewTeamRoot("https://relay.example:8470", owner, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), teamTestLimits())
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func teamTestRoster(t testing.TB) TeamRoster {
	t.Helper()
	root := teamTestRoot(t)
	return TeamRoster{TeamRoot: root, Schema: TeamRosterSchema, Suite: string(couriercrypto.SuiteV1), Slug: "crew", Version: "1", Owner: root.GenesisOwner, OwnerEpoch: "1", IssuedAt: "2026-10-08T00:00:00Z", ExpiresAt: "2026-10-09T00:00:00Z", Status: "active", Visibility: TeamPrivate, HistoryDisclosure: TeamHistoryDisclosure, RemovalPolicy: TeamRemovalPolicy, Members: []TeamMember{}}
}
func teamTestSign(t testing.TB, v TeamPayload, role string, n byte) TeamSignature {
	t.Helper()
	address, key := teamTestKey(n)
	s, e := MakeTeamSignature(v, role, address, func(b []byte) ([]byte, error) { return ed25519.Sign(key, b), nil }, teamTestLimits())
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func teamTestBytes(t testing.TB, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestTeamStrictRoster(t *testing.T) {
	r := teamTestRoster(t)
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	raw := teamTestBytes(t, r)
	if _, e := ParseTeamRoster(raw, teamTestLimits()); e != nil {
		t.Fatal(e)
	}
	cases := map[string][]byte{
		"duplicate":     bytes.Replace(raw, []byte(`"slug":"crew"`), []byte(`"slug":"crew","sl\u0075g":"crew"`), 1),
		"unknown":       append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"future":"x"}`)...),
		"missing":       bytes.Replace(raw, []byte(`"previous_hash":null,`), nil, 1),
		"case":          bytes.Replace(raw, []byte(`"slug"`), []byte(`"Slug"`), 1),
		"null":          bytes.Replace(raw, []byte(`"slug":"crew"`), []byte(`"slug":null`), 1),
		"number":        bytes.Replace(raw, []byte(`"version":"1"`), []byte(`"version":1`), 1),
		"overflow":      bytes.Replace(raw, []byte(`"version":"1"`), []byte(`"version":"18446744073709551616"`), 1),
		"leading zero":  bytes.Replace(raw, []byte(`"version":"1"`), []byte(`"version":"01"`), 1),
		"suite omitted": bytes.Replace(raw, []byte(`"suite":"ed25519-x25519-naclbox-v1",`), nil, 1),
		"suite unknown": bytes.Replace(raw, []byte(`"suite":"ed25519-x25519-naclbox-v1"`), []byte(`"suite":"rsa"`), 1),
		"unicode":       bytes.Replace(raw, []byte(`"crew"`), []byte(`"cr\ud800ew"`), 1),
		"utf8":          append(append([]byte{}, raw...), 0xff),
		"trailing":      append(append([]byte{}, raw...), []byte(`{}`)...),
		"members null":  bytes.Replace(raw, []byte(`"members":[]`), []byte(`"members":null`), 1),
		"padded nonce":  bytes.Replace(raw, []byte(r.GenesisNonce), []byte(r.GenesisNonce+"="), 1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseTeamRoster(b, teamTestLimits()); e == nil {
				t.Fatal("accepted invalid wire")
			}
		})
	}
	l := teamTestLimits()
	l.MaxObjectBytes = len(raw) - 1
	if _, e := ParseTeamRoster(raw, l); !errors.Is(e, ErrTeamLimit) {
		t.Fatalf("limit: %v", e)
	}
}

func TestTeamCanonicalSubset(t *testing.T) {
	l := teamTestLimits()
	b, e := CanonicalTeamJSON([]byte(` { "z":null, "a":["\u0061", "<>&/", "\"\\"] } `), l)
	if e != nil {
		t.Fatal(e)
	}
	want := `{"a":["a","<>&/","\"\\"],"z":null}`
	if string(b) != want {
		t.Fatalf("%s != %s", b, want)
	}
	for _, s := range []string{`{"x":true}`, `{"x":1}`, `{"x":"\n"}`, `{"x":"é"}`, `{"x":null,"\u0078":null}`, strings.Repeat("[", 10) + strings.Repeat("]", 10)} {
		if _, e := CanonicalTeamJSON([]byte(s), l); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	if _, e := CanonicalTeamJSON([]byte(`{}`), TeamLimits{}); !errors.Is(e, ErrTeamLimit) {
		t.Fatal(e)
	}
}

func TestTeamShapeAndEncoding(t *testing.T) {
	base := teamTestRoster(t)
	address, _ := teamTestKey(2)
	hash := "sha256:" + strings.Repeat("a", 64)
	tests := map[string]func(*TeamRoster){
		"unsorted":          func(r *TeamRoster) { r.Members = []TeamMember{{"z", address, hash}, {"a", r.Owner, hash}} },
		"duplicate handle":  func(r *TeamRoster) { r.Members = []TeamMember{{"a", address, hash}, {"a", r.Owner, hash}} },
		"duplicate address": func(r *TeamRoster) { r.Members = []TeamMember{{"a", address, hash}, {"b", address, hash}} },
		"uppercase":         func(r *TeamRoster) { r.Slug = "Crew" },
		"origin slash":      func(r *TeamRoster) { r.RelayOrigin += "/" },
		"origin uppercase":  func(r *TeamRoster) { r.RelayOrigin = "https://RELAY.example:8470" },
		"public":            func(r *TeamRoster) { r.Visibility = "public" },
		"duration":          func(r *TeamRoster) { r.ExpiresAt = "2026-10-09T00:00:01Z" },
		"equal window":      func(r *TeamRoster) { r.ExpiresAt = r.IssuedAt },
		"fractional time":   func(r *TeamRoster) { r.IssuedAt = "2026-10-08T00:00:00.0Z" },
		"uppercase hash":    func(r *TeamRoster) { r.GenesisRoot = strings.ToUpper(r.GenesisRoot) },
		"zero epoch":        func(r *TeamRoster) { r.OwnerEpoch = "0" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if _, e := CanonicalTeamPayload(r, teamTestLimits()); e == nil {
				t.Fatal("accepted invalid shape")
			}
		})
	}
	for _, origin := range []string{"https://relay.example", "https://relay.example:8470", "https://127.0.0.1", "https://[::1]:8470"} {
		if !teamOrigin(origin) {
			t.Fatal(origin)
		}
	}
	for _, origin := range []string{"http://relay.example", "https://relay.example:443", "https://relay.example:08470", "https://relay.example:", "https://relay.example?", "https://user@relay.example", "https://relay.example#x", "https://-relay.example", "https://relay..example", "https://[0:0:0:0:0:0:0:1]"} {
		if teamOrigin(origin) {
			t.Fatal(origin)
		}
	}
	var nilRoster *TeamRoster
	if _, e := CanonicalTeamPayload(nilRoster, teamTestLimits()); e == nil {
		t.Fatal("nil")
	}
	// Existing protocols retain their pre-team omitted-suite behavior.
	if suite, e := couriercrypto.AgreeSuite(""); e != nil || suite != couriercrypto.SuiteV1 {
		t.Fatal(suite, e)
	}
}

func TestTeamSignatureDomain(t *testing.T) {
	r := teamTestRoster(t)
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	expected := []TeamSignature{{Role: "owner", Address: r.Owner}}
	if e := verifyTeamSignatures(r, r.Signatures, expected, teamTestLimits()); e != nil {
		t.Fatal(e)
	}
	hash1, _ := TeamPayloadHash(r, teamTestLimits())
	r.Signatures[0].Sig = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	hash2, _ := TeamPayloadHash(r, teamTestLimits())
	if hash1 != hash2 {
		t.Fatal("signature entered hash")
	}
	if e := verifyTeamSignatures(r, r.Signatures, expected, teamTestLimits()); !errors.Is(e, ErrTeamSignature) {
		t.Fatal(e)
	}
	_, key := teamTestKey(1)
	canonical, _ := CanonicalTeamPayload(r, teamTestLimits())
	r.Signatures[0].Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, canonical))
	if e := verifyTeamSignatures(r, r.Signatures, expected, teamTestLimits()); e == nil {
		t.Fatal("unprefixed signature accepted")
	}
	r.Signatures = []TeamSignature{teamTestSign(t, r, "owner", 1)}
	r.Slug = "changed"
	if e := verifyTeamSignatures(r, r.Signatures, expected, teamTestLimits()); e == nil {
		t.Fatal("mutation accepted")
	}
}

func teamTestNow() time.Time { t, _ := time.Parse(time.RFC3339, "2026-10-08T12:00:00Z"); return t }

func TestTeamRejectExtendedPayload(t *testing.T) {
	type extended struct {
		TeamRoster
		Task string `json:"task"`
	}
	if _, e := CanonicalTeamPayload(extended{teamTestRoster(t), "execute"}, teamTestLimits()); !errors.Is(e, ErrTeamWire) {
		t.Fatal("unreviewed wire extension", e)
	}
}
