// Tests for the crypto-suite registry (issue #138).
//
// A second, test-only suite ("testsuite-v2", prefix "testsuite:") is
// registered here so the mismatch and dispatch paths can be exercised
// for real: with only SuiteV1 registered, a suite/address mismatch is
// inexpressible, which is exactly the gap Lane flagged in review
// ("the existing test only covers unknown-prefix rejection, not the
// actual mismatch branch").
package crypto

import (
	"strings"
	"sync"
	"testing"
)

const testSuiteV2 Suite = "testsuite-v2"

var registerTestSuiteOnce sync.Once

func registerTestSuite() {
	registerTestSuiteOnce.Do(func() {
		registerSuite(&SuiteDescriptor{
			Suite:         testSuiteV2,
			AddressPrefix: "testsuite:",
			ParseIdentity: func(body string) ([]byte, error) {
				return []byte("test-identity:" + body), nil
			},
			ValidateEnvelopeFields: func(eph, nonce []byte) error {
				if len(eph) != 16 || len(nonce) != 8 {
					return errTestShape
				}
				return nil
			},
			ValidateKeyFields: func(key []byte) error {
				if len(key) != 16 {
					return errTestShape
				}
				return nil
			},
			ValidateSignatureFields: func(sig []byte) error {
				if len(sig) != 16 {
					return errTestShape
				}
				return nil
			},
			VerifySignature: func(pub, msg, sig []byte) bool {
				return false
			},
			SealMessage: func(toPub, plaintext []byte) ([]byte, []byte, []byte, error) {
				return nil, nil, nil, errTestShape
			},
			OpenMessage: func(priv, eph, nonce, ct []byte) ([]byte, error) {
				return nil, errTestShape
			},
		})
	})
}

var errTestShape = errorString("testsuite-v2: bad field shape")

type errorString string

func (e errorString) Error() string { return string(e) }

func testV1Address(t *testing.T) ParsedAddress {
	t.Helper()
	id, _ := IdentityFromSeed(testSeed())
	pa, err := ParseAddressSuite(FormatAddress(id.EdPub[:]))
	if err != nil {
		t.Fatal(err)
	}
	return pa
}

func testV2Address(t *testing.T) ParsedAddress {
	t.Helper()
	registerTestSuite()
	pa, err := ParseAddressSuite("testsuite:abcd")
	if err != nil {
		t.Fatal(err)
	}
	if pa.Suite != testSuiteV2 {
		t.Fatalf("suite = %q, want %q", pa.Suite, testSuiteV2)
	}
	return pa
}

func TestDescriptorLookup(t *testing.T) {
	registerTestSuite()
	desc, ok := Descriptor(SuiteV1)
	if !ok || desc.Suite != SuiteV1 {
		t.Fatalf("Descriptor(SuiteV1) = %v, %v", desc, ok)
	}
	desc, ok = Descriptor(testSuiteV2)
	if !ok || desc.Suite != testSuiteV2 {
		t.Fatalf("Descriptor(testsuite-v2) = %v, %v", desc, ok)
	}
	if _, ok := Descriptor("future-suite-x"); ok {
		t.Fatal("Descriptor must fail closed for unregistered suites")
	}
	// KnownSuites is derived from the registry, never hand-edited.
	found := map[Suite]bool{}
	for _, s := range KnownSuites {
		found[s] = true
	}
	if !found[SuiteV1] || !found[testSuiteV2] {
		t.Fatalf("KnownSuites = %v, want both v1 and testsuite-v2", KnownSuites)
	}
}

func TestAgreeSuite(t *testing.T) {
	registerTestSuite()
	v1 := testV1Address(t)
	v2 := testV2Address(t)

	// Absent wire label defaults to SuiteV1 (older peers).
	s, err := AgreeSuite("", v1)
	if err != nil || s != SuiteV1 {
		t.Fatalf("AgreeSuite(\"\", v1) = %q, %v", s, err)
	}
	// Explicit v1 agreeing with v1 addresses.
	s, err = AgreeSuite(string(SuiteV1), v1, v1)
	if err != nil || s != SuiteV1 {
		t.Fatalf("AgreeSuite(v1, v1, v1) = %q, %v", s, err)
	}
	// The actual mismatch branch: a known suite that disagrees with
	// the address suite is rejected loudly — never processed as v1.
	if _, err := AgreeSuite(string(SuiteV1), v2); err == nil {
		t.Fatal("expected mismatch rejection for v1 label on testsuite-v2 address")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatch error = %q, want a \"does not match\" refusal", err)
	}
	if _, err := AgreeSuite(string(testSuiteV2), v1); err == nil {
		t.Fatal("expected mismatch rejection for testsuite-v2 label on v1 address")
	}
	// Unknown suite names fail closed even when every address agrees.
	if _, err := AgreeSuite("future-suite-x", v1); err == nil {
		t.Fatal("expected rejection of unknown suite")
	} else if !strings.Contains(err.Error(), "unknown crypto suite") {
		t.Fatalf("unknown-suite error = %q", err)
	}
	// A registered second suite agrees with its own addresses.
	s, err = AgreeSuite(string(testSuiteV2), v2)
	if err != nil || s != testSuiteV2 {
		t.Fatalf("AgreeSuite(testsuite-v2, v2) = %q, %v", s, err)
	}
}

func TestSuiteOwnsValidation(t *testing.T) {
	registerTestSuite()
	// The registry owns per-suite wire shapes: v1 and testsuite-v2
	// accept different field lengths, and neither accepts the other's.
	v1, _ := Descriptor(SuiteV1)
	v2, _ := Descriptor(testSuiteV2)
	if err := v1.ValidateEnvelopeFields(make([]byte, 32), make([]byte, 24)); err != nil {
		t.Fatalf("v1 should accept 32/24: %v", err)
	}
	if err := v1.ValidateEnvelopeFields(make([]byte, 16), make([]byte, 8)); err == nil {
		t.Fatal("v1 must reject testsuite-v2's 16/8 shapes")
	}
	if err := v2.ValidateEnvelopeFields(make([]byte, 16), make([]byte, 8)); err != nil {
		t.Fatalf("testsuite-v2 should accept 16/8: %v", err)
	}
	if err := v2.ValidateEnvelopeFields(make([]byte, 32), make([]byte, 24)); err == nil {
		t.Fatal("testsuite-v2 must reject v1's 32/24 shapes")
	}
	// Key and signature shapes are per-suite too.
	if err := v1.ValidateKeyFields(make([]byte, 32)); err != nil {
		t.Fatalf("v1 should accept 32-byte keys: %v", err)
	}
	if err := v2.ValidateKeyFields(make([]byte, 32)); err == nil {
		t.Fatal("testsuite-v2 must reject 32-byte keys")
	}
	if err := v1.ValidateSignatureFields(make([]byte, 64)); err != nil {
		t.Fatalf("v1 should accept 64-byte signatures: %v", err)
	}
	if err := v2.ValidateSignatureFields(make([]byte, 64)); err == nil {
		t.Fatal("testsuite-v2 must reject 64-byte signatures")
	}
}

func TestParseAddressSuiteDispatchesOnPrefix(t *testing.T) {
	registerTestSuite()
	// Longest-prefix match wins, and unknown prefixes fail closed.
	if _, err := ParseAddressSuite("testsuite:abcd"); err != nil {
		t.Fatalf("testsuite: prefix should parse: %v", err)
	}
	if _, err := ParseAddressSuite("pq:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("unknown prefix must be rejected")
	}
}
