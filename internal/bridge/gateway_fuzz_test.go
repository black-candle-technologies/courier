package bridge

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzHandleIngest feeds arbitrary request bodies to the bridge
// gateway's ingest endpoint (POST /v1/bridge/ingest) with a valid
// bearer token: the JSON body decoder, caller sanitization, body-cap
// enforcement, allowlist check, and recipient address validation all
// run on untrusted input here.
// Invariants: never panic; the response is always a JSON object; the
// status is one of the documented outcomes (200 send, 449 confirmation
// required, 400/401/403/413/429 rejections); and handling is
// deterministic — the same body against a fresh fixture yields the
// same status.
func FuzzHandleIngest(f *testing.F) {
	addr := testAddr(42)                                 // allowlisted in the fixture token
	other := testAddr(43)                                // well-formed but not allowlisted
	f.Add(`{"recipient":"` + addr + `","body":"hello"}`) // valid: 449 confirmation_required
	f.Add(`{"recipient":"` + addr + `","body":"hello","caller":"chatgpt"}`)
	f.Add(`{"recipient":"` + other + `","body":"hello"}`)                                          // not allowlisted: 403
	f.Add(``)                                                                                      // empty
	f.Add(`{`)                                                                                     // truncated
	f.Add(`[]`)                                                                                    // wrong top-level type
	f.Add(`{"recipient":123,"body":null}`)                                                         // wrong field types
	f.Add(`{"recipient":"not-an-address","body":"x"}`)                                             // bad recipient
	f.Add(`{"recipient":"","body":"x"}`)                                                           // empty recipient
	f.Add(`{"recipient":"` + addr + `","body":"` + strings.Repeat("x", 70000) + `"}`)              // over body cap: 413
	f.Add(`{"recipient":"` + addr + `","body":"x","confirm_token":"bogus"}`)                       // bad confirm token
	f.Add(`{"recipient":"` + addr + `","body":"x","caller":"` + strings.Repeat("c", 10000) + `"}`) // huge caller
	f.Fuzz(func(t *testing.T, body string) {
		ingestOnce := func(fx *gwFixture, b string) *httptest.ResponseRecorder {
			return fx.ingest(t, fx.raw, b)
		}
		fx := newGwFixture(t)
		rec := ingestOnce(fx, body)
		var js map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &js); err != nil {
			t.Fatalf("ingest: non-JSON response (code %d) for body %q", rec.Code, body)
		}
		switch rec.Code {
		case 200, 400, 401, 403, 413, 429, StatusConfirmationRequired:
		default:
			t.Fatalf("ingest: unexpected status %d for body %q: %s", rec.Code, body, rec.Body.String())
		}
		// Deterministic: same body on a fresh fixture -> same status.
		fx2 := newGwFixture(t)
		if rec2 := ingestOnce(fx2, body); rec2.Code != rec.Code {
			t.Fatalf("ingest: non-deterministic status for body %q: %d then %d", body, rec.Code, rec2.Code)
		}
	})
}
