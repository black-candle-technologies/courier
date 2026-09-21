package relay

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/black-candle-technologies/courier/internal/store"
)

// seedSendEnvelope is a correctly signed DM envelope (fixed test
// identities) for the /v1/send fuzz target.
const seedSendEnvelope = `{"ct":"s5GAk_BORbqmrtzkyL66vmQt9cpt","eph":"sJUSCSLxDo3x-CQhKvz-SVcJXHIJM9K8r7DCoKzqTQU","from":"ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","nonce":"I1KEd5aw4WAs3bKuqUtLZCRcv1Ocq8gJ","sent_at":1780000000,"sig":"mmLXE7a5Yi6AhsJS4VLBqiTqwfS40Vc-mtyeWQKD2RcZ7W1v6RFuBtnWjZCMQcHtfbBnuxduqLVYEa08oiGxCQ","to":"ed25519:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"}`

// seedGroupControlCreate is a correctly signed group "create" control.
const seedGroupControlCreate = `{"action":"create","admin":"ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","epoch":1,"group":"group:AQIDBAUGBwgJCgsMDQ4PEA","name":"test group","sig":"dCcOKYQWD2NKgYBFDAY4wNohDJ7UZ2znROLBkh4T7LUINVy3oYiBNahYcpngP9jmW51Bot165SJiCQ1xpfPiDg"}`

// fuzzRelayServer builds a relay Server over a fresh temp database for
// one fuzz iteration, so handler side effects (stored envelopes, group
// state, rate-limiter buckets) never leak between inputs.
func fuzzRelayServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st)
}

// postFuzz sends body to path on srv and returns the recorder.
func postFuzz(srv *Server, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// checkFuzzHTTPResponse asserts the properties every relay handler must
// uphold for arbitrary input: the response is always a JSON object
// (handlers reply via writeJSON/writeErr). replaySame selects the
// replay semantic: for /v1/send a replayed envelope is acknowledged
// with its original status (201, duplicate), while for group controls a
// replayed control must be rejected (400) rather than applied twice.
func checkFuzzHTTPResponse(t *testing.T, srv *Server, path string, body []byte, replaySame bool) {
	t.Helper()
	rec := postFuzz(srv, path, body)
	var js map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &js); err != nil {
		t.Fatalf("POST %s: non-JSON response (code %d) for body %q: %v", path, rec.Code, body, err)
	}
	rec2 := postFuzz(srv, path, body)
	if replaySame {
		if rec2.Code != rec.Code {
			t.Fatalf("POST %s: non-deterministic status for body %q: %d then %d", path, body, rec.Code, rec2.Code)
		}
		return
	}
	// A replay must never be applied twice: either it was already a
	// rejection (same status), or the replay of a successful control is
	// rejected.
	if rec.Code == 400 {
		if rec2.Code != 400 {
			t.Fatalf("POST %s: non-deterministic rejection for body %q: %d then %d", path, body, rec.Code, rec2.Code)
		}
	} else if rec2.Code != 400 {
		t.Fatalf("POST %s: replay of body %q applied twice: %d then %d", path, body, rec.Code, rec2.Code)
	}
}

// FuzzHandleSend feeds arbitrary bytes to POST /v1/send: the JSON body
// decoder plus the full envelope validation chain (address parsing,
// base64 field shapes, ciphertext bounds, signature verification,
// replay dedup, spam throttling).
func FuzzHandleSend(f *testing.F) {
	f.Add([]byte(seedSendEnvelope))                         // valid signed envelope
	f.Add([]byte(``))                                       // empty
	f.Add([]byte(`{`))                                      // truncated
	f.Add([]byte(`[]`))                                     // wrong top-level type
	f.Add([]byte(`{"to":123,"from":null,"sent_at":"now"}`)) // wrong field types
	f.Add([]byte(`{"to":"ed25519:","from":"ed25519:","eph":"","nonce":"","ct":"","sent_at":0,"sig":""}`))
	f.Add([]byte(`{"to":"group:AQIDBAUGBwgJCgsMDQ4PEA","kind":"group"}`))                        // group path, unsigned
	f.Add([]byte(`{"to":"ed25519:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg","kind":"weird"}`)) // bad kind
	f.Fuzz(func(t *testing.T, body []byte) {
		srv := fuzzRelayServer(t)
		checkFuzzHTTPResponse(t, srv, "/v1/send", body, true)
	})
}

// FuzzHandleGroupControl feeds arbitrary bytes to POST /v1/groups/control:
// the JSON body decoder plus group-ID parsing, action allow-listing,
// address parsing, epoch rules, and control-signature verification.
func FuzzHandleGroupControl(f *testing.F) {
	f.Add([]byte(seedGroupControlCreate)) // valid signed create
	f.Add([]byte(``))                     // empty
	f.Add([]byte(`{`))                    // truncated
	f.Add([]byte(`{"group":"group:AQIDBAUGBwgJCgsMDQ4PEA","action":"drop-table","admin":"ed25519:","epoch":-1,"sig":""}`))
	f.Add([]byte(`{"group":"not-a-group","action":"create","admin":"ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","epoch":1,"sig":"AA"}`))
	f.Add([]byte(`{"group":"group:AQIDBAUGBwgJCgsMDQ4PEA","action":"add","target":"not-an-address","admin":"ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw","epoch":2,"sig":"AA"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		srv := fuzzRelayServer(t)
		checkFuzzHTTPResponse(t, srv, "/v1/groups/control", body, false)
	})
}
