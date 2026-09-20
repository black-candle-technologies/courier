// Tests for the long-poll inbox subscription endpoint (issue #42).
package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
	"github.com/black-candle-technologies/courier/internal/envelope"
)

func signedSubscribeURL(t *testing.T, id *crypto.Identity, cursor int64) string {
	t.Helper()
	ts := time.Now().Unix()
	sig := id.Sign(envelope.SubscribeRequest(id.EdPub[:], cursor, ts))
	return fmt.Sprintf("/v1/inbox/subscribe?to=%s&cursor=%d&ts=%d&sig=%s",
		crypto.FormatAddress(id.EdPub[:]), cursor, ts, b64.EncodeToString(sig))
}

type subscribeResult struct {
	Messages []map[string]any `json:"messages"`
	Timeout  bool             `json:"timeout"`
}

func decodeSubscribe(t *testing.T, body io.Reader) subscribeResult {
	t.Helper()
	var r subscribeResult
	if err := json.NewDecoder(body).Decode(&r); err != nil {
		t.Fatalf("decode subscribe response: %v", err)
	}
	return r
}

// subscribeHeld starts a subscription request against a live test
// server and returns a channel for its eventual response.
func subscribeHeld(t *testing.T, ts *httptest.Server, url string) <-chan subscribeResult {
	t.Helper()
	done := make(chan subscribeResult, 1)
	go func() {
		resp, err := http.Get(ts.URL + url)
		if err != nil {
			t.Errorf("subscribe GET: %v", err)
			close(done)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("subscribe: got %d, body %s", resp.StatusCode, body)
			close(done)
			return
		}
		done <- decodeSubscribe(t, resp.Body)
	}()
	return done
}

// TestSubscribeDeliversNewEnvelope is the core instant-wake acceptance
// test: a held subscription must receive a newly arrived envelope
// within ~2s of its send.
func TestSubscribeDeliversNewEnvelope(t *testing.T) {
	srv := testServer(t)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	done := subscribeHeld(t, ts, signedSubscribeURL(t, bob, 0))
	// Give the handler time to register before the send lands; the
	// registration-before-check ordering makes this robust anyway.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	if rec := postSend(t, srv, makeEnvelope(t, alice, bob, "wake me")); rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d", rec.Code)
	}
	select {
	case r, ok := <-done:
		if !ok {
			t.Fatal("subscribe request failed")
		}
		elapsed := time.Since(start)
		if r.Timeout {
			t.Fatal("subscription returned timeout instead of the new message")
		}
		if len(r.Messages) != 1 {
			t.Fatalf("got %d messages, want 1", len(r.Messages))
		}
		if r.Messages[0]["from"] != crypto.FormatAddress(alice.EdPub[:]) {
			t.Fatalf("wrong sender: %v", r.Messages[0]["from"])
		}
		if elapsed > 2*time.Second {
			t.Fatalf("delivery took %v, want < 2s", elapsed)
		}
		t.Logf("held subscription delivered in %v", elapsed)
	case <-time.After(10 * time.Second):
		t.Fatal("held subscription was not woken by the send")
	}
}

// TestSubscribeReturnsPendingImmediately covers the fast path: messages
// already pending at the cursor return without waiting, which is what
// makes reconnects gap-free.
func TestSubscribeReturnsPendingImmediately(t *testing.T) {
	srv := testServer(t)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	if rec := postSend(t, srv, makeEnvelope(t, alice, bob, "one")); rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d", rec.Code)
	}
	if rec := postSend(t, srv, makeEnvelope(t, alice, bob, "two")); rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d", rec.Code)
	}

	// Cursor past the first envelope: only the second is pending.
	start := time.Now()
	resp, err := http.Get(ts.URL + signedSubscribeURL(t, bob, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := decodeSubscribe(t, resp.Body)
	if r.Timeout || len(r.Messages) != 1 {
		t.Fatalf("got timeout=%v messages=%d, want 1 message", r.Timeout, len(r.Messages))
	}
	if id := int64(r.Messages[0]["id"].(float64)); id != 2 {
		t.Fatalf("got message id %d, want 2", id)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pending messages took %v, want immediate", elapsed)
	}
}

// TestSubscribeTimeout verifies the server-side deadline: with nothing
// new, the held request ends with timeout=true instead of hanging.
func TestSubscribeTimeout(t *testing.T) {
	old := SubscribeTimeout
	SubscribeTimeout = 150 * time.Millisecond
	defer func() { SubscribeTimeout = old }()

	srv := testServer(t)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()
	bob, _ := crypto.GenerateIdentity()

	start := time.Now()
	resp, err := http.Get(ts.URL + signedSubscribeURL(t, bob, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := decodeSubscribe(t, resp.Body)
	if !r.Timeout || len(r.Messages) != 0 {
		t.Fatalf("got timeout=%v messages=%d, want clean timeout", r.Timeout, len(r.Messages))
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v, want ~150ms", elapsed)
	}
}

// TestSubscribeDuplicateSendDoesNotWake ensures replayed envelopes
// (acknowledged, not stored) do not wake subscribers: there is no new
// message.
func TestSubscribeDuplicateSendDoesNotWake(t *testing.T) {
	old := SubscribeTimeout
	SubscribeTimeout = 200 * time.Millisecond
	defer func() { SubscribeTimeout = old }()

	srv := testServer(t)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	env := makeEnvelope(t, alice, bob, "once")
	if rec := postSend(t, srv, env); rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d", rec.Code)
	}
	// Cursor past the stored message; the held subscription has nothing
	// pending.
	done := subscribeHeld(t, ts, signedSubscribeURL(t, bob, 1))
	time.Sleep(100 * time.Millisecond)
	// Replay the identical envelope: acknowledged as duplicate, not stored.
	if rec := postSend(t, srv, env); rec.Code != http.StatusCreated {
		t.Fatalf("resend: got %d", rec.Code)
	}
	select {
	case r, ok := <-done:
		if !ok {
			t.Fatal("subscribe request failed")
		}
		if !r.Timeout {
			t.Fatalf("duplicate send woke the subscription: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscription did not return after deadline")
	}
}

// TestSubscribeRequiresValidSignature mirrors the inbox auth: only the
// address owner can hold a subscription on their inbox.
func TestSubscribeRequiresValidSignature(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	// Signed by alice for bob's address.
	ts := time.Now().Unix()
	sig := alice.Sign(envelope.SubscribeRequest(bob.EdPub[:], 0, ts))
	url := fmt.Sprintf("/v1/inbox/subscribe?to=%s&cursor=0&ts=%d&sig=%s",
		crypto.FormatAddress(bob.EdPub[:]), ts, b64.EncodeToString(sig))
	req := httptest.NewRequest("GET", url, nil)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}

	// Stale timestamp.
	old := time.Now().Unix() - 1000
	sig = bob.Sign(envelope.SubscribeRequest(bob.EdPub[:], 0, old))
	url = fmt.Sprintf("/v1/inbox/subscribe?to=%s&cursor=0&ts=%d&sig=%s",
		crypto.FormatAddress(bob.EdPub[:]), old, b64.EncodeToString(sig))
	req = httptest.NewRequest("GET", url, nil)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("stale ts: got %d, want 400", rec.Code)
	}
}

// TestSubscribePerIdentityCap ensures a runaway client cannot hold
// unbounded subscriptions.
func TestSubscribePerIdentityCap(t *testing.T) {
	old := SubscribeTimeout
	SubscribeTimeout = 500 * time.Millisecond
	defer func() { SubscribeTimeout = old }()

	srv := testServer(t)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()
	bob, _ := crypto.GenerateIdentity()

	var wg sync.WaitGroup
	for i := 0; i < maxSubscribersPerIdentity; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + signedSubscribeURL(t, bob, 0))
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	time.Sleep(300 * time.Millisecond) // let them all register

	resp, err := http.Get(ts.URL + signedSubscribeURL(t, bob, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", resp.StatusCode)
	}
	wg.Wait()
}

// TestSubscribeResponseShapeMatchesInbox ensures the subscribe message
// objects carry the same fields as GET /v1/inbox, so clients share one
// parser.
func TestSubscribeResponseShapeMatchesInbox(t *testing.T) {
	srv := testServer(t)
	alice, _ := crypto.GenerateIdentity()
	bob, _ := crypto.GenerateIdentity()

	if rec := postSend(t, srv, makeEnvelope(t, alice, bob, "shape")); rec.Code != http.StatusCreated {
		t.Fatalf("send: got %d", rec.Code)
	}
	routes := srv.Routes()

	// Subscribe as bob via the test server directly.
	subReq := httptest.NewRequest("GET", signedSubscribeURL(t, bob, 0), nil)
	subRec := httptest.NewRecorder()
	routes.ServeHTTP(subRec, subReq)
	var sub subscribeResult
	if err := json.NewDecoder(subRec.Body).Decode(&sub); err != nil {
		t.Fatal(err)
	}

	inReq := httptest.NewRequest("GET", signedInboxURL(t, bob, 0, 50), nil)
	inRec := httptest.NewRecorder()
	routes.ServeHTTP(inRec, inReq)
	var inbox struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.NewDecoder(inRec.Body).Decode(&inbox); err != nil {
		t.Fatal(err)
	}
	if len(sub.Messages) != 1 || len(inbox.Messages) != 1 {
		t.Fatalf("sub=%d inbox=%d, want 1 each", len(sub.Messages), len(inbox.Messages))
	}
	for k := range inbox.Messages[0] {
		if _, ok := sub.Messages[0][k]; !ok {
			t.Fatalf("subscribe message missing inbox field %q", k)
		}
	}
}
