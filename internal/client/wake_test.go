// Tests for the built-in instant wake daemon (issue #42).
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptStep is one scripted /v1/inbox/subscribe response.
type scriptStep struct {
	status int
	body   string
	delay  time.Duration
}

// scriptedRelay serves a scripted sequence of subscribe responses and
// records the cursor each request carried.
type scriptedRelay struct {
	t       *testing.T
	mu      sync.Mutex
	steps   []scriptStep
	cursors []int64
}

func (s *scriptedRelay) handler(w http.ResponseWriter, r *http.Request) {
	c, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
	s.mu.Lock()
	s.cursors = append(s.cursors, c)
	step := s.steps[len(s.steps)-1]
	if len(s.cursors) <= len(s.steps) {
		step = s.steps[len(s.cursors)-1]
	}
	s.mu.Unlock()
	if step.delay > 0 {
		time.Sleep(step.delay)
	}
	if step.status == 0 {
		step.status = http.StatusOK
	}
	w.WriteHeader(step.status)
	fmt.Fprint(w, step.body)
}

func (s *scriptedRelay) seenCursors() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.cursors...)
}

func newScriptedRelay(t *testing.T, steps []scriptStep) (*httptest.Server, *scriptedRelay) {
	t.Helper()
	sr := &scriptedRelay{t: t, steps: steps}
	ts := httptest.NewServer(http.HandlerFunc(sr.handler))
	t.Cleanup(ts.Close)
	return ts, sr
}

func subMsg(id int64, from string) string {
	return fmt.Sprintf(`{"id":%d,"from":%q,"eph":"e","nonce":"n","ct":"c","sent_at":1700000000,"received_at":1700000001,"sig":"s"}`,
		id, from)
}

func subBody(msgs ...string) string {
	return fmt.Sprintf(`{"messages":[%s],"timeout":false}`, strings.Join(msgs, ","))
}

const subTimeoutBody = `{"messages":[],"timeout":true}`

// actionCall records one wake action invocation.
type actionCall struct {
	argv    []string
	payload []byte
}

type actionRecorder struct {
	mu    sync.Mutex
	calls []actionCall
}

func (r *actionRecorder) run(ctx context.Context, argv []string, payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, actionCall{argv: append([]string(nil), argv...), payload: append([]byte(nil), payload...)})
	return nil
}

func (r *actionRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// payloadMessages extracts the message ids from every recorded action.
func (r *actionRecorder) payloadIDs(t *testing.T) [][]int64 {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [][]int64
	for _, c := range r.calls {
		var p struct {
			Messages []WakeMessage `json:"messages"`
		}
		if err := json.Unmarshal(c.payload, &p); err != nil {
			t.Fatalf("bad wake payload: %v", err)
		}
		var ids []int64
		for _, m := range p.Messages {
			ids = append(ids, m.ID)
		}
		out = append(out, ids)
	}
	return out
}

func testWakeDaemon(t *testing.T, cl *Client, rec *actionRecorder, command []string) *WakeDaemon {
	t.Helper()
	d := NewWakeDaemon(cl, WakeDaemonConfig{
		Command:             command,
		Cooldown:            time.Minute,
		MaxActionsPerMinute: 100,
		PIDFile:             "", // no pidfile in tests
	}, nil)
	d.runAction = rec.run
	return d
}

// TestWakeDaemonDeliversPendingImmediately: messages already pending at
// the wake cursor fire one wake action right away, the cursor advances
// past them, and the reconnect carries the new cursor (no duplicates).
func TestWakeDaemonDeliversPendingImmediately(t *testing.T) {
	cfg := testConfig(t)
	ts, sr := newScriptedRelay(t, []scriptStep{
		{body: subBody(subMsg(1, "ed25519:alice"), subMsg(2, "ed25519:bob"))},
		{body: subTimeoutBody},
	})
	cfg.RelayURL = ts.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	rec := &actionRecorder{}
	d := testWakeDaemon(t, cl, rec, []string{"hook"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	time.Sleep(600 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down")
	}

	if n := rec.count(); n != 1 {
		t.Fatalf("wake actions = %d, want 1", n)
	}
	if ids := rec.payloadIDs(t); len(ids) != 1 || len(ids[0]) != 2 || ids[0][0] != 1 || ids[0][1] != 2 {
		t.Fatalf("payload ids = %v, want [[1 2]]", ids)
	}
	cursors := sr.seenCursors()
	if len(cursors) < 2 {
		t.Fatalf("relay saw %d subscribe calls, want >= 2", len(cursors))
	}
	if cursors[0] != 0 || cursors[1] != 2 {
		t.Fatalf("cursors = %v, want first 0 then 2 (no replay)", cursors)
	}
	// The cursor is persisted to disk, so a restarted daemon resumes.
	fresh, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if fresh.WakeCursor != 2 {
		t.Fatalf("persisted WakeCursor = %d, want 2", fresh.WakeCursor)
	}
}

// TestWakeDaemonTimeoutReconnectResumes: a server timeout is followed
// by an immediate re-subscribe from the same cursor; later messages
// arrive exactly once with no gaps.
func TestWakeDaemonTimeoutReconnectResumes(t *testing.T) {
	cfg := testConfig(t)
	cfg.WakeCursor = 4
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	ts, sr := newScriptedRelay(t, []scriptStep{
		{body: subTimeoutBody},
		{body: subBody(subMsg(5, "ed25519:alice"), subMsg(6, "ed25519:alice"))},
		{body: subTimeoutBody},
	})
	cfg.RelayURL = ts.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	rec := &actionRecorder{}
	d := testWakeDaemon(t, cl, rec, []string{"hook"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	time.Sleep(600 * time.Millisecond)
	cancel()
	<-done

	if n := rec.count(); n != 1 {
		t.Fatalf("wake actions = %d, want 1", n)
	}
	if ids := rec.payloadIDs(t); len(ids) != 1 || len(ids[0]) != 2 || ids[0][0] != 5 || ids[0][1] != 6 {
		t.Fatalf("payload ids = %v, want [[5 6]]", ids)
	}
	cursors := sr.seenCursors()
	if len(cursors) < 3 {
		t.Fatalf("relay saw %d subscribe calls, want >= 3", len(cursors))
	}
	// Timeout reconnects reuse the cursor; after delivery it advances.
	if cursors[0] != 4 || cursors[1] != 4 || cursors[2] != 6 {
		t.Fatalf("cursors = %v, want [4 4 6]", cursors)
	}
}

// TestWakeBackoffProgression: reconnect delays double and cap at
// maxWakeBackoff.
func TestWakeBackoffProgression(t *testing.T) {
	d := initialWakeBackoff
	var got []time.Duration
	for i := 0; i < 10; i++ {
		got = append(got, d)
		d = nextWakeBackoff(d)
	}
	want := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second,
		60 * time.Second, 60 * time.Second,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff[%d] = %v, want %v (full sequence %v)", i, got[i], want[i], got)
		}
	}
}

// TestWakeJitterBounds: full jitter always lands inside [0, d].
func TestWakeJitterBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if j := wakeJitter(3 * time.Second); j < 0 || j > 3*time.Second {
			t.Fatalf("jitter out of bounds: %v", j)
		}
	}
	if wakeJitter(0) != 0 {
		t.Fatal("jitter(0) != 0")
	}
}

// TestWakeDaemonRecoversFromErrors: transport failures are retried
// (not fatal, not a hot loop) and the daemon recovers to deliver
// later messages.
func TestWakeDaemonRecoversFromErrors(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := newScriptedRelay(t, []scriptStep{
		{status: http.StatusInternalServerError, body: `{"error":"boom"}`},
		{status: http.StatusInternalServerError, body: `{"error":"boom"}`},
		{body: subTimeoutBody, delay: 300 * time.Millisecond},
		{body: subBody(subMsg(1, "ed25519:alice")), delay: 300 * time.Millisecond},
		{body: subTimeoutBody, delay: 300 * time.Millisecond},
	})
	cfg.RelayURL = ts.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	rec := &actionRecorder{}
	d := testWakeDaemon(t, cl, rec, []string{"hook"})

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	start := time.Now()
	if err := d.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The message after the failures was still delivered exactly once.
	if n := rec.count(); n != 1 {
		t.Fatalf("wake actions = %d, want 1", n)
	}
	if ids := rec.payloadIDs(t); len(ids) != 1 || len(ids[0]) != 1 || ids[0][0] != 1 {
		t.Fatalf("payload ids = %v, want [[1]]", ids)
	}
	t.Logf("recovered and delivered in %v", time.Since(start))
}

// TestWakeActionStdinNotShell is the hostile-input regression test: a
// payload full of shell metacharacters is delivered to the action on
// stdin, verbatim. If the implementation ever interpolated message
// content into a shell string, the sentinel file would be created and
// this test would fail.
func TestWakeActionStdinNotShell(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "pwned")
	out := filepath.Join(dir, "stdin-capture")
	hostileFrom := `ed25519:attacker"; $(touch ` + sentinel + `) ; ` + "`touch " + sentinel + "`" + ` ; $(echo INJECTED)`
	payload, err := json.Marshal(map[string]any{
		"messages": []map[string]any{
			{"id": 1, "from": hostileFrom, "sent_at": 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := defaultRunWakeAction(ctx, []string{"tee", out}, payload); err != nil {
		t.Fatalf("runAction: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("stdin got %q, want payload verbatim", got)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("hostile payload achieved execution: sentinel file exists")
	}
}

// TestWakeCooldownBurst: a burst of messages from one sender in a single
// round fires exactly one wake action, and a follow-up inside the
// cooldown fires none — while every message is still eligible for the
// payload when it does fire.
func TestWakeCooldownBurst(t *testing.T) {
	cfg := testConfig(t)
	cl := New(cfg)
	rec := &actionRecorder{}
	d := testWakeDaemon(t, cl, rec, []string{"hook"})

	ctx := context.Background()
	var burst []WakeMessage
	for i := int64(1); i <= 5; i++ {
		burst = append(burst, WakeMessage{ID: i, From: "ed25519:chatty", SentAt: 1})
	}
	d.handleMessages(ctx, burst)
	if n := rec.count(); n != 1 {
		t.Fatalf("burst: wake actions = %d, want 1", n)
	}
	if ids := rec.payloadIDs(t); len(ids[0]) != 5 {
		t.Fatalf("burst payload has %d messages, want 5", len(ids[0]))
	}
	// Another message from the same sender inside the cooldown: no action.
	d.handleMessages(ctx, []WakeMessage{{ID: 6, From: "ed25519:chatty", SentAt: 2}})
	if n := rec.count(); n != 1 {
		t.Fatalf("after cooldown hit: wake actions = %d, want still 1", n)
	}
	// A different sender is not in cooldown: fires.
	d.handleMessages(ctx, []WakeMessage{{ID: 7, From: "ed25519:other", SentAt: 3}})
	if n := rec.count(); n != 2 {
		t.Fatalf("other sender: wake actions = %d, want 2", n)
	}
}

// TestWakePolicySuppressions: blocked, dismissed, held-for-review, and
// spam-throttled senders never fire the wake action.
func TestWakePolicySuppressions(t *testing.T) {
	cfg := testConfig(t)
	mkaddr := func() string {
		id, err := NewIdentity("")
		if err != nil {
			t.Fatal(err)
		}
		return id.Address
	}
	blocked, dismissed, stranger, spammer, bursty := mkaddr(), mkaddr(), mkaddr(), mkaddr(), mkaddr()
	if err := cfg.Block(blocked); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Dismiss(dismissed); err != nil {
		t.Fatal(err)
	}
	// "bursty" is a contact so contacts mode does not hold it; the
	// rate_limited flag alone must not suppress the wake.
	if err := cfg.AddContact("bursty", bursty); err != nil {
		t.Fatal(err)
	}
	cfg.DMPolicy = DMPolicyContacts // strangers are held for review
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	rec := &actionRecorder{}
	d := testWakeDaemon(t, cl, rec, []string{"hook"})

	ctx := context.Background()
	d.handleMessages(ctx, []WakeMessage{
		{ID: 1, From: blocked, SentAt: 1},
		{ID: 2, From: dismissed, SentAt: 1},
		{ID: 3, From: stranger, SentAt: 1}, // held for review in contacts mode
		{ID: 4, From: spammer, SentAt: 1, SenderFlags: []string{"reported"}},
		{ID: 5, From: bursty, SentAt: 1, SenderFlags: []string{"rate_limited"}},
	})
	// Only the merely-bursty sender is eligible: one action, one message.
	if n := rec.count(); n != 1 {
		t.Fatalf("wake actions = %d, want 1", n)
	}
	ids := rec.payloadIDs(t)
	if len(ids) != 1 || len(ids[0]) != 1 || ids[0][0] != 5 {
		t.Fatalf("payload ids = %v, want [[5]]", ids)
	}
}

// TestWakeGlobalRateLimit: many distinct senders cannot wake-storm the
// operator past the per-minute cap.
func TestWakeGlobalRateLimit(t *testing.T) {
	cfg := testConfig(t)
	cl := New(cfg)
	rec := &actionRecorder{}
	d := NewWakeDaemon(cl, WakeDaemonConfig{
		Command:             []string{"hook"},
		Cooldown:            time.Millisecond,
		MaxActionsPerMinute: 3,
	}, nil)
	d.runAction = rec.run

	ctx := context.Background()
	for i := int64(1); i <= 5; i++ {
		d.handleMessages(ctx, []WakeMessage{{ID: i, From: fmt.Sprintf("ed25519:sender%d", i), SentAt: 1}})
	}
	if n := rec.count(); n != 3 {
		t.Fatalf("wake actions = %d, want capped at 3", n)
	}
}

// TestSubscribeParsesResponse checks one long-poll round: parsing,
// lastID, and the timeout flag.
func TestSubscribeParsesResponse(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := newScriptedRelay(t, []scriptStep{
		{body: subBody(subMsg(9, "ed25519:alice"))},
	})
	cfg.RelayURL = ts.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)

	msgs, lastID, timedOut, err := cl.Subscribe(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if timedOut || len(msgs) != 1 || msgs[0].ID != 9 || msgs[0].From != "ed25519:alice" {
		t.Fatalf("msgs=%+v timedOut=%v", msgs, timedOut)
	}
	if lastID != 9 {
		t.Fatalf("lastID = %d, want 9", lastID)
	}
}

// TestSubscribeSurfacesRelayErrors: a 500 is an error, not a timeout.
func TestSubscribeSurfacesRelayErrors(t *testing.T) {
	cfg := testConfig(t)
	ts, _ := newScriptedRelay(t, []scriptStep{
		{status: http.StatusInternalServerError, body: `{"error":"boom"}`},
	})
	cfg.RelayURL = ts.URL
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)

	_, _, _, err := cl.Subscribe(context.Background(), 0)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want relay error", err)
	}
}

// TestWakeLockExclusive: a second daemon refuses to start while the
// first holds the pidfile lock (unix only; other platforms skip).
func TestWakeLockExclusive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock-based pidfile lock is unix-only")
	}
	path := filepath.Join(t.TempDir(), "wake.pid")
	release, err := acquireWakeLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := acquireWakeLock(path); err == nil {
		t.Fatal("second lock acquisition succeeded, want refusal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if pid := strings.TrimSpace(string(data)); pid != fmt.Sprint(os.Getpid()) {
		t.Fatalf("pidfile = %q, want %d", pid, os.Getpid())
	}
}

// TestWakeBridgedMarkedInPayload: a message from a pinned bridge
// gateway still wakes the daemon (the bridge is the operator's own
// channel — silently dropping the operator's own messages would break
// the bridge), but the wake payload marks it bridged (issues #96/#97)
// so the woken agent/harness cannot mistake it for trusted input. The
// daemon never decrypts bodies, so the mark comes from the pin list
// alone — the layer that needs no sender cooperation.
func TestWakeBridgedMarkedInPayload(t *testing.T) {
	cfg := testConfig(t)
	bridgeAddr := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	peerAddr := "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if err := cfg.AddBridgeGateway(bridgeAddr); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	rec := &actionRecorder{}
	d := testWakeDaemon(t, cl, rec, []string{"hook"})

	ctx := context.Background()
	d.handleMessages(ctx, []WakeMessage{
		{ID: 1, From: bridgeAddr, SentAt: 1},
		{ID: 2, From: peerAddr, SentAt: 1},
	})
	// Both messages are eligible: one wake action carrying both.
	if n := rec.count(); n != 1 {
		t.Fatalf("wake actions = %d, want 1", n)
	}
	rec.mu.Lock()
	payload := append([]byte(nil), rec.calls[0].payload...)
	rec.mu.Unlock()
	var p struct {
		Messages []WakeMessage `json:"messages"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatalf("bad wake payload: %v", err)
	}
	if len(p.Messages) != 2 {
		t.Fatalf("payload messages = %d, want 2", len(p.Messages))
	}
	byID := map[int64]WakeMessage{}
	for _, m := range p.Messages {
		byID[m.ID] = m
	}
	if !byID[1].Bridged {
		t.Error("message from pinned bridge gateway not marked bridged in wake payload")
	}
	if byID[2].Bridged {
		t.Error("ordinary message wrongly marked bridged in wake payload")
	}
}

// TestWakeSuppressBridgedActions: with SuppressBridgedActions, a
// bridged-only batch never fires the wake command (issue #97), while a
// mixed batch fires carrying only the non-bridged messages. The daemon
// is the one place Courier autonomously triggers code on message
// arrival, so this is the structural enforcement point for hooks whose
// command does more than read-only ingestion.
func TestWakeSuppressBridgedActions(t *testing.T) {
	cfg := testConfig(t)
	bridgeAddr := "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	peerAddr := "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if err := cfg.AddBridgeGateway(bridgeAddr); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	ctx := context.Background()
	newDaemon := func() (*WakeDaemon, *actionRecorder) {
		rec := &actionRecorder{}
		d := testWakeDaemon(t, cl, rec, []string{"hook"})
		d.cfg.SuppressBridgedActions = true
		return d, rec
	}
	payloadIDs := func(rec *actionRecorder) []int64 {
		t.Helper()
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if len(rec.calls) != 1 {
			t.Fatalf("actions = %d, want 1", len(rec.calls))
		}
		var p struct {
			Messages []WakeMessage `json:"messages"`
		}
		if err := json.Unmarshal(rec.calls[0].payload, &p); err != nil {
			t.Fatalf("bad wake payload: %v", err)
		}
		var ids []int64
		for _, m := range p.Messages {
			ids = append(ids, m.ID)
		}
		return ids
	}

	// Bridged-only batch: the command never fires.
	d, rec := newDaemon()
	d.handleMessages(ctx, []WakeMessage{{ID: 1, From: bridgeAddr, SentAt: 1}})
	if n := rec.count(); n != 0 {
		t.Fatalf("bridged-only batch fired %d actions, want 0", n)
	}

	// Mixed batch: fires once, with the bridged message stripped.
	d, rec = newDaemon()
	d.handleMessages(ctx, []WakeMessage{
		{ID: 1, From: bridgeAddr, SentAt: 1},
		{ID: 2, From: peerAddr, SentAt: 1},
	})
	if ids := payloadIDs(rec); len(ids) != 1 || ids[0] != 2 {
		t.Fatalf("suppressed payload ids = %v, want [2]", ids)
	}

	// Knob off (default): bridged messages still wake, marked bridged.
	recDefault := &actionRecorder{}
	dDefault := testWakeDaemon(t, cl, recDefault, []string{"hook"})
	dDefault.handleMessages(ctx, []WakeMessage{{ID: 3, From: bridgeAddr, SentAt: 1}})
	if ids := payloadIDs(recDefault); len(ids) != 1 || ids[0] != 3 {
		t.Fatalf("default payload ids = %v, want [3]", ids)
	}
}
