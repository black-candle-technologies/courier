// Tests for shared agent state (issue #49).
package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

func TestParseStatePayloadValid(t *testing.T) {
	raw, _ := json.Marshal(statePayload{
		Magic: stateMagic, Type: "state", Version: statePayloadVersion,
		Events: []StateEvent{{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "hello"}},
	})
	p, ok := parseStatePayload(raw)
	if !ok {
		t.Fatal("valid state payload rejected")
	}
	if len(p.Events) != 1 || p.Events[0].Title != "hello" {
		t.Fatalf("events not parsed: %+v", p.Events)
	}
}

func TestParseStatePayloadRejects(t *testing.T) {
	valid := func() []byte {
		raw, _ := json.Marshal(statePayload{
			Magic: stateMagic, Type: "state", Version: statePayloadVersion,
			Events: []StateEvent{{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "x"}},
		})
		return raw
	}
	cases := map[string][]byte{
		"chat text":        []byte("just a chat message"),
		"empty":            []byte(""),
		"empty events":     []byte(`{"cs":1,"t":"state","v":1,"events":[]}`),
		"wrong magic":      []byte(`{"cs":2,"t":"state","v":1,"events":[]}`),
		"wrong type":       []byte(`{"cs":1,"t":"chat","v":1,"events":[]}`),
		"group dm payload": []byte(`{"cg":1,"t":"key","g":"abc"}`),
	}
	for name, raw := range cases {
		if _, ok := parseStatePayload(raw); ok {
			t.Errorf("%s: should not parse as state payload", name)
		}
	}
	// Unknown event kind fails the whole payload: it must fall through
	// to chat, never be half-applied.
	bad := valid()
	var p statePayload
	if err := json.Unmarshal(bad, &p); err != nil {
		t.Fatal(err)
	}
	p.Events[0].Kind = "teleport"
	raw, _ := json.Marshal(p)
	if _, ok := parseStatePayload(raw); ok {
		t.Error("unknown event kind should fail the whole payload")
	}
	// Batch over the cap is rejected.
	p.Events[0].Kind = StateEventNoteAdd
	for i := 0; i < maxStateEventsPerPayload; i++ {
		p.Events = append(p.Events, StateEvent{Kind: StateEventNoteAdd, Seq: int64(i + 2), SentAt: 100, NoteID: "n", Title: "x"})
	}
	raw, _ = json.Marshal(p)
	if _, ok := parseStatePayload(raw); ok {
		t.Error("oversized batch should be rejected")
	}
}

func TestValidateStateEvent(t *testing.T) {
	bad := []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 0, NoteID: "n", Title: "x"}, // seq 0
		{Kind: "nope", Seq: 1},                                                        // unknown kind
		{Kind: StateEventNoteAdd, Seq: 1, NoteID: "n"},                                // no title/body
		{Kind: StateEventNoteAdd, Seq: 1, Title: "x"},                                 // no note id
		{Kind: StateEventTaskAdd, Seq: 1, TaskID: "t"},                                // no title
		{Kind: StateEventTaskAdd, Seq: 1, TaskID: "t", Title: "x"},                    // no assignee
		{Kind: StateEventTaskAdd, Seq: 1, TaskID: "t", Title: "x", Assignee: "bogus"}, // bad assignee
		{Kind: StateEventTaskDone, Seq: 1},                                            // no task id
	}
	for i, ev := range bad {
		if err := validateStateEvent(&ev); err == nil {
			t.Errorf("case %d (%s): expected validation error", i, ev.Kind)
		}
	}
	goodAssignee, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	good := StateEvent{Kind: StateEventTaskAdd, Seq: 1, TaskID: "t", Title: "x", Assignee: goodAssignee.Address}
	if err := validateStateEvent(&good); err != nil {
		t.Errorf("valid task-add rejected: %v", err)
	}
}

func le(author string, ev StateEvent) LoggedStateEvent {
	return LoggedStateEvent{Author: author, StateEvent: ev}
}

func TestFoldNotesLWW(t *testing.T) {
	const alice, bob = "alice", "bob"
	log := []LoggedStateEvent{
		le(alice, StateEvent{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "groceries"}),
		le(bob, StateEvent{Kind: StateEventNoteDone, Seq: 1, SentAt: 200, NoteID: "n1", Done: true}),
		le(alice, StateEvent{Kind: StateEventNoteDone, Seq: 2, SentAt: 300, NoteID: "n1", Done: false}),
	}
	v := foldStateEvents(log)
	n := v.Notes["n1"]
	if n == nil {
		t.Fatal("note missing")
	}
	if n.Done {
		t.Error("LWW: later reopen (sentAt 300) should win over done (sentAt 200)")
	}
	if n.Author != alice || n.Title != "groceries" {
		t.Errorf("note attribution/title wrong: %+v", n)
	}
	// Done toggle for an unknown note is ignored, not fatal.
	v2 := foldStateEvents([]LoggedStateEvent{
		le(alice, StateEvent{Kind: StateEventNoteDone, Seq: 1, SentAt: 100, NoteID: "ghost", Done: true}),
	})
	if len(v2.Notes) != 0 {
		t.Errorf("toggle of unknown note should be ignored, got %d notes", len(v2.Notes))
	}
}

func TestFoldTaskLifecycle(t *testing.T) {
	const alice, bob = "alice", "bob"
	log := []LoggedStateEvent{
		le(alice, StateEvent{Kind: StateEventTaskAdd, Seq: 1, SentAt: 100, TaskID: "t1", Title: "deploy", Assignee: bob}),
		// Unauthorized: alice is not the assignee, so her task-done is ignored.
		le(alice, StateEvent{Kind: StateEventTaskDone, Seq: 2, SentAt: 150, TaskID: "t1"}),
		// Unauthorized: bob is not the assigner, so his reassign is ignored.
		le(bob, StateEvent{Kind: StateEventTaskAssign, Seq: 1, SentAt: 160, TaskID: "t1", Assignee: alice}),
		le(bob, StateEvent{Kind: StateEventTaskDone, Seq: 2, SentAt: 200, TaskID: "t1"}),
		le(alice, StateEvent{Kind: StateEventTaskReopen, Seq: 3, SentAt: 300, TaskID: "t1"}),
		le(alice, StateEvent{Kind: StateEventTaskAssign, Seq: 4, SentAt: 400, TaskID: "t1", Assignee: alice}),
		le(alice, StateEvent{Kind: StateEventTaskDone, Seq: 5, SentAt: 500, TaskID: "t1"}),
	}
	v := foldStateEvents(log)
	tk := v.Tasks["t1"]
	if tk == nil {
		t.Fatal("task missing")
	}
	if tk.State != StateTaskDone {
		t.Errorf("task should be done, got %q", tk.State)
	}
	if tk.Assignee != alice {
		t.Errorf("assignee should be alice after authorized reassign, got %q", tk.Assignee)
	}
	if tk.DoneBy != alice {
		t.Errorf("doneBy should be alice, got %q", tk.DoneBy)
	}
	if tk.Assigner != alice {
		t.Errorf("assigner should stay alice, got %q", tk.Assigner)
	}
	// The unauthorized mid-log transitions must not have taken effect:
	// check an intermediate fold stops at "open" before bob's done.
	vMid := foldStateEvents(log[:3])
	if vMid.Tasks["t1"].State != StateTaskOpen {
		t.Errorf("unauthorized task-done by non-assignee took effect: %q", vMid.Tasks["t1"].State)
	}
	if vMid.Tasks["t1"].Assignee != bob {
		t.Errorf("unauthorized task-assign by non-assigner took effect: %q", vMid.Tasks["t1"].Assignee)
	}
}

func TestFoldDeterministicAcrossArrivalOrder(t *testing.T) {
	const alice, bob = "alice", "bob"
	events := []LoggedStateEvent{
		le(alice, StateEvent{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "a"}),
		le(bob, StateEvent{Kind: StateEventNoteAdd, Seq: 1, SentAt: 110, NoteID: "n2", Title: "b"}),
		le(alice, StateEvent{Kind: StateEventTaskAdd, Seq: 2, SentAt: 120, TaskID: "t1", Title: "x", Assignee: bob}),
		le(bob, StateEvent{Kind: StateEventNoteDone, Seq: 2, SentAt: 130, NoteID: "n1", Done: true}),
		le(bob, StateEvent{Kind: StateEventTaskDone, Seq: 3, SentAt: 140, TaskID: "t1"}),
	}
	want := foldStateEvents(events)
	// Reverse arrival order must fold to the same view.
	rev := make([]LoggedStateEvent, len(events))
	for i, e := range events {
		rev[len(events)-1-i] = e
	}
	got := foldStateEvents(rev)
	if len(got.Notes) != len(want.Notes) || len(got.Tasks) != len(want.Tasks) {
		t.Fatalf("order-dependent fold: %+v vs %+v", got, want)
	}
	if !got.Notes["n1"].Done || got.Tasks["t1"].State != StateTaskDone {
		t.Errorf("reversed fold diverged: %+v", got)
	}
}

func TestApplyStateEventsIdempotent(t *testing.T) {
	cfg := testConfig(t)
	c := New(cfg)
	peerCfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer := peerCfg.Address
	evs := []StateEvent{{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "x"}}
	a1, err := c.applyStateEvents(peer, peer, evs)
	if err != nil {
		t.Fatal(err)
	}
	if len(a1) != 1 {
		t.Fatalf("first apply: got %d, want 1", len(a1))
	}
	a2, err := c.applyStateEvents(peer, peer, evs)
	if err != nil {
		t.Fatal(err)
	}
	if len(a2) != 0 {
		t.Fatalf("re-apply: got %d new, want 0 (idempotent)", len(a2))
	}
	v, err := c.StateConversation(peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Notes) != 1 {
		t.Fatalf("want 1 note, got %d", len(v.Notes))
	}
}

func TestStateCompact(t *testing.T) {
	cfg := testConfig(t)
	c := New(cfg)
	peerCfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer := peerCfg.Address
	now := time.Now().Unix()
	old := now - 100*86400
	_, err = c.applyStateEvents(peer, peer, []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, SentAt: old, NoteID: "n-old", Title: "ancient"},
		{Kind: StateEventNoteDone, Seq: 2, SentAt: old + 10, NoteID: "n-old", Done: true},
		{Kind: StateEventNoteAdd, Seq: 3, SentAt: now, NoteID: "n-new", Title: "fresh"},
		{Kind: StateEventTaskAdd, Seq: 4, SentAt: old, TaskID: "t-old", Title: "keep me", Assignee: peer},
	})
	if err != nil {
		t.Fatal(err)
	}
	dropped, err := c.StateCompact(peer, 90)
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 (the old note events)", dropped)
	}
	v, err := c.StateConversation(peer)
	if err != nil {
		t.Fatal(err)
	}
	// The compacted note survives via the snapshot, still done.
	n := v.Notes["n-old"]
	if n == nil || !n.Done || n.Title != "ancient" {
		t.Errorf("compacted note lost or wrong: %+v", n)
	}
	if v.Notes["n-new"] == nil {
		t.Error("new note missing after compact")
	}
	// Task events are never compacted.
	if v.Tasks["t-old"] == nil {
		t.Error("task event was compacted; tasks must be archived, not pruned")
	}
	// Toggling the compacted note still works (post-snapshot event).
	_, err = c.applyStateEvents(peer, peer, []StateEvent{
		{Kind: StateEventNoteDone, Seq: 5, SentAt: now, NoteID: "n-old", Done: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	v, _ = c.StateConversation(peer)
	if v.Notes["n-old"].Done {
		t.Error("post-compact toggle did not apply")
	}
}

func TestStateSearch(t *testing.T) {
	cfg := testConfig(t)
	c := New(cfg)
	peerCfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer := peerCfg.Address
	_, err = c.applyStateEvents(peer, peer, []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "Grocery List", Body: "milk and eggs"},
		{Kind: StateEventTaskAdd, Seq: 2, SentAt: 100, TaskID: "t1", Title: "Deploy Relay", Assignee: peer},
	})
	if err != nil {
		t.Fatal(err)
	}
	notes, tasks, err := c.StateSearch(peer, "grocery")
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || len(tasks) != 0 {
		t.Errorf("search grocery: notes=%d tasks=%d, want 1/0", len(notes), len(tasks))
	}
	notes, tasks, err = c.StateSearch(peer, "RELAY") // case-insensitive
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 || len(tasks) != 1 {
		t.Errorf("search RELAY: notes=%d tasks=%d, want 0/1", len(notes), len(tasks))
	}
	_, _, err = c.StateSearch(peer, "zzz")
	if err != nil {
		t.Fatal(err)
	}
}

func TestResolveStateID(t *testing.T) {
	v := &StateView{
		Notes: map[string]*StateNote{"abcdef1234": {}, "abcfff9999": {}},
		Tasks: map[string]*StateTask{"deadbeef00": {}},
	}
	id, kind, err := resolveStateID(v, "abcdef1234")
	if err != nil || id != "abcdef1234" || kind != "note" {
		t.Errorf("exact: %q %q %v", id, kind, err)
	}
	id, kind, err = resolveStateID(v, "abcdef")
	if err != nil || id != "abcdef1234" || kind != "note" {
		t.Errorf("prefix: %q %q %v", id, kind, err)
	}
	id, kind, err = resolveStateID(v, "dead")
	if err != nil || id != "deadbeef00" || kind != "task" {
		t.Errorf("task prefix: %q %q %v", id, kind, err)
	}
	if _, _, err = resolveStateID(v, "abc"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("ambiguous prefix should error, got %v", err)
	}
	if _, _, err = resolveStateID(v, "zzz"); err == nil {
		t.Error("unknown prefix should error")
	}
}

func TestDefaultAssignee(t *testing.T) {
	cfg := testConfig(t)
	c := New(cfg)
	peerCfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer := peerCfg.Address
	// Empty defaults to self.
	a, err := c.defaultAssignee(peer, "")
	if err != nil || a != cfg.Address {
		t.Errorf("default: %q %v", a, err)
	}
	// Peer is allowed.
	a, err = c.defaultAssignee(peer, peer)
	if err != nil || a != peer {
		t.Errorf("peer: %q %v", a, err)
	}
	// Third party is rejected: nobody could ever complete the task.
	other, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.defaultAssignee(peer, other.Address); err == nil {
		t.Error("third-party assignee should be rejected")
	}
	// Garbage is rejected.
	if _, err = c.defaultAssignee(peer, "not-an-address"); err == nil {
		t.Error("bad address should be rejected")
	}
}

func TestStateEventIDUnique(t *testing.T) {
	if stateEventID("a", 1) == stateEventID("a", 2) || stateEventID("a", 1) == stateEventID("b", 1) {
		t.Error("event ids must be unique per (author, seq)")
	}
}

// --- wire end-to-end: state events ride inside encrypted DMs ---

// stateFixtureEnvelope seals a state payload for the recipient cfg as
// sender, ready to be served on a mock relay.
func stateFixtureEnvelope(t *testing.T, sender *crypto.Identity, cfg *Config, id int64, events []StateEvent) map[string]any {
	t.Helper()
	raw, err := json.Marshal(statePayload{Magic: stateMagic, Type: "state", Version: statePayloadVersion, Events: events})
	if err != nil {
		t.Fatal(err)
	}
	return pushTestEnvelope(t, sender, cfg, id, string(raw))
}

// TestInboxConsumesStatePayloadE2E: a state payload arriving as an
// encrypted DM is consumed into the shared-state log, not delivered
// as chat, and replays are suppressed.
func TestInboxConsumesStatePayloadE2E(t *testing.T) {
	cfg := testConfig(t)
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	env := stateFixtureEnvelope(t, sender, cfg, 1, []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "Agenda", Body: "milk"},
		{Kind: StateEventTaskAdd, Seq: 2, SentAt: 101, TaskID: "t1", Title: "Ship It", Assignee: cfg.Address},
	})
	pc := &pushCapture{}
	ts := httptest.NewServer(pc.handler([]map[string]any{env}))
	t.Cleanup(ts.Close)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = ts.URL
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)

	msgs, _, _, _, err := cl.Inbox(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("state payload surfaced as chat: %+v", msgs)
	}
	peer := crypto.FormatAddress(sender.EdPub[:])
	notes, err := cl.StateListNotes(peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || notes[0].Title != "Agenda" {
		t.Fatalf("note not applied: %+v", notes)
	}
	tasks, err := cl.StateListTasks(peer, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].Title != "Ship It" {
		t.Fatalf("task not applied: %+v", tasks)
	}
	// A re-fetch must not duplicate or re-announce the events.
	msgs, _, _, _, err = cl.Inbox(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatalf("replay resurfaced: %+v", msgs)
	}
}

// TestStateSyncE2E: StateSync fetches and applies missed events via
// the state consumer's own replay-suppression set.
func TestStateSyncE2E(t *testing.T) {
	cfg := testConfig(t)
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	env := stateFixtureEnvelope(t, sender, cfg, 5, []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "Catchup"},
	})
	pc := &pushCapture{}
	ts := httptest.NewServer(pc.handler([]map[string]any{env}))
	t.Cleanup(ts.Close)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = ts.URL
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	peer := crypto.FormatAddress(sender.EdPub[:])

	applied, err := cl.StateSync(peer)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("sync applied %d events, want 1", applied)
	}
	applied, err = cl.StateSync(peer)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("second sync applied %d events, want 0", applied)
	}
}

// statePushCapture records pushed dashboard message bodies so tests
// can assert on the state-event summaries.
type statePushCapture struct {
	bodies []string
}

func (sc *statePushCapture) handler(envs []map[string]any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/inbox":
			after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
			var out []map[string]any
			for _, e := range envs {
				if e["id"].(int64) > after {
					out = append(out, e)
				}
			}
			raw, _ := json.Marshal(map[string]any{"messages": out})
			w.Write(raw)
		case "/v1/dashboard/push":
			raw, _ := io.ReadAll(r.Body)
			var req struct {
				Messages []struct {
					Body string `json:"body"`
				} `json:"messages"`
			}
			_ = json.Unmarshal(raw, &req)
			for _, m := range req.Messages {
				sc.bodies = append(sc.bodies, m.Body)
			}
			fmt.Fprintf(w, `{"stored":%d}`, len(req.Messages))
		default:
			http.NotFound(w, r)
		}
	})
}

// TestDashboardPushAnnouncesStateEvents: newly applied state events are
// pushed to the dashboard as human-readable summaries, once.
func TestDashboardPushAnnouncesStateEvents(t *testing.T) {
	cfg := testConfig(t)
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	env := stateFixtureEnvelope(t, sender, cfg, 1, []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "Agenda"},
		{Kind: StateEventTaskDone, Seq: 3, SentAt: 102, TaskID: "t1"},
	})
	sc := &statePushCapture{}
	ts := httptest.NewServer(sc.handler([]map[string]any{env}))
	t.Cleanup(ts.Close)
	if err := cfg.Update(func(fresh *Config) error {
		fresh.RelayURL = ts.URL
		fresh.DashboardURL = ts.URL
		fresh.DashboardToken = "test-token"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)

	pushed, err := cl.DashboardPush()
	if err != nil {
		t.Fatal(err)
	}
	if pushed != 2 {
		t.Fatalf("pushed = %d, want 2 state summaries", pushed)
	}
	found := false
	for _, b := range sc.bodies {
		if strings.Contains(b, "📝") && strings.Contains(b, "Agenda") {
			found = true
		}
	}
	if !found {
		t.Fatalf("dashboard push missing note summary: %v", sc.bodies)
	}
	// Second push is a no-op: the summaries were recorded as seen.
	pushed, err = cl.DashboardPush()
	if err != nil {
		t.Fatal(err)
	}
	if pushed != 0 {
		t.Fatalf("second push pushed %d, want 0", pushed)
	}
}

// TestHeldStatePayloadFallsThrough: a state payload from a held
// (quarantined/reported) sender must NOT enter shared state; it is
// delivered as ordinary chat.
func TestHeldStatePayloadFallsThrough(t *testing.T) {
	sender, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var pushed [][]byte
	cfg, cl, srv := contactsModeRecipient(t, nil)
	srv.Close() // replaced below with a server serving the state envelope
	env := stateFixtureEnvelope(t, sender, cfg, 1, []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "Evil Note"},
	})
	srv2 := spamInboxServer(t, []map[string]any{env}, &pushed)
	t.Cleanup(srv2.Close)
	pointAtServer(t, cfg, srv2)

	msgs, _, _, _, err := cl.Inbox(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("held state payload must surface as one chat message, got %d", len(msgs))
	}
	if !msgs[0].Request {
		t.Fatal("held message from unknown sender should be a request")
	}
	peer := crypto.FormatAddress(sender.EdPub[:])
	notes, err := cl.StateListNotes(peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Fatalf("held sender's state payload entered the log: %+v", notes)
	}
}
