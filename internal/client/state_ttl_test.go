// Tests for disappearing messages / TTL (issue #53).
package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStateEventExpiryValidation(t *testing.T) {
	peer, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	goodAssignee := peer.Address
	// expires_at is only valid on note-add and task-add.
	bad := []StateEvent{
		{Kind: StateEventNoteDone, Seq: 1, NoteID: "n", Done: true, ExpiresAt: 999},
		{Kind: StateEventTaskDone, Seq: 1, TaskID: "t", ExpiresAt: 999},
		{Kind: StateEventTaskAssign, Seq: 1, TaskID: "t", Assignee: goodAssignee, ExpiresAt: 999},
		{Kind: StateEventTaskReopen, Seq: 1, TaskID: "t", ExpiresAt: 999},
		{Kind: StateEventNoteAdd, Seq: 1, NoteID: "n", Title: "x", ExpiresAt: -5},
	}
	for i, ev := range bad {
		if err := validateStateEvent(&ev); err == nil {
			t.Errorf("case %d (%s): expected validation error", i, ev.Kind)
		}
	}
	good := []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, NoteID: "n", Title: "x", ExpiresAt: 999},
		{Kind: StateEventTaskAdd, Seq: 1, TaskID: "t", Title: "x", Assignee: goodAssignee, ExpiresAt: 999},
		{Kind: StateEventNoteAdd, Seq: 1, NoteID: "n", Title: "x"}, // no expiry: fine
	}
	for i, ev := range good {
		if err := validateStateEvent(&ev); err != nil {
			t.Errorf("case %d (%s): unexpected validation error: %v", i, ev.Kind, err)
		}
	}
	// A payload carrying expires_at on a non-add kind fails the whole
	// payload so it falls through to chat, never half-applied.
	raw, _ := json.Marshal(statePayload{
		Magic: stateMagic, Type: "state", Version: statePayloadVersion,
		Events: []StateEvent{{Kind: StateEventNoteDone, Seq: 1, SentAt: 100, NoteID: "n", Done: true, ExpiresAt: 999}},
	})
	if _, ok := parseStatePayload(raw); ok {
		t.Error("payload with expires_at on note-done should be rejected")
	}
}

func TestStateEventExpiryEncodeDecode(t *testing.T) {
	ev := StateEvent{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n1", Title: "x", ExpiresAt: 1893456000}
	raw, err := json.Marshal(statePayload{
		Magic: stateMagic, Type: "state", Version: statePayloadVersion, Events: []StateEvent{ev},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"expires_at":1893456000`) {
		t.Fatalf("expires_at missing from wire encoding: %s", raw)
	}
	p, ok := parseStatePayload(raw)
	if !ok {
		t.Fatal("payload with expires_at rejected")
	}
	if p.Events[0].ExpiresAt != 1893456000 {
		t.Fatalf("expires_at = %d, want 1893456000", p.Events[0].ExpiresAt)
	}
	// Old-client tolerance: a client whose StateEvent has no ExpiresAt
	// field (pre-#53) still parses the payload — the note just never
	// expires for it. Simulate by decoding into a stripped struct.
	type oldEvent struct {
		Kind   string `json:"k"`
		Seq    int64  `json:"seq"`
		NoteID string `json:"note_id,omitempty"`
		Title  string `json:"title,omitempty"`
	}
	type oldPayload struct {
		Magic  int        `json:"cs"`
		Type   string     `json:"t"`
		Events []oldEvent `json:"events"`
	}
	var op oldPayload
	if err := json.Unmarshal(raw, &op); err != nil {
		t.Fatalf("old client would choke on TTL payload: %v", err)
	}
	if len(op.Events) != 1 || op.Events[0].Title != "x" {
		t.Fatalf("old client misparsed TTL payload: %+v", op.Events)
	}
}

func TestFoldExpiredItemsExcluded(t *testing.T) {
	now := int64(1_000_000)
	alive := now + 3600
	dead := now - 10
	log := []LoggedStateEvent{
		le("alice", StateEvent{Kind: StateEventNoteAdd, Seq: 1, SentAt: 100, NoteID: "n-live", Title: "live", ExpiresAt: alive}),
		le("alice", StateEvent{Kind: StateEventNoteAdd, Seq: 2, SentAt: 100, NoteID: "n-dead", Title: "dead", ExpiresAt: dead}),
		le("alice", StateEvent{Kind: StateEventNoteAdd, Seq: 3, SentAt: 100, NoteID: "n-forever", Title: "forever"}),
		le("alice", StateEvent{Kind: StateEventTaskAdd, Seq: 4, SentAt: 100, TaskID: "t-dead", Title: "gone", Assignee: "alice", ExpiresAt: dead}),
		le("alice", StateEvent{Kind: StateEventTaskAdd, Seq: 5, SentAt: 100, TaskID: "t-live", Title: "here", Assignee: "alice", ExpiresAt: alive}),
	}
	v := foldStateEventsAt(log, now)
	if v.Notes["n-live"] == nil || v.Notes["n-forever"] == nil {
		t.Error("live/forever notes missing from view")
	}
	if v.Notes["n-dead"] != nil {
		t.Error("expired note still in view")
	}
	if v.Tasks["t-live"] == nil {
		t.Error("live task missing from view")
	}
	if v.Tasks["t-dead"] != nil {
		t.Error("expired task still in view")
	}
	// Expiry survives the fold onto the derived items.
	if v.Notes["n-live"].ExpiresAt != alive {
		t.Errorf("note ExpiresAt = %d, want %d", v.Notes["n-live"].ExpiresAt, alive)
	}
	// At exactly expires_at the item is gone (now >= expires_at).
	v2 := foldStateEventsAt(log, alive)
	if v2.Notes["n-live"] != nil {
		t.Error("note at exactly expires_at should be expired")
	}
}

func TestPruneExpiredStateDeletesEvents(t *testing.T) {
	cfg := testConfig(t)
	c := New(cfg)
	peerCfg, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	peer := peerCfg.Address
	now := time.Now().Unix()
	_, err = c.applyStateEvents(peer, peer, []StateEvent{
		{Kind: StateEventNoteAdd, Seq: 1, SentAt: now - 100, NoteID: "n-dead", Title: "dead", ExpiresAt: now - 10},
		{Kind: StateEventNoteDone, Seq: 2, SentAt: now - 90, NoteID: "n-dead", Done: true},
		{Kind: StateEventNoteAdd, Seq: 3, SentAt: now, NoteID: "n-live", Title: "live", ExpiresAt: now + 3600},
		{Kind: StateEventTaskAdd, Seq: 4, SentAt: now, TaskID: "t-live", Title: "task", Assignee: peer},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The expired note's events were pruned on apply; the live items
	// remain in both the view and the log.
	v, err := c.StateConversation(peer)
	if err != nil {
		t.Fatal(err)
	}
	if v.Notes["n-dead"] != nil {
		t.Error("expired note still visible")
	}
	if v.Notes["n-live"] == nil || v.Tasks["t-live"] == nil {
		t.Error("live note/task missing")
	}
	n, err := c.stateEventCount(peer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("event count = %d, want 2 (expired note's 2 events pruned)", n)
	}
	// A later read (no new events) keeps the view stable and the log
	// pruned.
	v2, err := c.StateConversation(peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.Notes) != 1 || len(v2.Tasks) != 1 {
		t.Errorf("unexpected view after re-read: %+v", v2)
	}
}

func TestViewOfAtFiltersExpiredSnapshot(t *testing.T) {
	now := int64(1_000_000)
	conv := &stateConversation{
		MaxSeq: map[string]int64{},
		SnapshotNotes: map[string]*StateNote{
			"n-old": {ID: "n-old", Title: "old", ExpiresAt: now - 1},
			"n-new": {ID: "n-new", Title: "new", ExpiresAt: now + 100},
		},
	}
	v := conv.viewOfAt(now)
	if v.Notes["n-old"] != nil {
		t.Error("expired snapshot note still in view")
	}
	if v.Notes["n-new"] == nil {
		t.Error("live snapshot note missing from view")
	}
	// Pruning also drops the expired snapshot entry itself.
	if n := pruneExpiredState(conv, now); n != 0 {
		t.Errorf("prune dropped %d events, want 0 (snapshot-only)", n)
	}
	if _, ok := conv.SnapshotNotes["n-old"]; ok {
		t.Error("expired snapshot note not pruned")
	}
}

func TestTtlExpiry(t *testing.T) {
	if exp, err := ttlExpiry(0); err != nil || exp != 0 {
		t.Errorf("ttlExpiry(0) = %d, %v; want 0, nil", exp, err)
	}
	if _, err := ttlExpiry(-time.Second); err == nil {
		t.Error("negative ttl accepted")
	}
	before := time.Now().Unix()
	exp, err := ttlExpiry(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if exp < before+600 || exp > before+601 {
		t.Errorf("ttlExpiry(10m) = %d, want ~%d", exp, before+600)
	}
}

func TestSendWithTTLValidation(t *testing.T) {
	cfg := testConfig(t)
	c := New(cfg)
	if _, err := c.SendWithTTL("ed25519:xxx", "hi", 0); err == nil {
		t.Error("zero ttl accepted")
	}
	if _, err := c.SendWithTTL("ed25519:xxx", "hi", -time.Minute); err == nil {
		t.Error("negative ttl accepted")
	}
}

func TestReadSentLogPrunesExpired(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	now := time.Now().Unix()
	p, err := sentLogPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// One expired entry, one live expiring entry, one immortal entry.
	if err := appendSentLog(SentEntry{CourierID: 1, To: "a", Body: "gone", SentAt: now - 100, ExpiresAt: now - 10}); err != nil {
		t.Fatal(err)
	}
	if err := appendSentLog(SentEntry{CourierID: 2, To: "a", Body: "live", SentAt: now, ExpiresAt: now + 3600}); err != nil {
		t.Fatal(err)
	}
	if err := appendSentLog(SentEntry{CourierID: 3, To: "a", Body: "forever", SentAt: now}); err != nil {
		t.Fatal(err)
	}
	entries, err := readSentLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].CourierID != 2 || entries[1].CourierID != 3 {
		t.Fatalf("pruned log = %+v, want ids 2,3", entries)
	}
	// The file itself was rewritten without the expired entry.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"gone"`) {
		t.Error("expired entry still in sent.jsonl")
	}
	// Old log lines without expires_at parse as never-expiring.
	raw2 := "{\"courier_id\":9,\"to\":\"b\",\"body\":\"legacy\",\"sent_at\":123}\n"
	if err := os.WriteFile(p, []byte(raw2), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err = readSentLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Body != "legacy" || entries[0].ExpiresAt != 0 {
		t.Fatalf("legacy entry misparsed: %+v", entries)
	}
}

func TestStateSummaryExpiry(t *testing.T) {
	ev := StateEvent{Kind: StateEventNoteAdd, NoteID: "n1", Title: "x", ExpiresAt: 1893456000}
	s := stateSummary("ed25519:peer", ev)
	if !strings.Contains(s, "expires") {
		t.Errorf("disappearing note summary missing expiry: %q", s)
	}
	ev2 := StateEvent{Kind: StateEventNoteAdd, NoteID: "n1", Title: "x"}
	if strings.Contains(stateSummary("ed25519:peer", ev2), "expires") {
		t.Errorf("immortal note summary should not mention expiry: %q", stateSummary("ed25519:peer", ev2))
	}
}
