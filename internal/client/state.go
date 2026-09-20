// Shared agent state (issue #49).
//
// One typed, signed, append-only shared-state substrate for notes and
// tasks between two agents — "shared memory between agents" as the
// persistence layer for cross-agent collaboration.
//
// Transport is in-channel: state events ride inside ordinary encrypted
// DMs as an app-layer type flag (like the group protocol's "cg" magic),
// so they reuse Courier identity/auth and need no new relay semantics.
// The inbox layer consumes state payloads into the per-peer log instead
// of surfacing them as chat messages (the same pattern as group-control
// DMs, issue #32). `courier dashboard push` announces new notes/tasks
// to the dashboard as human-readable summaries.
//
// Local state lives in ~/.courier/state.json (0600), one conversation
// (event log) per counterparty address. State is derived by folding the
// log: each writer numbers their own events with a per-author sequence
// number, and the fold applies events in (sentAt, author, seq) order so
// both sides derive the same view. Unauthorized task transitions are
// kept in the log (the accountability trail) but do not change the fold.
//
// MVP: structured notes with a done flag (notes are immutable; the done
// flag resolves by last-writer-wins). Tasks are notes with a state
// machine: task-add / task-assign / task-done / task-reopen. Only the
// assignee's signed event marks a task done; only the assigner can
// reassign or reopen. Task events are archived, never pruned; note
// events can be compacted past a retention horizon.
package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/black-candle-technologies/courier/internal/crypto"
)

// ---- wire format ----

// stateMagic marks direct messages that belong to the shared-state
// layer. They are consumed silently and never surface as chat messages.
const stateMagic = 1

// statePayloadVersion is the current version of the state event batch
// format. Bump when the event schema changes incompatibly.
const statePayloadVersion = 1

// maxStateEventsPerPayload bounds one state message, so a malicious or
// buggy peer cannot make us fold an unbounded batch.
const maxStateEventsPerPayload = 50

// Event kinds.
const (
	StateEventNoteAdd    = "note-add"
	StateEventNoteDone   = "note-done"
	StateEventTaskAdd    = "task-add"
	StateEventTaskAssign = "task-assign"
	StateEventTaskDone   = "task-done"
	StateEventTaskReopen = "task-reopen"
)

// StateEvent is one shared-state mutation. Author is implicit: the
// address that sent the enclosing DM (authenticated by the envelope
// signature). Seq is the author's per-author sequence number.
// ExpiresAt is an optional unix timestamp (issue #53): on note-add and
// task-add it marks when the item disappears (see stateExpired). It is
// rejected on every other event kind.
type StateEvent struct {
	Kind      string `json:"k"`
	Seq       int64  `json:"seq"`
	SentAt    int64  `json:"ts"`
	NoteID    string `json:"note_id,omitempty"`
	TaskID    string `json:"task_id,omitempty"`
	Title     string `json:"title,omitempty"`
	Body      string `json:"body,omitempty"`
	Assignee  string `json:"assignee,omitempty"`
	Escalate  bool   `json:"escalate,omitempty"`
	Done      bool   `json:"done,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// stateExpired reports whether an item with the given expiry timestamp
// is gone at now. Zero means "never expires".
func stateExpired(now, expiresAt int64) bool {
	return expiresAt != 0 && now >= expiresAt
}

// statePayload is the wire format: a batch of events inside one DM's
// ciphertext.
type statePayload struct {
	Magic   int          `json:"cs"`
	Type    string       `json:"t"`
	Version int          `json:"v"`
	Events  []StateEvent `json:"events"`
}

// stateEventID identifies an event within a conversation's log. It is
// derived, not trusted from the wire: author + per-author seq is unique
// by construction.
func stateEventID(author string, seq int64) string {
	return fmt.Sprintf("%s:%d", author, seq)
}

// parseStatePayload returns the shared-state payload if plain is one,
// and false otherwise. Only well-formed payloads with at least one
// valid event are intercepted; anything else is delivered as a normal
// message — never silently swallowed.
func parseStatePayload(plain []byte) (statePayload, bool) {
	var p statePayload
	if json.Unmarshal(plain, &p) != nil {
		return p, false
	}
	if p.Magic != stateMagic || p.Type != "state" || p.Version != statePayloadVersion {
		return p, false
	}
	if len(p.Events) == 0 || len(p.Events) > maxStateEventsPerPayload {
		return p, false
	}
	for i := range p.Events {
		if err := validateStateEvent(&p.Events[i]); err != nil {
			return p, false
		}
	}
	return p, true
}

// validateStateEvent checks an event's shape (not its authorization —
// that is enforced when folding). Invalid events fail the whole
// payload so it falls through to chat instead of being half-applied.
func validateStateEvent(ev *StateEvent) error {
	if ev.Seq <= 0 {
		return errors.New("event seq must be positive")
	}
	// issue #53: expiry is only meaningful when an item is created.
	if ev.ExpiresAt != 0 {
		switch ev.Kind {
		case StateEventNoteAdd, StateEventTaskAdd:
			if ev.ExpiresAt <= 0 {
				return errors.New("expires_at must be positive")
			}
		default:
			return fmt.Errorf("%s: expires_at only valid on note-add/task-add", ev.Kind)
		}
	}
	switch ev.Kind {
	case StateEventNoteAdd:
		if ev.NoteID == "" {
			return errors.New("note-add: missing note id")
		}
		if ev.Title == "" && ev.Body == "" {
			return errors.New("note-add: title or body required")
		}
	case StateEventNoteDone:
		if ev.NoteID == "" {
			return errors.New("note-done: missing note id")
		}
	case StateEventTaskAdd:
		if ev.TaskID == "" {
			return errors.New("task-add: missing task id")
		}
		if ev.Title == "" {
			return errors.New("task-add: title required")
		}
		if ev.Assignee == "" {
			return errors.New("task-add: missing assignee")
		}
		if _, err := crypto.ParseAddress(ev.Assignee); err != nil {
			return fmt.Errorf("task-add: bad assignee address: %w", err)
		}
	case StateEventTaskAssign:
		if ev.TaskID == "" {
			return errors.New("task-assign: missing task id")
		}
		if ev.Assignee == "" {
			return errors.New("task-assign: missing assignee")
		}
		if _, err := crypto.ParseAddress(ev.Assignee); err != nil {
			return fmt.Errorf("task-assign: bad assignee address: %w", err)
		}
	case StateEventTaskDone, StateEventTaskReopen:
		if ev.TaskID == "" {
			return fmt.Errorf("%s: missing task id", ev.Kind)
		}
	default:
		return fmt.Errorf("unknown event kind %q", ev.Kind)
	}
	return nil
}

// newStateID generates a random note/task id (12 bytes, hex).
func newStateID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ---- derived state ----

// StateNote is one shared note. Notes are immutable once added; only
// the done flag changes, by last-writer-wins. ExpiresAt is zero for
// notes that never expire (issue #53).
type StateNote struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Body      string `json:"body,omitempty"`
	Done      bool   `json:"done"`
	Author    string `json:"author"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// Task states.
const (
	StateTaskOpen = "open"
	StateTaskDone = "done"
)

// StateTask is one shared task: a note with a state machine.
type StateTask struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Body      string `json:"body,omitempty"`
	Assignee  string `json:"assignee"`
	Assigner  string `json:"assigner"`
	Escalate  bool   `json:"escalate,omitempty"`
	State     string `json:"state"`
	Author    string `json:"author"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	DoneBy    string `json:"done_by,omitempty"`
	// ExpiresAt is zero for tasks that never expire (issue #53). An
	// expired task disappears from the view and its events are pruned —
	// the one exception to "task events are archived, never pruned",
	// because expiry is an explicit deletion request.
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// LoggedStateEvent is one event in a conversation's log, with its
// (authenticated) author.
type LoggedStateEvent struct {
	Author string `json:"author"`
	StateEvent
}

// StateView is the folded view of a conversation: current notes and
// tasks.
type StateView struct {
	Notes map[string]*StateNote `json:"notes"`
	Tasks map[string]*StateTask `json:"tasks"`
}

// foldStateEvents derives the view from a conversation's events.
// Events apply in (sentAt, author, seq) order so both writers derive
// the same state. Task transitions are authorized here: task-assign
// and task-reopen only from the assigner, task-done only from the
// assignee. Unauthorized transitions are ignored by the fold (they stay
// in the log as the audit trail). Items whose expires_at has passed
// (issue #53) are excluded from the view.
func foldStateEvents(log []LoggedStateEvent) *StateView {
	return foldStateEventsAt(log, time.Now().Unix())
}

// foldStateEventsAt is foldStateEvents evaluated at a fixed now (used
// by viewOf and by tests).
func foldStateEventsAt(log []LoggedStateEvent, now int64) *StateView {
	v := &StateView{Notes: map[string]*StateNote{}, Tasks: map[string]*StateTask{}}
	foldStateEventsIntoAt(v, log, now)
	return v
}

// foldStateEventsInto folds log on top of an existing view (used to
// apply post-snapshot events over compacted notes).
func foldStateEventsInto(v *StateView, log []LoggedStateEvent) {
	foldStateEventsIntoAt(v, log, time.Now().Unix())
}

// foldStateEventsIntoAt is foldStateEventsInto evaluated at a fixed now.
func foldStateEventsIntoAt(v *StateView, log []LoggedStateEvent, now int64) {
	foldStateEventsOrdered(v, log)
	// issue #53: expired items disappear from the derived view. Their
	// events are pruned from the local log separately (pruneExpiredState);
	// the fold only decides what is visible.
	filterExpiredStateView(v, now)
}

// foldStateEventsOrdered applies log to v in (sentAt, author, seq)
// order, without any expiry filtering. pruneExpiredState uses it to see
// every item's ExpiresAt, including expired ones.
func foldStateEventsOrdered(v *StateView, log []LoggedStateEvent) {
	ordered := make([]LoggedStateEvent, len(log))
	copy(ordered, log)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.SentAt != b.SentAt {
			return a.SentAt < b.SentAt
		}
		if a.Author != b.Author {
			return a.Author < b.Author
		}
		return a.Seq < b.Seq
	})
	for _, le := range ordered {
		ev := le.StateEvent
		switch ev.Kind {
		case StateEventNoteAdd:
			if _, ok := v.Notes[ev.NoteID]; !ok {
				v.Notes[ev.NoteID] = &StateNote{
					ID: ev.NoteID, Title: ev.Title, Body: ev.Body,
					Author: le.Author, CreatedAt: ev.SentAt, UpdatedAt: ev.SentAt,
					ExpiresAt: ev.ExpiresAt,
				}
			}
		case StateEventNoteDone:
			if n, ok := v.Notes[ev.NoteID]; ok {
				// Last-writer-wins on the done flag: later events in
				// fold order win. Either writer may toggle a note.
				n.Done = ev.Done
				n.UpdatedAt = ev.SentAt
			}
		case StateEventTaskAdd:
			if _, ok := v.Tasks[ev.TaskID]; !ok {
				v.Tasks[ev.TaskID] = &StateTask{
					ID: ev.TaskID, Title: ev.Title, Body: ev.Body,
					Assignee: ev.Assignee, Assigner: le.Author,
					Escalate: ev.Escalate, State: StateTaskOpen,
					Author: le.Author, CreatedAt: ev.SentAt, UpdatedAt: ev.SentAt,
					ExpiresAt: ev.ExpiresAt,
				}
			}
		case StateEventTaskAssign:
			t, ok := v.Tasks[ev.TaskID]
			if !ok || le.Author != t.Assigner {
				continue // unknown task, or not the assigner
			}
			t.Assignee = ev.Assignee
			if t.State == StateTaskDone {
				t.State = StateTaskOpen // reassigning a done task reopens it
				t.DoneBy = ""
			}
			t.UpdatedAt = ev.SentAt
		case StateEventTaskDone:
			t, ok := v.Tasks[ev.TaskID]
			if !ok || le.Author != t.Assignee {
				continue // unknown task, or not the assignee
			}
			t.State = StateTaskDone
			t.DoneBy = le.Author
			t.UpdatedAt = ev.SentAt
		case StateEventTaskReopen:
			t, ok := v.Tasks[ev.TaskID]
			if !ok || le.Author != t.Assigner {
				continue // unknown task, or not the assigner
			}
			t.State = StateTaskOpen
			t.DoneBy = ""
			t.UpdatedAt = ev.SentAt
		}
	}
}

// filterExpiredStateView drops expired notes and tasks from a folded
// view (issue #53).
func filterExpiredStateView(v *StateView, now int64) {
	for id, n := range v.Notes {
		if stateExpired(now, n.ExpiresAt) {
			delete(v.Notes, id)
		}
	}
	for id, t := range v.Tasks {
		if stateExpired(now, t.ExpiresAt) {
			delete(v.Tasks, id)
		}
	}
}

// appliedStateEvent is one shared-state event newly applied to the
// local log during an inbox fetch, with the envelope metadata the
// dashboard push needs to announce it.
type appliedStateEvent struct {
	From       string
	EnvelopeID int64
	SentAt     int64
	ReceivedAt int64
	Hash       string // envelope dedup hash, for the push consumer's seen bookkeeping
	Event      StateEvent
}

// ---- local storage ----

// stateFile is ~/.courier/state.json: one conversation per counterparty.
type stateFile struct {
	Conversations map[string]*stateConversation `json:"conversations"`
}

// stateConversation is one peer's event log. SnapshotNotes holds notes
// compacted past the retention horizon (see StateCompact); Events holds
// everything after the snapshot. Task events are never compacted:
// archive, don't prune.
type stateConversation struct {
	Events        []LoggedStateEvent    `json:"events"`
	MaxSeq        map[string]int64      `json:"max_seq"`
	SnapshotNotes map[string]*StateNote `json:"snapshot_notes,omitempty"`
	SnapshotAt    int64                 `json:"snapshot_at,omitempty"`
	StateCursor   int64                 `json:"state_cursor,omitempty"`
}

// stateFilePath is ~/.courier/state.json.
func stateFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "state.json"), nil
}

func (sf *stateFile) conversation(peer string) *stateConversation {
	if sf.Conversations == nil {
		sf.Conversations = map[string]*stateConversation{}
	}
	c := sf.Conversations[peer]
	if c == nil {
		c = &stateConversation{MaxSeq: map[string]int64{}}
		sf.Conversations[peer] = c
	}
	if c.MaxSeq == nil {
		c.MaxSeq = map[string]int64{}
	}
	return c
}

func loadStateLocked() (*stateFile, error) {
	p, err := stateFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &stateFile{}, nil
		}
		return nil, err
	}
	sf := &stateFile{}
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("state.json: %w", err)
	}
	return sf, nil
}

func saveStateLocked(sf *stateFile) error {
	p, err := stateFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, p)
}

// updateState performs an atomic read-modify-write of state.json under
// the cross-process config lock (same discipline as Config.Update and
// updateGroups).
func updateState(fn func(*stateFile) error) error {
	return withConfigLock(func() error {
		sf, err := loadStateLocked()
		if err != nil {
			return err
		}
		if err := fn(sf); err != nil {
			return err
		}
		return saveStateLocked(sf)
	})
}

// loadState returns the local shared-state file.
func loadState() (*stateFile, error) {
	var sf *stateFile
	if err := withConfigLock(func() error {
		var err error
		sf, err = loadStateLocked()
		return err
	}); err != nil {
		return nil, err
	}
	return sf, nil
}

// viewOf folds one conversation: snapshot notes plus post-snapshot
// events. Post-snapshot events fold on top of the snapshot, so a
// note-done for a compacted note still applies. Expired snapshot notes
// (issue #53) are dropped before folding.
func (c *stateConversation) viewOf() *StateView {
	return c.viewOfAt(time.Now().Unix())
}

// viewOfAt is viewOf evaluated at a fixed now (used by tests).
func (c *stateConversation) viewOfAt(now int64) *StateView {
	v := &StateView{Notes: map[string]*StateNote{}, Tasks: map[string]*StateTask{}}
	for id, n := range c.SnapshotNotes {
		if stateExpired(now, n.ExpiresAt) {
			continue
		}
		cp := *n
		v.Notes[id] = &cp
	}
	foldStateEventsIntoAt(v, c.Events, now)
	return v
}

// pruneExpiredState deletes the local log events of expired notes and
// tasks, and drops expired snapshot notes. This is real local deletion
// (issue #53): each endpoint prunes its own copies independently on
// read/sync — the relay keeps the envelopes until its retention policy
// ages them out. It returns the number of events dropped.
func pruneExpiredState(conv *stateConversation, now int64) int {
	// Fold without the expiry filter so expired items are visible with
	// their ExpiresAt; snapshot notes seed the view first.
	v := &StateView{Notes: map[string]*StateNote{}, Tasks: map[string]*StateTask{}}
	for id, n := range conv.SnapshotNotes {
		cp := *n
		v.Notes[id] = &cp
	}
	foldStateEventsOrdered(v, conv.Events)
	expiredNotes := map[string]bool{}
	expiredTasks := map[string]bool{}
	for id, n := range v.Notes {
		if stateExpired(now, n.ExpiresAt) {
			expiredNotes[id] = true
		}
	}
	for id, t := range v.Tasks {
		if stateExpired(now, t.ExpiresAt) {
			expiredTasks[id] = true
		}
	}
	if len(expiredNotes) == 0 && len(expiredTasks) == 0 {
		return 0
	}
	for id := range expiredNotes {
		delete(conv.SnapshotNotes, id)
	}
	dropped := 0
	keep := conv.Events[:0]
	for _, le := range conv.Events {
		switch le.Kind {
		case StateEventNoteAdd, StateEventNoteDone:
			if expiredNotes[le.NoteID] {
				dropped++
				continue
			}
		case StateEventTaskAdd, StateEventTaskAssign, StateEventTaskDone, StateEventTaskReopen:
			if expiredTasks[le.TaskID] {
				dropped++
				continue
			}
		}
		keep = append(keep, le)
	}
	// Zero the tail so pruned events don't linger in the backing array.
	for i := len(keep); i < len(conv.Events); i++ {
		conv.Events[i] = LoggedStateEvent{}
	}
	conv.Events = keep
	return dropped
}

// applyStateEvents validates a batch of events from author for peer's
// conversation and appends the new ones. It returns the newly applied
// events (for dashboard push announcements). Application is idempotent:
// an event already in the log (by author:seq) is skipped.
func (c *Client) applyStateEvents(peer, author string, events []StateEvent) ([]StateEvent, error) {
	seenIDs := map[string]bool{}
	var applied []StateEvent
	err := updateState(func(sf *stateFile) error {
		conv := sf.conversation(peer)
		for _, e := range conv.Events {
			seenIDs[stateEventID(e.Author, e.Seq)] = true
		}
		for _, ev := range events {
			if err := validateStateEvent(&ev); err != nil {
				return fmt.Errorf("bad state event from %s: %w", author, err)
			}
			id := stateEventID(author, ev.Seq)
			if seenIDs[id] {
				continue // already applied
			}
			seenIDs[id] = true
			conv.Events = append(conv.Events, LoggedStateEvent{Author: author, StateEvent: ev})
			if ev.Seq > conv.MaxSeq[author] {
				conv.MaxSeq[author] = ev.Seq
			}
			applied = append(applied, ev)
		}
		// issue #53: prune expired items' events from the local log.
		// This runs on every consumer's pass (inbox, dashboard push,
		// state sync) and on the sender's local apply, so each
		// endpoint deletes its own expired copies independently.
		pruneExpiredState(conv, time.Now().Unix())
		return nil
	})
	return applied, err
}

// ---- composing and sending ----

// stateSummary renders one event as a human-readable one-liner for the
// sent log and dashboard push.
func stateSummary(peer string, ev StateEvent) string {
	shortID := ev.NoteID
	if shortID == "" {
		shortID = ev.TaskID
	}
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	title := ev.Title
	if title == "" {
		title = shortID
	}
	// issue #53: flag disappearing items in the announcement.
	expiry := ""
	if ev.ExpiresAt != 0 {
		expiry = fmt.Sprintf(" (expires %s)", time.Unix(ev.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05Z"))
	}
	switch ev.Kind {
	case StateEventNoteAdd:
		return fmt.Sprintf("📝 shared note with %s: %s%s", shortPeer(peer), title, expiry)
	case StateEventNoteDone:
		if ev.Done {
			return fmt.Sprintf("☑ shared note done: %s", title)
		}
		return fmt.Sprintf("↩ shared note reopened: %s", title)
	case StateEventTaskAdd:
		s := fmt.Sprintf("📌 task for %s: %s", shortPeer(ev.Assignee), title)
		if ev.Escalate {
			s += " (needs human)"
		}
		return s + expiry
	case StateEventTaskAssign:
		return fmt.Sprintf("📌 task reassigned to %s: %s", shortPeer(ev.Assignee), title)
	case StateEventTaskDone:
		return fmt.Sprintf("✅ task done: %s", title)
	case StateEventTaskReopen:
		return fmt.Sprintf("↩ task reopened: %s", title)
	default:
		return fmt.Sprintf("state update: %s", ev.Kind)
	}
}

// shortPeer renders an address as its first 8 chars for summaries.
func shortPeer(addr string) string {
	a := strings.TrimPrefix(addr, "ed25519:")
	if len(a) > 8 {
		return a[:8]
	}
	return a
}

// sendStateEvents numbers events with this client's per-author sequence
// numbers, seals them into one DM to peer, and applies them to the local
// log once the relay accepts the message. The local apply happens after
// the send so a failed send never leaves phantom events in the log.
func (c *Client) sendStateEvents(peer string, events []StateEvent) (int64, error) {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	var prepared []StateEvent
	if err := updateState(func(sf *stateFile) error {
		conv := sf.conversation(address)
		for i := range events {
			seq := conv.MaxSeq[c.cfg.Address] + 1
			conv.MaxSeq[c.cfg.Address] = seq
			events[i].Seq = seq
			events[i].SentAt = now
			if err := validateStateEvent(&events[i]); err != nil {
				return err
			}
			prepared = append(prepared, events[i])
		}
		return nil
	}); err != nil {
		return 0, err
	}
	plain, err := json.Marshal(statePayload{
		Magic: stateMagic, Type: "state", Version: statePayloadVersion, Events: prepared,
	})
	if err != nil {
		return 0, fmt.Errorf("encode state payload: %w", err)
	}
	var summaries []string
	for _, ev := range prepared {
		summaries = append(summaries, stateSummary(address, ev))
	}
	id, err := c.sendSealed(address, plain, strings.Join(summaries, "; "), 0, "", true, 0)
	if err != nil {
		return 0, err
	}
	if _, err := c.applyStateEvents(address, c.cfg.Address, prepared); err != nil {
		// The peer has the events; a local log failure must not fail
		// the send. The next sync re-applies them idempotently... but
		// our own sent events are not on our inbox, so surface the
		// error for visibility while still reporting the send as done.
		return id, fmt.Errorf("sent (id %d) but local log write failed: %w", id, err)
	}
	return id, nil
}

// StateConversation loads and folds one peer conversation. Expired
// notes/tasks (issue #53) are pruned from the local log on the way,
// so pure reads (list/show/search with no new events) still delete
// expired items.
func (c *Client) StateConversation(peer string) (*StateView, error) {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return nil, err
	}
	var view *StateView
	err = updateState(func(sf *stateFile) error {
		conv := sf.Conversations[address]
		if conv == nil {
			view = &StateView{Notes: map[string]*StateNote{}, Tasks: map[string]*StateTask{}}
			return nil
		}
		pruneExpiredState(conv, time.Now().Unix())
		view = conv.viewOf()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}

// StateListNotes returns the conversation's notes sorted by most
// recently updated.
func (c *Client) StateListNotes(peer string) ([]*StateNote, error) {
	view, err := c.StateConversation(peer)
	if err != nil {
		return nil, err
	}
	notes := make([]*StateNote, 0, len(view.Notes))
	for _, n := range view.Notes {
		notes = append(notes, n)
	}
	sort.Slice(notes, func(i, j int) bool { return notes[i].UpdatedAt > notes[j].UpdatedAt })
	return notes, nil
}

// StateListTasks returns the conversation's tasks sorted by most
// recently updated. filter is "", "open", or "done".
func (c *Client) StateListTasks(peer, filter string) ([]*StateTask, error) {
	view, err := c.StateConversation(peer)
	if err != nil {
		return nil, err
	}
	tasks := make([]*StateTask, 0, len(view.Tasks))
	for _, t := range view.Tasks {
		switch filter {
		case "open":
			if t.State != StateTaskOpen {
				continue
			}
		case "done":
			if t.State != StateTaskDone {
				continue
			}
		}
		tasks = append(tasks, t)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].UpdatedAt > tasks[j].UpdatedAt })
	return tasks, nil
}

// resolveStateID matches a note/task id prefix unambiguously within a
// view. It returns the full id.
func resolveStateID(view *StateView, prefix string) (string, string, error) {
	if _, ok := view.Notes[prefix]; ok {
		return prefix, "note", nil
	}
	if _, ok := view.Tasks[prefix]; ok {
		return prefix, "task", nil
	}
	var match, kind string
	for id := range view.Notes {
		if strings.HasPrefix(id, prefix) {
			if match != "" {
				return "", "", fmt.Errorf("ambiguous id prefix %q", prefix)
			}
			match, kind = id, "note"
		}
	}
	for id := range view.Tasks {
		if strings.HasPrefix(id, prefix) {
			if match != "" {
				return "", "", fmt.Errorf("ambiguous id prefix %q", prefix)
			}
			match, kind = id, "task"
		}
	}
	if match == "" {
		return "", "", fmt.Errorf("unknown note/task id %q", prefix)
	}
	return match, kind, nil
}

// defaultAssignee resolves the assignee for a new/changed task: empty
// means self. The assignee must be one of the two collaborators — a
// task assigned to a third party could never be completed, since only
// the assignee's signed event marks it done.
func (c *Client) defaultAssignee(peer, assignee string) (string, error) {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return "", err
	}
	if assignee == "" {
		return c.cfg.Address, nil
	}
	a, err := c.cfg.ResolveRecipient(assignee)
	if err != nil {
		return "", err
	}
	if a != c.cfg.Address && a != address {
		return "", fmt.Errorf("assignee must be you or %s (the collaborator)", shortPeer(address))
	}
	return a, nil
}

// StateAddNote shares a note with peer. ttl is the disappearing-message
// lifetime (issue #53); zero means the note never expires. Returns the
// note id and the relay envelope id.
func (c *Client) StateAddNote(peer, title, body string, ttl time.Duration) (string, int64, error) {
	expiresAt, err := ttlExpiry(ttl)
	if err != nil {
		return "", 0, err
	}
	noteID, err := newStateID()
	if err != nil {
		return "", 0, err
	}
	id, err := c.sendStateEvents(peer, []StateEvent{{
		Kind: StateEventNoteAdd, NoteID: noteID, Title: title, Body: body,
		ExpiresAt: expiresAt,
	}})
	if err != nil {
		return "", 0, err
	}
	return noteID, id, nil
}

// StateSetNoteDone toggles a note's done flag. Either writer may toggle
// a note (last-writer-wins on concurrent toggles).
func (c *Client) StateSetNoteDone(peer, notePrefix string, done bool) (int64, error) {
	v, err := c.StateConversation(peer)
	if err != nil {
		return 0, err
	}
	id, kind, err := resolveStateID(v, notePrefix)
	if err != nil {
		return 0, err
	}
	if kind != "note" {
		return 0, fmt.Errorf("%q is a task, not a note", notePrefix)
	}
	return c.sendStateEvents(peer, []StateEvent{{
		Kind: StateEventNoteDone, NoteID: id, Done: done,
		Title: v.Notes[id].Title,
	}})
}

// StateAddTask shares a task with peer. Empty assignee means self.
// ttl is the disappearing-message lifetime (issue #53); zero means the
// task never expires. Returns the task id and the relay envelope id.
func (c *Client) StateAddTask(peer, title, body, assignee string, escalate bool, ttl time.Duration) (string, int64, error) {
	a, err := c.defaultAssignee(peer, assignee)
	if err != nil {
		return "", 0, err
	}
	expiresAt, err := ttlExpiry(ttl)
	if err != nil {
		return "", 0, err
	}
	taskID, err := newStateID()
	if err != nil {
		return "", 0, err
	}
	id, err := c.sendStateEvents(peer, []StateEvent{{
		Kind: StateEventTaskAdd, TaskID: taskID, Title: title, Body: body,
		Assignee: a, Escalate: escalate, ExpiresAt: expiresAt,
	}})
	if err != nil {
		return "", 0, err
	}
	return taskID, id, nil
}

// ttlExpiry converts a disappearing-message TTL into an absolute unix
// expiry timestamp stamped from the sender's clock (issue #53). Zero
// ttl means "never expires" (returned as 0). Negative ttls are
// rejected.
func ttlExpiry(ttl time.Duration) (int64, error) {
	if ttl < 0 {
		return 0, fmt.Errorf("ttl must not be negative")
	}
	if ttl == 0 {
		return 0, nil
	}
	return time.Now().Unix() + int64(ttl.Seconds()), nil
}

// StateAssignTask reassigns a task. Only the current assigner may
// reassign.
func (c *Client) StateAssignTask(peer, taskPrefix, assignee string) (int64, error) {
	v, err := c.StateConversation(peer)
	if err != nil {
		return 0, err
	}
	id, kind, err := resolveStateID(v, taskPrefix)
	if err != nil {
		return 0, err
	}
	if kind != "task" {
		return 0, fmt.Errorf("%q is a note, not a task", taskPrefix)
	}
	t := v.Tasks[id]
	if t.Assigner != c.cfg.Address {
		return 0, fmt.Errorf("only the assigner (%s) can reassign this task", shortPeer(t.Assigner))
	}
	a, err := c.defaultAssignee(peer, assignee)
	if err != nil {
		return 0, err
	}
	return c.sendStateEvents(peer, []StateEvent{{
		Kind: StateEventTaskAssign, TaskID: id, Assignee: a, Title: t.Title,
	}})
}

// StateCompleteTask marks a task done. Only the assignee's signed event
// counts (enforced again when folding).
func (c *Client) StateCompleteTask(peer, taskPrefix string) (int64, error) {
	v, err := c.StateConversation(peer)
	if err != nil {
		return 0, err
	}
	id, kind, err := resolveStateID(v, taskPrefix)
	if err != nil {
		return 0, err
	}
	if kind != "task" {
		return 0, fmt.Errorf("%q is a note, not a task", taskPrefix)
	}
	t := v.Tasks[id]
	if t.State == StateTaskDone {
		return 0, fmt.Errorf("task %q is already done", taskPrefix)
	}
	if t.Assignee != c.cfg.Address {
		return 0, fmt.Errorf("only the assignee (%s) can mark this task done", shortPeer(t.Assignee))
	}
	return c.sendStateEvents(peer, []StateEvent{{
		Kind: StateEventTaskDone, TaskID: id, Title: t.Title,
	}})
}

// StateReopenTask reopens a done task. Only the assigner may reopen.
func (c *Client) StateReopenTask(peer, taskPrefix string) (int64, error) {
	v, err := c.StateConversation(peer)
	if err != nil {
		return 0, err
	}
	id, kind, err := resolveStateID(v, taskPrefix)
	if err != nil {
		return 0, err
	}
	if kind != "task" {
		return 0, fmt.Errorf("%q is a note, not a task", taskPrefix)
	}
	t := v.Tasks[id]
	if t.State != StateTaskDone {
		return 0, fmt.Errorf("task %q is not done", taskPrefix)
	}
	if t.Assigner != c.cfg.Address {
		return 0, fmt.Errorf("only the assigner (%s) can reopen this task", shortPeer(t.Assigner))
	}
	return c.sendStateEvents(peer, []StateEvent{{
		Kind: StateEventTaskReopen, TaskID: id, Title: t.Title,
	}})
}

// StateSearch returns notes and tasks whose title or body contains the
// query (case-insensitive), searched locally after decryption.
func (c *Client) StateSearch(peer, query string) ([]*StateNote, []*StateTask, error) {
	v, err := c.StateConversation(peer)
	if err != nil {
		return nil, nil, err
	}
	q := strings.ToLower(query)
	var notes []*StateNote
	for _, n := range v.Notes {
		if strings.Contains(strings.ToLower(n.Title), q) || strings.Contains(strings.ToLower(n.Body), q) {
			notes = append(notes, n)
		}
	}
	var tasks []*StateTask
	for _, t := range v.Tasks {
		if strings.Contains(strings.ToLower(t.Title), q) || strings.Contains(strings.ToLower(t.Body), q) {
			tasks = append(tasks, t)
		}
	}
	sort.Slice(notes, func(i, j int) bool { return notes[i].CreatedAt < notes[j].CreatedAt })
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].CreatedAt < tasks[j].CreatedAt })
	return notes, tasks, nil
}

// StatePeers lists counterparty addresses with a shared-state
// conversation.
func (c *Client) StatePeers() ([]string, error) {
	sf, err := loadState()
	if err != nil {
		return nil, err
	}
	var out []string
	for peer := range sf.Conversations {
		out = append(out, peer)
	}
	sort.Strings(out)
	return out, nil
}

// maxStateSyncPages bounds one sync so a pathological backlog cannot
// loop forever.
const maxStateSyncPages = 10

// StateSync fetches new envelopes through the dedicated state consumer
// (issue #45: independent replay-suppression set, so syncing never
// consumes inbox or dashboard-push messages) and applies any state
// events. On the first sync the cursor starts at the furthest point the
// inbox or dashboard-push consumers have already inspected — their
// fetches already applied those events. Returns the number of newly
// applied events.
func (c *Client) StateSync(peer string) (int, error) {
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return 0, err
	}
	before, err := c.stateEventCount(address)
	if err != nil {
		return 0, err
	}
	var cursor int64
	if err := updateState(func(sf *stateFile) error {
		conv := sf.conversation(address)
		if conv.StateCursor == 0 {
			floor := c.cfg.Cursor
			if c.cfg.DashboardCursor > floor {
				floor = c.cfg.DashboardCursor
			}
			conv.StateCursor = floor
		}
		cursor = conv.StateCursor
		return nil
	}); err != nil {
		return 0, err
	}
	for i := 0; i < maxStateSyncPages; i++ {
		_, lastID, _, _, _, _, err := c.inbox(cursor, 200, true, seenConsumerState)
		if err != nil {
			return 0, err
		}
		if lastID <= cursor {
			break
		}
		cursor = lastID
		if err := updateState(func(sf *stateFile) error {
			sf.conversation(address).StateCursor = cursor
			return nil
		}); err != nil {
			return 0, err
		}
	}
	after, err := c.stateEventCount(address)
	if err != nil {
		return 0, err
	}
	// issue #53: prune even when nothing new arrived (the fetch above
	// only prunes inside applyStateEvents when events are applied).
	// Pruning can drop old events, so the net count may go negative;
	// clamp it — the return is "newly applied events", never negative.
	if err := updateState(func(sf *stateFile) error {
		pruneExpiredState(sf.conversation(address), time.Now().Unix())
		return nil
	}); err != nil {
		return 0, err
	}
	if n := after - before; n > 0 {
		return n, nil
	}
	return 0, nil
}

func (c *Client) stateEventCount(peer string) (int, error) {
	sf, err := loadState()
	if err != nil {
		return 0, err
	}
	conv := sf.Conversations[peer]
	if conv == nil {
		return 0, nil
	}
	return len(conv.Events), nil
}

// StateCompact snapshots the current notes and drops note events older
// than days days. Task events are never dropped: archive, don't prune.
// Returns the number of events dropped.
func (c *Client) StateCompact(peer string, days int) (int, error) {
	if days < 0 {
		return 0, fmt.Errorf("days must be non-negative")
	}
	address, err := c.cfg.ResolveRecipient(peer)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Unix() - int64(days)*86400
	dropped := 0
	err = updateState(func(sf *stateFile) error {
		conv := sf.conversation(address)
		view := conv.viewOf()
		var keep []LoggedStateEvent
		for _, le := range conv.Events {
			switch le.Kind {
			case StateEventNoteAdd, StateEventNoteDone:
				if le.SentAt < cutoff {
					dropped++
					continue
				}
			}
			keep = append(keep, le)
		}
		if dropped > 0 {
			conv.SnapshotNotes = map[string]*StateNote{}
			for id, n := range view.Notes {
				cp := *n
				conv.SnapshotNotes[id] = &cp
			}
			conv.SnapshotAt = time.Now().Unix()
			conv.Events = keep
		}
		return nil
	})
	return dropped, err
}
