package client

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type archiveTestEvent struct {
	Kind    string `json:"k"`
	Note    string `json:"note_id,omitempty"`
	Task    string `json:"task_id,omitempty"`
	TS      int64  `json:"ts"`
	Author  string `json:"author"`
	Seq     int64  `json:"seq"`
	Expires int64  `json:"expires_at"`
	Extra   string `json:"unknown_metadata"`
}

// Independent reference: reproduce the retired ordered fold, then keep raw order.
func referenceArchiveEvents(events []archiveTestEvent, snapshots map[string]int64, now int64) []archiveTestEvent {
	ordered := append([]archiveTestEvent(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.TS != b.TS {
			return a.TS < b.TS
		}
		if a.Author != b.Author {
			return a.Author < b.Author
		}
		return a.Seq < b.Seq
	})
	notes, tasks := map[string]int64{}, map[string]int64{}
	for k, v := range snapshots {
		notes[k] = v
	}
	for _, e := range ordered {
		if e.Kind == "note-add" {
			if _, ok := notes[e.Note]; !ok {
				notes[e.Note] = e.Expires
			}
		}
		if e.Kind == "task-add" {
			if _, ok := tasks[e.Task]; !ok {
				tasks[e.Task] = e.Expires
			}
		}
	}
	var out []archiveTestEvent
	for _, e := range events {
		dead := false
		switch e.Kind {
		case "note-add", "note-done":
			dead = stateExpired(now, notes[e.Note])
		case "task-add", "task-assign", "task-done", "task-reopen":
			dead = stateExpired(now, tasks[e.Task])
		}
		if !dead {
			out = append(out, e)
		}
	}
	return out
}
func writeArchiveFixture(t testing.TB, p string, events []archiveTestEvent, snapshots map[string]int64) {
	t.Helper()
	notes := map[string]any{}
	for k, v := range snapshots {
		notes[k] = map[string]any{"expires_at": v, "unknown": "snapshot-metadata"}
	}
	b, err := json.Marshal(map[string]any{"extra": "root-metadata", "conversations": map[string]any{"peer": map[string]any{"extra": "conversation-metadata", "events": events, "snapshot_notes": notes}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func readArchiveEvents(t testing.TB, p string) []archiveTestEvent {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Conversations map[string]struct {
			Events []archiveTestEvent `json:"events"`
		} `json:"conversations"`
	}
	if err = json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"root-metadata", "conversation-metadata"} {
		if !strings.Contains(string(b), v) {
			t.Fatalf("lost %s", v)
		}
	}
	return root.Conversations["peer"].Events
}
func TestLegacyArchiveLinearMatchesReference(t *testing.T) {
	events := []archiveTestEvent{
		{Kind: "note-add", Note: "snapshot", Expires: 1},
		{Kind: "note-add", Note: "dead-snapshot", Expires: 0},
		{Kind: "task-add", Task: "exact-tie", TS: 2, Author: "a", Seq: 2, Expires: 1},
		{Kind: "task-add", Task: "exact-tie", TS: 2, Author: "a", Seq: 2, Expires: 1},
		{Kind: "note-add", Note: "zero", TS: 1, Expires: 0}, {Kind: "note-add", Note: "zero", TS: 2, Expires: 1},
		{Kind: "task-add", Task: "timestamp", TS: 2, Expires: 0}, {Kind: "task-add", Task: "timestamp", TS: 1, Expires: 1},
		{Kind: "task-add", Task: "author", TS: 1, Author: "b", Expires: 0}, {Kind: "task-add", Task: "author", TS: 1, Author: "a", Expires: 1},
		{Kind: "note-add", Note: "sequence", TS: 1, Author: "a", Seq: 2, Expires: 0}, {Kind: "note-add", Note: "sequence", TS: 1, Author: "a", Seq: 1, Expires: 1},
		{Kind: "task-done", Task: "timestamp"}, {Kind: "note-done", Note: "sequence"}, {Kind: "unknown", Note: "sequence", Extra: "future-kind-preserved"},
	}
	snapshots := map[string]int64{"snapshot": 0, "dead-snapshot": 1}
	p := filepath.Join(t.TempDir(), "state.json")
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 100; i++ {
		r.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
		writeArchiveFixture(t, p, events, snapshots)
		if err := maintainLegacyStateLocked(p, 100); err != nil {
			t.Fatal(err)
		}
		got := readArchiveEvents(t, p)
		want := referenceArchiveEvents(events, snapshots, 100)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("permutation %d got %#v want %#v", i, got, want)
		}
	}
}
func TestLegacyArchiveLargeFutureExpiry(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	events := make([]archiveTestEvent, 20001)
	for i := 0; i < 20000; i++ {
		events[i] = archiveTestEvent{Kind: "task-add", Task: fmt.Sprint(i), TS: int64(20000 - i), Extra: "permanent"}
	}
	events[20000] = archiveTestEvent{Kind: "task-add", Task: "future", Expires: 200, Extra: "unique-expiring-secret"}
	writeArchiveFixture(t, p, events, nil)
	if err := maintainLegacyStateLocked(p, 100); err != nil {
		t.Fatal(err)
	}
	if got := readArchiveEvents(t, p); len(got) != len(events) {
		t.Fatal("premature expiry")
	}
	if err := maintainLegacyStateLocked(p, 200); err != nil {
		t.Fatal(err)
	}
	if got := readArchiveEvents(t, p); len(got) != 20000 {
		t.Fatal("lost live history or retained expiry")
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "unique-expiring-secret") {
		t.Fatal("expired bytes retained")
	}
}
func TestLegacyArchiveMalformedDiagnostic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	for _, raw := range []string{"broken", `{"conversations":1}`, `{"conversations":{"p":{"events":1}}}`, `{"conversations":{"p":{"events":[{"ts":"bad"}]}}}`, `{"conversations":{"p":{"snapshot_notes":{"x":{"expires_at":"bad"}}}}}`} {
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		err := maintainLegacyStateLocked(p, 100)
		if err == nil || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "preserve a backup") || !strings.Contains(err.Error(), "do not delete") {
			t.Fatalf("unsafe diagnostic: %v", err)
		}
		got, _ := os.ReadFile(p)
		if string(got) != raw {
			t.Fatal("malformed data changed")
		}
	}
}
func BenchmarkLegacyArchiveLinear(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			p := filepath.Join(b.TempDir(), "state.json")
			events := make([]archiveTestEvent, n)
			for i := range events {
				events[i] = archiveTestEvent{Kind: "task-add", Task: fmt.Sprint(i), TS: int64(n - i)}
			}
			writeArchiveFixture(b, p, events, nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := maintainLegacyStateLocked(p, 100); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
