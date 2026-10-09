package client

// Compatibility quarantine for the retired shared-state feature. Keep its
// reserved wire discriminator out of chat, including malformed/unknown versions.
// There is deliberately no state command, event application, or transmission.
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func isLegacyStatePayload(plain []byte) bool {
	var p struct {
		Magic int    `json:"cs"`
		Type  string `json:"t"`
	}
	return json.Unmarshal(plain, &p) == nil && p.Magic == 1 && p.Type == "state"
}

// Maintain the retired archive in place. Repeating this at every config load
// preserves future TTLs; a one-time export would strand entries that expire later.
// Raw fields preserve unknown metadata and all non-expired user content.
func maintainLegacyState() error {
	return withConfigLock(func() error {
		p, err := configPath()
		if err != nil {
			return err
		}
		p = filepath.Join(filepath.Dir(p), "state.json")
		return maintainLegacyStateLocked(p, time.Now().Unix())
	})
}

// Caller holds the config lock; explicit time keeps expiry maintenance testable.
func maintainLegacyStateLocked(p string, now int64) (err error) {
	p, err = filepath.Abs(p)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("legacy state archive %q: %w; preserve a backup and repair or restore the archive before retrying (do not delete it)", p, err)
		}
	}()
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if err = json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("legacy state archive: %w", err)
	}
	if root["conversations"] == nil {
		return nil
	} // Legacy empty archives are valid.
	var conversations map[string]map[string]json.RawMessage
	if err = json.Unmarshal(root["conversations"], &conversations); err != nil {
		return fmt.Errorf("legacy state conversations: %w", err)
	}
	changed := false
	for _, conv := range conversations {
		var events []json.RawMessage
		if raw := conv["events"]; raw != nil {
			if err = json.Unmarshal(raw, &events); err != nil {
				return err
			}
		}
		var notes map[string]json.RawMessage
		if raw := conv["snapshot_notes"]; raw != nil {
			if err = json.Unmarshal(raw, &notes); err != nil {
				return err
			}
		}
		deadNotes, deadTasks := map[string]bool{}, map[string]bool{}
		type expiry struct {
			Kind    string `json:"k"`
			Note    string `json:"note_id"`
			Task    string `json:"task_id"`
			Expires int64  `json:"expires_at"`
			SentAt  int64  `json:"ts"`
			Author  string `json:"author"`
			Seq     int64  `json:"seq"`
		}
		noteExpiry, taskExpiry := map[string]int64{}, map[string]int64{}
		for id, raw := range notes {
			var e expiry
			if err = json.Unmarshal(raw, &e); err != nil {
				return err
			}
			noteExpiry[id] = e.Expires
		}
		// Snapshots own their note's TTL, including a zero (no expiry) TTL.
		// Select earliest adds in one pass instead of sorting the full history.
		earlier := func(a, b expiry) bool {
			if a.SentAt != b.SentAt {
				return a.SentAt < b.SentAt
			}
			if a.Author != b.Author {
				return a.Author < b.Author
			}
			return a.Seq < b.Seq
		}
		firstNotes, firstTasks := map[string]expiry{}, map[string]expiry{}
		parsed := make([]expiry, len(events))
		for i, raw := range events {
			if err = json.Unmarshal(raw, &parsed[i]); err != nil {
				return err
			}
			e := parsed[i]
			switch e.Kind {
			case "note-add":
				if _, snapshotOwns := notes[e.Note]; snapshotOwns {
					continue
				}
				if old, ok := firstNotes[e.Note]; !ok || earlier(e, old) {
					firstNotes[e.Note] = e
				}
			case "task-add":
				if old, ok := firstTasks[e.Task]; !ok || earlier(e, old) {
					firstTasks[e.Task] = e
				}
			}
		}
		for id, e := range firstNotes {
			noteExpiry[id] = e.Expires
		}
		for id, e := range firstTasks {
			taskExpiry[id] = e.Expires
		}

		for id, exp := range noteExpiry {
			if stateExpired(now, exp) {
				deadNotes[id] = true
			}
		}
		for id, exp := range taskExpiry {
			if stateExpired(now, exp) {
				deadTasks[id] = true
			}
		}
		if len(deadNotes)+len(deadTasks) == 0 {
			continue
		}
		changed = true
		for id := range deadNotes {
			delete(notes, id)
		}
		keep := make([]json.RawMessage, 0, len(events))
		for i, raw := range events {
			e := parsed[i]
			expired := false
			switch e.Kind {
			case "note-add", "note-done":
				expired = deadNotes[e.Note]
			case "task-add", "task-assign", "task-done", "task-reopen":
				expired = deadTasks[e.Task]
			}
			if !expired {
				keep = append(keep, raw)
			}
		}
		conv["events"], err = json.Marshal(keep)
		if err != nil {
			return err
		}
		if conv["snapshot_notes"] != nil {
			conv["snapshot_notes"], err = json.Marshal(notes)
			if err != nil {
				return err
			}
		}
	}
	if !changed {
		return nil
	}
	root["conversations"], err = json.Marshal(conversations)
	if err != nil {
		return err
	}
	data, err = json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), "legacy-state-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, p)
}
