package client

// Compatibility quarantine for the retired shared-state feature. Keep its
// reserved wire discriminator out of chat, including malformed/unknown versions.
// There is deliberately no state command, event application, or transmission.
import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
func (s Context) maintainLegacyState() error {
	return s.withConfigLock(func() error {
		p, err := s.configPath()
		if err != nil {
			return err
		}
		p = filepath.Join(filepath.Dir(p), "state.json")
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
		now := time.Now().Unix()
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
			ordered := make([]expiry, len(events))
			for i, raw := range events {
				if err = json.Unmarshal(raw, &ordered[i]); err != nil {
					return err
				}
			}
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
			// Match the retired fold: snapshots precede events and the first
			// add in (timestamp, author, sequence) order owns an item's TTL.
			for _, e := range ordered {
				switch e.Kind {
				case "note-add":
					if _, ok := noteExpiry[e.Note]; !ok {
						noteExpiry[e.Note] = e.Expires
					}
				case "task-add":
					if _, ok := taskExpiry[e.Task]; !ok {
						taskExpiry[e.Task] = e.Expires
					}
				}
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
			for _, raw := range events {
				var e expiry
				if err = json.Unmarshal(raw, &e); err != nil {
					return err
				}
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
	})
}
