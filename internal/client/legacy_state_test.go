package client

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyStateNeverBecomesChat(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{1, 2} {
		env.asSender()
		id, err := env.sender.sendProtocolDM(env.recipCfg.Address, fmt.Sprintf(`{"cs":1,"t":"state","v":%d,"events":[{"k":"note-add","note_id":"n","title":"expired-secret","expires_at":1}]}`, version))
		if err != nil {
			t.Fatal(err)
		}
		env.asRecipient()
		if _, err := env.recipient.FetchMessage(id); err == nil || !strings.Contains(err.Error(), "retired state") {
			t.Fatal("legacy state was fetchable as chat")
		}
		msgs, _, _, _, err := env.recipient.Inbox(0, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != 0 {
			t.Fatalf("legacy plaintext delivered: %+v", msgs)
		}
	}
	env = newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	env.asSender()
	_, err := env.sender.Send(env.recipCfg.Address, "ordinary chat")
	if err != nil {
		t.Fatal(err)
	}
	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil || len(msgs) != 1 || msgs[0].Body != "ordinary chat" {
		t.Fatalf("chat regression: %+v %v", msgs, err)
	}
}

func TestLegacyStateArchivePrunesAndPreserves(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	p = filepath.Join(filepath.Dir(p), "state.json")
	future := time.Now().Unix() + 3600
	raw := fmt.Sprintf(`{"extra":"preserved","conversations":{"peer":{"max_seq":{"peer":5},"events":[{"k":"note-add","note_id":"dead","title":"expired-secret","expires_at":1},{"k":"note-done","note_id":"dead","body":"expired-mutation"},{"k":"task-add","task_id":"live","title":"live-secret","expires_at":%d},{"k":"note-add","note_id":"forever","title":"forever-secret"}],"snapshot_notes":{"old":{"title":"expired-snapshot","expires_at":1},"live":{"title":"live-snapshot"}}}}}`, future)
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, secret := range []string{"expired-secret", "expired-mutation", "expired-snapshot"} {
		if strings.Contains(s, secret) {
			t.Fatalf("retained %s", secret)
		}
	}
	for _, secret := range []string{"live-secret", "forever-secret", "live-snapshot", "preserved", "max_seq"} {
		if !strings.Contains(s, secret) {
			t.Fatalf("lost %s", secret)
		}
	}
	// Simulate a later lifecycle access after the future TTL elapsed.
	s = strings.ReplaceAll(s, fmt.Sprint(future), "1")
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if strings.Contains(string(b), "live-secret") {
		t.Fatal("later expiry orphaned")
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("archive permissions", err)
	}
}

func TestLegacyStateMalformedArchivePreserved(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	p = filepath.Join(filepath.Dir(p), "state.json")
	if err := os.WriteFile(p, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err == nil {
		t.Fatal("malformed archive silently ignored")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "broken" {
		t.Fatal("malformed archive overwritten")
	}
}

func TestLegacyStateArchivePreservesOriginalFold(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	p = filepath.Join(filepath.Dir(p), "state.json")
	raw := `{"conversations":{"peer":{"events":[{"k":"note-add","note_id":"live","ts":1,"title":"first-live"},{"k":"note-add","note_id":"live","ts":2,"expires_at":1,"title":"duplicate"},{"k":"task-add","task_id":"dead","note_id":"live","expires_at":1},{"k":"note-add","note_id":"snap","expires_at":1}],"snapshot_notes":{"snap":{"title":"snapshot-live"}}}}}`
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	for _, want := range []string{"first-live", "duplicate", "snapshot-live"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("lost %s", want)
		}
	}
	if strings.Contains(string(b), `"task-add"`) {
		t.Fatal("expired task retained")
	}
}

func TestLegacyStateMaintenanceDuringPolling(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	p, _ := configPath()
	p = filepath.Join(filepath.Dir(p), "state.json")
	if err := os.WriteFile(p, []byte(`{"conversations":{"peer":{"events":[{"k":"note-add","note_id":"dead","title":"poll-expired","expires_at":1}]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	// Existing client instance; no LoadConfig call between polls.
	if _, _, _, _, err := env.recipient.Inbox(0, 50); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "poll-expired") {
		t.Fatal("polling stranded expiry")
	}
}

func TestLegacyStateEmptyArchiveCompatibility(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	p = filepath.Join(filepath.Dir(p), "state.json")
	for _, raw := range []string{`{}`, `null`, `{"conversations":null}`, `{"extra":"preserve"}`} {
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(); err != nil {
			t.Fatalf("legacy empty archive rejected: %s: %v", raw, err)
		}
		b, _ := os.ReadFile(p)
		if string(b) != raw {
			t.Fatal("empty archive changed")
		}
	}
}

func TestBridgedSendMaintainsLegacyStateAfterStartup(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	cl := New(cfg)
	p, _ := configPath()
	p = filepath.Join(filepath.Dir(p), "state.json")
	// A gateway has already loaded its client when the archive expires.
	raw := `{"conversations":{"peer":{"events":[{"k":"note-add","note_id":"dead","title":"expired-secret","expires_at":1}]}}}`
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	_, _ = cl.SendBridged("invalid-address", "body", nil)
	b, err := os.ReadFile(p)
	if err != nil || strings.Contains(string(b), "expired-secret") {
		t.Fatalf("gateway retained expired state: %s %v", b, err)
	}
}

func TestFSRetiredAndExpiredPayloadsStayOutOfChat(t *testing.T) {
	h := newFSHarness(t)
	h.asAlice(func() {
		if err := h.alice.sendFSInit(h.bobCfg.Address); err != nil {
			t.Fatal(err)
		}
	})
	h.bobInbox(t)
	h.aliceInbox(t)
	for _, body := range []string{`{"cs":1,"t":"state","v":99,"events":[]}`, `{"cc":2,"t":"msg","v":99}`, `{"v":1,"body":"expired","expires_at":1}`} {
		h.asAlice(func() {
			if _, err := h.alice.Send(h.bobCfg.Address, body); err != nil {
				t.Fatal(err)
			}
		})
		if msgs := h.bobInbox(t); len(msgs) != 0 {
			t.Fatalf("protocol or expired FS plaintext became chat: %+v", msgs)
		}
	}
	h.asAlice(func() {
		if _, err := h.alice.Send(h.bobCfg.Address, "live control"); err != nil {
			t.Fatal(err)
		}
	})
	if msgs := h.bobInbox(t); len(msgs) != 1 || msgs[0].Body != "live control" {
		t.Fatalf("FS session failed after consumed frames: %+v", msgs)
	}
}
