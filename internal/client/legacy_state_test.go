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
