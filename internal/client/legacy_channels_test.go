package client

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyChannelSecretsNeverBecomeChat(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"join-request", "join-accept", "rekey", "msg", "leave"} {
		env.asSender()
		id, err := env.sender.sendProtocolDM(env.recipCfg.Address, fmt.Sprintf(`{"cc":2,"t":%q,"s":"private-secret"}`, kind))
		if err != nil {
			t.Fatal(err)
		}
		env.asRecipient()
		if _, err := env.recipient.FetchMessage(id); err == nil || !strings.Contains(err.Error(), "retired channel") {
			t.Fatalf("fetch %s: %v", kind, err)
		}
		msgs, _, _, _, err := env.recipient.Inbox(0, 50)
		if err != nil || len(msgs) != 0 {
			t.Fatalf("leaked channel %s: %+v %v", kind, msgs, err)
		}
	}
	if !isLegacyChannelPayload([]byte(`{"cc":2,"t":"rekey","s":42}`)) {
		t.Fatal("malformed ancillary secret fell through")
	}
	for _, raw := range []string{`{"cc":1,"t":"rekey"}`, `{"cc":2,"t":"other"}`, `hello`} {
		if isLegacyChannelPayload([]byte(raw)) {
			t.Fatal("ordinary input swallowed", raw)
		}
	}
	env.asSender()
	_, err := env.sender.Send(env.recipCfg.Address, "ordinary chat")
	if err != nil {
		t.Fatal(err)
	}
	env.asRecipient()
	msgs, _, _, _, err := env.recipient.Inbox(0, 50)
	if err != nil || len(msgs) != 1 || msgs[0].Body != "ordinary chat" {
		t.Fatal(msgs, err)
	}
}
func TestLegacyChannelArchiveWarnsWithoutMutation(t *testing.T) {
	cfg := testConfig(t)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	p, _ := configPath()
	p = filepath.Join(filepath.Dir(p), "channels.json")
	raw := []byte(`{"secret":"do-not-print-or-delete"}`)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	_, loadErr := LoadConfig()
	if loadErr == nil {
		_, loadErr = LoadConfig()
	}
	w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	r.Close()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if strings.Count(string(out), "https://github.com/black-candle-technologies/courier/blob/main/docs/legacy-channel-retirement.md") != 1 || strings.Contains(string(out), "do-not-print") {
		t.Fatal("unsafe or missing warning", string(out))
	}
	b, _ := os.ReadFile(p)
	if string(b) != string(raw) {
		t.Fatal("archive modified")
	}
}

func TestRetiredProtocolKeepsPushHashesAligned(t *testing.T) {
	env := newAttachTestEnv(t)
	env.asRecipient()
	if err := env.recipient.PublishKey(); err != nil {
		t.Fatal(err)
	}
	env.asSender()
	if _, err := env.sender.sendProtocolDM(env.recipCfg.Address, `{"cc":2,"t":"rekey","s":"secret"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := env.sender.Send(env.recipCfg.Address, "chat after protocol"); err != nil {
		t.Fatal(err)
	}
	env.asRecipient()
	msgs, _, _, _, hashes, err := env.recipient.inbox(0, 50, false, seenConsumerPush)
	if err != nil || len(msgs) != 1 || len(hashes) != 1 || hashes[0] == "" {
		t.Fatalf("unaligned push: %v %v %v", msgs, hashes, err)
	}
	env.recipient.recordSeen(seenConsumerPush, hashes)
	msgs, _, _, _, _, err = env.recipient.inbox(0, 50, false, seenConsumerPush)
	if err != nil || len(msgs) != 0 {
		t.Fatalf("acknowledged chat replayed: %v %v", msgs, err)
	}
}
