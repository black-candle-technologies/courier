package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
)

func TestSplitSendArgs(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantPos   []string
		wantFile  string
		wantRply  string
		wantAtt   []string
		wantTTL   string
		wantTier  string
		wantAttst string
	}{
		{
			name:    "flags before positionals",
			args:    []string{"--attach", "a.bin", "ed25519:abc", "hello"},
			wantPos: []string{"ed25519:abc", "hello"},
			wantAtt: []string{"a.bin"},
		},
		{
			name:    "flags after positionals (documented form)",
			args:    []string{"ed25519:abc", "hello", "--attach", "a.bin"},
			wantPos: []string{"ed25519:abc", "hello"},
			wantAtt: []string{"a.bin"},
		},
		{
			name:    "equals form and repeatable attach",
			args:    []string{"ed25519:abc", "--attach=a.bin", "hi", "--attach", "b.bin"},
			wantPos: []string{"ed25519:abc", "hi"},
			wantAtt: []string{"a.bin", "b.bin"},
		},
		{
			name:     "file flag anywhere",
			args:     []string{"--file", "body.txt", "ed25519:abc"},
			wantPos:  []string{"ed25519:abc"},
			wantFile: "body.txt",
		},
		{
			name:    "no flags",
			args:    []string{"ed25519:abc", "hello", "world"},
			wantPos: []string{"ed25519:abc", "hello", "world"},
		},
		{
			name:     "reply-to anywhere",
			args:     []string{"--reply-to", "42", "ed25519:abc", "hello"},
			wantPos:  []string{"ed25519:abc", "hello"},
			wantRply: "42",
		},
		{
			name:     "reply-to equals form after positionals",
			args:     []string{"ed25519:abc", "hello", "--reply-to=43"},
			wantPos:  []string{"ed25519:abc", "hello"},
			wantRply: "43",
		},
		{
			name:    "ttl flag after message",
			args:    []string{"ed25519:abc", "hello", "--ttl", "10m"},
			wantPos: []string{"ed25519:abc", "hello"},
			wantTTL: "10m",
		},
		{
			name:    "ttl equals form before positionals",
			args:    []string{"--ttl=2h", "ed25519:abc", "hello"},
			wantPos: []string{"ed25519:abc", "hello"},
			wantTTL: "2h",
		},
		{
			name:      "tier and attestation flags",
			args:      []string{"ed25519:abc", "hello", "--tier", "2", "--attestation=abc123"},
			wantPos:   []string{"ed25519:abc", "hello"},
			wantTier:  "2",
			wantAttst: "abc123",
		},
		{
			name:     "tier equals form before positionals",
			args:     []string{"--tier=1", "ed25519:abc", "hello"},
			wantPos:  []string{"ed25519:abc", "hello"},
			wantTier: "1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, file, replyTo, att, ttl, tier, attest := splitSendArgs(tc.args)
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Errorf("positional = %v, want %v", pos, tc.wantPos)
			}
			if file != tc.wantFile {
				t.Errorf("file = %q, want %q", file, tc.wantFile)
			}
			if replyTo != tc.wantRply {
				t.Errorf("replyTo = %q, want %q", replyTo, tc.wantRply)
			}
			if !reflect.DeepEqual(att, tc.wantAtt) {
				t.Errorf("attach = %v, want %v", att, tc.wantAtt)
			}
			if ttl != tc.wantTTL {
				t.Errorf("ttl = %q, want %q", ttl, tc.wantTTL)
			}
			if tier != tc.wantTier {
				t.Errorf("tier = %q, want %q", tier, tc.wantTier)
			}
			if attest != tc.wantAttst {
				t.Errorf("attestation = %q, want %q", attest, tc.wantAttst)
			}
		})
	}
}

func TestSplitBackupArgs(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantPos     []string
		wantOutput  string
		wantPassEnv string
		wantForce   bool
		wantDevice  string
	}{
		{
			name:        "flags after positional",
			args:        []string{"backup.json", "--force", "--passphrase-env", "PW"},
			wantPos:     []string{"backup.json"},
			wantPassEnv: "PW",
			wantForce:   true,
		},
		{
			name:        "flags before positional",
			args:        []string{"--force", "--passphrase-env", "PW", "backup.json"},
			wantPos:     []string{"backup.json"},
			wantPassEnv: "PW",
			wantForce:   true,
		},
		{
			name:       "equals form",
			args:       []string{"--output=out.json", "--device-name=laptop"},
			wantPos:    nil,
			wantOutput: "out.json",
			wantDevice: "laptop",
		},
		{
			name:    "no flags",
			args:    []string{"sync.json"},
			wantPos: []string{"sync.json"},
		},
		{
			name:    "unknown args stay positional",
			args:    []string{"--bogus", "x.json"},
			wantPos: []string{"--bogus", "x.json"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, output, device, passEnv, force := splitBackupArgs(tc.args)
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Errorf("positional = %v, want %v", pos, tc.wantPos)
			}
			if output != tc.wantOutput {
				t.Errorf("output = %q, want %q", output, tc.wantOutput)
			}
			if device != tc.wantDevice {
				t.Errorf("device = %q, want %q", device, tc.wantDevice)
			}
			if passEnv != tc.wantPassEnv {
				t.Errorf("passphraseEnv = %q, want %q", passEnv, tc.wantPassEnv)
			}
			if force != tc.wantForce {
				t.Errorf("force = %v, want %v", force, tc.wantForce)
			}
		})
	}
}

// TestToStdioMessageBridged: the stdio bridge (the agent integration
// surface) must carry the bridged flag (issues #96/#97) — dropping it
// here would silently strip the untrusted-input signal from agent
// consumers.
func TestToStdioMessageBridged(t *testing.T) {
	bridged := toStdioMessage(client.Message{
		ID: 7, From: "ed25519:bridge", Body: "hi", Bridged: true,
	})
	if !bridged.Bridged {
		t.Error("bridged flag lost in stdio mapping")
	}
	plain := toStdioMessage(client.Message{
		ID: 8, From: "ed25519:peer", Body: "hi",
	})
	if plain.Bridged {
		t.Error("ordinary message mapped as bridged")
	}
	// The flag is serialized (omitempty): a careless agent parsing the
	// JSON still sees bridged:true, and sees nothing for the rest.
	raw, err := json.Marshal(bridged)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["bridged"] != true {
		t.Errorf("bridged not serialized: %s", raw)
	}
	raw, _ = json.Marshal(plain)
	wire = nil
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["bridged"]; ok {
		t.Error("non-bridged message must omit the bridged field")
	}
}

// TestSaveAttachmentHardened (issue #136 review): recovered plaintext is
// written with strict local-file semantics — a directory created by the
// command is 0700, files are 0600, creation is atomic O_CREATE|O_EXCL
// (no stat-then-write TOCTOU window), an existing name gets a numeric
// suffix instead of being overwritten, and a planted symlink is never
// followed.
func TestSaveAttachmentHardened(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dl")

	p, err := saveAttachment(target, "secret.bin", []byte("plaintext"))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if want := filepath.Join(target, "secret.bin"); p != want {
		t.Fatalf("path = %q, want %q", p, want)
	}
	if fi, err := os.Stat(target); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Fatalf("created dir mode = %o, want 700", fi.Mode().Perm())
	}
	if fi, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", fi.Mode().Perm())
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "plaintext" {
		t.Fatalf("content = %q, err = %v", b, err)
	}

	// An existing name is never overwritten: a numeric suffix is added.
	p2, err := saveAttachment(target, "secret.bin", []byte("v2"))
	if err != nil {
		t.Fatalf("second save: %v", err)
	}
	if p2 == p {
		t.Fatal("second save overwrote the first file")
	}
	if b, _ := os.ReadFile(p); string(b) != "plaintext" {
		t.Fatal("first file was clobbered by the second save")
	}
	if b, _ := os.ReadFile(p2); string(b) != "v2" {
		t.Fatal("second file has wrong content")
	}

	// A symlink planted at the target name is never followed: the save
	// takes the next free suffix and the link target is untouched.
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(target, "link.bin")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	p3, err := saveAttachment(target, "link.bin", []byte("data"))
	if err != nil {
		t.Fatalf("save over symlink: %v", err)
	}
	if p3 == link {
		t.Fatal("save returned the symlink path itself")
	}
	if b, _ := os.ReadFile(victim); string(b) != "do not touch" {
		t.Fatal("planted symlink was followed: victim file overwritten")
	}
	if b, _ := os.ReadFile(p3); string(b) != "data" {
		t.Fatal("suffixed file has wrong content")
	}
}
