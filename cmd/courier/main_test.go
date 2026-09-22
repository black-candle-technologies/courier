package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/black-candle-technologies/courier/internal/client"
)

func TestSplitSendArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantPos  []string
		wantFile string
		wantRply string
		wantAtt  []string
		wantTTL  string
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, file, replyTo, att, ttl := splitSendArgs(tc.args)
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
