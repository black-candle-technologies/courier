package main

import (
	"reflect"
	"testing"
)

func TestSplitSendArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantPos  []string
		wantFile string
		wantAtt  []string
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, file, att := splitSendArgs(tc.args)
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Errorf("positional = %v, want %v", pos, tc.wantPos)
			}
			if file != tc.wantFile {
				t.Errorf("file = %q, want %q", file, tc.wantFile)
			}
			if !reflect.DeepEqual(att, tc.wantAtt) {
				t.Errorf("attach = %v, want %v", att, tc.wantAtt)
			}
		})
	}
}

func TestSplitBackupArgs(t *testing.T) {
	cases := []struct {
		name            string
		args            []string
		wantPos         []string
		wantOutput      string
		wantPassEnv     string
		wantForce       bool
		wantDevice      string
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
