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
