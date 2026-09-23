package main

import (
	"os"
	"testing"
)

func TestSanitizeForTerminal(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text untouched",
			input: "send 1.5 BTC to lane",
			want:  "send 1.5 BTC to lane",
		},
		{
			name:  "ansi escape rendered as visible escape",
			input: "approve\x1b[2K this",
			want:  `approve\x1b[2K this`,
		},
		{
			name:  "title-change sequence neutralized",
			input: "ok\x1b]0;pwned\adone",
			want:  `ok\x1b]0;pwned\adone`,
		},
		{
			name:  "newlines and tabs preserved for readability",
			input: "line1\n\tline2",
			want:  "line1\n\tline2",
		},
		{
			name:  "printable unicode passes through",
			input: "paÿment ✓ 完成",
			want:  "paÿment ✓ 完成",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeForTerminal(tc.input); got != tc.want {
				t.Errorf("sanitizeForTerminal(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestConfirmTypingRefusesPipedStdin(t *testing.T) {
	// stdin is a regular file here, not a terminal: the ceremony
	// must fail closed without consuming the "canned" response.
	f, err := os.CreateTemp("", "courier-vhl-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("MINT\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()
	if confirmTyping("mint VHL session token (type MINT to confirm)", "MINT") {
		t.Error("confirmTyping succeeded with non-terminal stdin; want refusal")
	}
}
