package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuoteSystemdArg(t *testing.T) {
	cases := []struct{ in, want string }{
		{"simple", "simple"},
		{"/home/user/my dir/courier", `"/home/user/my dir/courier"`},
		{"", `""`},
		{`a"b\c`, `"a\"b\\c"`},
		{"--cooldown", "--cooldown"},
		{"5m", "5m"},
	}
	for _, c := range cases {
		if got := quoteSystemdArg(c.in); got != c.want {
			t.Errorf("quoteSystemdArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestWakeInstallWritesUnit verifies `courier wake install` generates a
// valid systemd user unit embedding the wake command, and refuses to
// clobber without --force.
func TestWakeInstallWritesUnit(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	if err := cmdWakeInstall([]string{"--", "/opt/hooks/wake.sh", "--json"}); err != nil {
		t.Fatalf("install: %v", err)
	}
	unitPath := filepath.Join(dir, "systemd", "user", "courier-wake.service")
	raw, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(raw)
	for _, want := range []string{
		"[Unit]", "[Service]", "[Install]",
		"WantedBy=default.target",
		"Restart=on-failure",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q:\n%s", want, unit)
		}
	}
	// The ExecStart line must run `courier wake` with the hook as
	// separate argv (no shell), with systemd quoting where needed.
	var execStart string
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			execStart = line
		}
	}
	if execStart == "" {
		t.Fatalf("no ExecStart in unit:\n%s", unit)
	}
	if !strings.Contains(execStart, "wake") || !strings.Contains(execStart, "--") {
		t.Errorf("ExecStart does not invoke `courier wake -- ...`: %q", execStart)
	}
	if !strings.Contains(execStart, "/opt/hooks/wake.sh") {
		t.Errorf("ExecStart missing wake command: %q", execStart)
	}
	// Issue #97: the install path persists the daemon flags so the
	// installed unit keeps the operator's bridged-dispatch choice.
	if !strings.Contains(execStart, "--suppress-bridged-actions false") {
		t.Errorf("ExecStart missing persisted --suppress-bridged-actions: %q", execStart)
	}
	if strings.Contains(execStart, "sh -c") || strings.Contains(execStart, "/bin/sh") {
		t.Errorf("ExecStart must not involve a shell: %q", execStart)
	}

	// Second install without --force refuses to overwrite.
	if err := cmdWakeInstall([]string{"--", "/other/hook"}); err == nil {
		t.Fatal("second install without --force succeeded, want refusal")
	}
	// With --force it overwrites.
	if err := cmdWakeInstall([]string{"--force", "--", "/other/hook"}); err != nil {
		t.Fatalf("install --force: %v", err)
	}
	raw, _ = os.ReadFile(unitPath)
	if !strings.Contains(string(raw), "/other/hook") {
		t.Error("forced install did not overwrite the unit")
	}
	// --suppress-bridged-actions persists as true when requested.
	if err := cmdWakeInstall([]string{"--force", "--suppress-bridged-actions", "--", "/other/hook"}); err != nil {
		t.Fatalf("install --suppress-bridged-actions: %v", err)
	}
	raw, _ = os.ReadFile(unitPath)
	if !strings.Contains(string(raw), "--suppress-bridged-actions true") {
		t.Errorf("unit missing persisted --suppress-bridged-actions true:\n%s", raw)
	}
}
