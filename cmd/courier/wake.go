// Built-in instant wake (issue #42): `courier wake` and
// `courier wake install`.
//
// `courier wake -- <command> [args...]` runs a foreground daemon that
// holds a long-poll inbox subscription and executes the command —
// directly, never through a shell — with new-message metadata as JSON
// on stdin, within a second or two of each message's arrival.
//
// `courier wake install -- <command> [args...]` generates a systemd
// user unit that keeps the daemon running persistently. Wake stays
// opt-in: nothing runs until the operator installs and enables it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/black-candle-technologies/courier/internal/client"
)

func cmdWake(args []string) error {
	if len(args) > 0 && args[0] == "install" {
		return cmdWakeInstall(args[1:])
	}
	fs := flag.NewFlagSet("wake", flag.ContinueOnError)
	cooldown := fs.Duration("cooldown", client.DefaultWakeCooldown,
		"minimum interval between wake actions from the same sender")
	maxPerMin := fs.Int("max-per-minute", client.DefaultMaxWakeActionsPerMinute,
		"maximum wake actions per minute across all senders")
	pidfile := fs.String("pidfile", client.DefaultWakePIDFile(),
		"pidfile locked while the daemon runs (empty disables)")
	// Issue #97: when the wake command does more than read-only
	// ingestion, bridged (non-E2E, untrusted-input) messages can be
	// structurally excluded from wake dispatch.
	suppressBridged := fs.Bool("suppress-bridged-actions", false,
		"never fire the wake command for bridged (non-E2E) messages; they stay visible via inbox/dashboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Everything after the flags (a "--" separator is accepted and
	// ignored) is the wake command argv, run directly with no shell.
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("no wake command given: run `courier wake -- <command> [args...]`")
	}
	cfg, err := client.LoadConfig()
	if err != nil {
		return err
	}
	cl := client.New(cfg)
	daemon := client.NewWakeDaemon(cl, client.WakeDaemonConfig{
		Command:                command,
		Cooldown:               *cooldown,
		MaxActionsPerMinute:    *maxPerMin,
		PIDFile:                *pidfile,
		SuppressBridgedActions: *suppressBridged,
	}, os.Stderr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return daemon.Run(ctx)
}

// cmdWakeInstall writes a systemd user unit that runs the wake daemon
// persistently. Installing is the explicit opt-in: wake never starts
// on its own.
func cmdWakeInstall(args []string) error {
	fs := flag.NewFlagSet("wake install", flag.ContinueOnError)
	cooldown := fs.Duration("cooldown", client.DefaultWakeCooldown,
		"minimum interval between wake actions from the same sender")
	pidfile := fs.String("pidfile", client.DefaultWakePIDFile(),
		"pidfile locked while the daemon runs (empty disables)")
	// Issue #97: persisted into the generated unit so installed
	// daemons keep the operator's bridged-dispatch choice.
	suppressBridged := fs.Bool("suppress-bridged-actions", false,
		"never fire the wake command for bridged (non-E2E) messages; they stay visible via inbox/dashboard")
	force := fs.Bool("force", false, "overwrite an existing unit file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 {
		return fmt.Errorf("no wake command given: run `courier wake install -- <command> [args...]`")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate courier binary: %w", err)
	}
	unitDir, err := systemdUserDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", unitDir, err)
	}
	unitPath := filepath.Join(unitDir, "courier-wake.service")
	if _, err := os.Stat(unitPath); err == nil && !*force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", unitPath)
	}
	// The wake command is embedded as separate argv words with
	// systemd quoting: at runtime the daemon still execs it directly,
	// with no shell involved.
	quoted := make([]string, 0, len(command))
	for _, a := range command {
		quoted = append(quoted, quoteSystemdArg(a))
	}
	execStart := strings.Join([]string{
		quoteSystemdArg(exe), "wake",
		"--cooldown", cooldown.String(),
		"--pidfile", quoteSystemdArg(*pidfile),
		"--suppress-bridged-actions", strconv.FormatBool(*suppressBridged),
		"--",
	}, " ") + " " + strings.Join(quoted, " ")
	unit := fmt.Sprintf(`[Unit]
Description=Courier instant wake daemon
Documentation=https://github.com/black-candle-technologies/courier
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
`, execStart)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", unitPath, err)
	}
	fmt.Printf(`Wrote %s

Wake is opt-in and stays off until you enable it:
  systemctl --user daemon-reload
  systemctl --user enable --now courier-wake.service

The daemon will run: courier wake -- %s
Logs: journalctl --user -u courier-wake -f
`, unitPath, strings.Join(command, " "))
	return nil
}

func systemdUserDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "systemd", "user"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find home directory: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

// quoteSystemdArg quotes one argv word for a systemd ExecStart line,
// which splits on whitespace honoring double quotes and backslashes.
func quoteSystemdArg(a string) string {
	if a == "" {
		return `""`
	}
	safe := true
	for _, r := range a {
		if !(r == '/' || r == '.' || r == '-' || r == '_' || r == ':' ||
			r == '+' || r == '=' || r == ',' || r == '@' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			safe = false
			break
		}
	}
	if safe {
		return a
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range a {
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}
