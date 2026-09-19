//go:build unix

package client

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// This file implements cross-process config safety (v0.6.11 F5).
//
// Courier agents routinely run several long-lived processes against one
// identity: `dashboard push --follow`, inbox watchers, and one-shot
// commands like `rotate`. Each loads config.json once at startup. When a
// long-lived process later called Save(), it wrote back its stale
// in-memory copy and silently clobbered fields another process had
// changed meanwhile — e.g. wiping newly rotated encryption private keys.
//
// Two mechanisms fix this:
//  1. withConfigLock serializes config read-modify-write cycles across
//     processes with an flock on ~/.courier/config.lock.
//  2. Save writes atomically (temp file in the same directory + rename),
//     so a crash can never leave a partially written config.
//
// The rule: short-lived commands may keep using Save, but any mutation
// of a long-lived Config must go through Update, which takes the lock,
// reloads the freshest on-disk state, applies the mutation, and saves
// atomically.

// configLockPath is the cross-process mutex for config read-modify-write
// cycles.
func configLockPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "config.lock"), nil
}

// withConfigLock runs fn while holding the in-process config mutex and an
// exclusive flock on the config lock file. The mutex serializes goroutines
// sharing a Config; the flock serializes Courier processes. The lock is
// advisory and only coordinates Courier processes (which is the threat
// model here); a foreign writer that ignores it can still race, but
// Courier itself never will.
func withConfigLock(fn func() error) error {
	configMu.Lock()
	defer configMu.Unlock()
	p, err := configLockPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("config lock: %w", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}
