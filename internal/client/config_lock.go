//go:build unix

package client

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// This file implements cross-process config safety (v0.6.11 F5) on unix.
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
//
// Platform support: concurrent Courier processes are fully supported on
// unix (this file, flock) and on Windows (config_lock_windows.go,
// LockFileEx). On other platforms the lock degrades to an in-process
// mutex only (config_lock_other.go): torn writes are still impossible
// thanks to atomic rename, but concurrent processes can lost-update each
// other — see the platform table in config_lock_other.go.

// configLockPath is the cross-process mutex for config read-modify-write
// cycles.
func configLockPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "config.lock"), nil
}

// acquireConfigLock opens (creating) the lock file and takes an
// exclusive, blocking flock on it. The lock is advisory and only
// coordinates Courier processes (which is the threat model here); a
// foreign writer that ignores it can still race, but Courier itself never
// will. The lock releases automatically if the process dies, because the
// kernel drops the flock with the file description — a crashed process
// can never wedge the config.
func acquireConfigLock() (release func(), err error) {
	p, err := configLockPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("config lock: %w", err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}

// withConfigLock runs fn while holding the in-process config mutex and an
// exclusive flock on the config lock file. The mutex serializes goroutines
// sharing a Config; the flock serializes Courier processes.
func withConfigLock(fn func() error) error {
	configMu.Lock()
	defer configMu.Unlock()
	release, err := acquireConfigLock()
	if err != nil {
		return err
	}
	defer release()
	return fn()
}
