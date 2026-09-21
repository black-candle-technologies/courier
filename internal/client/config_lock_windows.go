//go:build windows

package client

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// This file implements cross-process config safety (v0.6.11 F5) on
// Windows, with the same withConfigLock semantics as the unix path
// (config_lock.go). It fixes issue #109, where the non-unix fallback
// degraded to an in-process mutex and concurrent CLI / wake daemon /
// dashboard-push / agent processes could lost-update each other.
//
// flock does not exist on Windows, so the lock is an exclusive LockFileEx
// over the first byte of the same ~/.courier/config.lock file the unix
// path uses. LockFileEx, like flock, is released automatically if the
// process dies (the kernel drops the lock with the handle), so a crashed
// process can never wedge the config. The lock is advisory and only
// coordinates Courier processes; a foreign writer that ignores it can
// still race, but Courier itself never will. A named mutex was
// considered, but the Global\ namespace needs privileges and the Local\
// namespace is per-session (a service-hosted wake daemon and a CLI in a
// user session would not share it); a file lock has neither problem and
// mirrors the unix behavior exactly.
//
// Platform support: concurrent Courier processes are fully supported on
// unix (config_lock.go, flock) and on Windows (this file, LockFileEx).
// On other platforms the lock degrades to an in-process mutex only
// (config_lock_other.go) — see that file's platform table.

func configLockPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".courier", "config.lock"), nil
}

// lockFileEx takes an exclusive LockFileEx over byte range [0,1) of f.
// When blocking is false, LOCKFILE_FAIL_IMMEDIATELY is set so the call
// returns ERROR_LOCK_VIOLATION instead of waiting for the lock.
func lockFileEx(f *os.File, blocking bool) error {
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if !blocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	// Zero Overlapped: the locked range starts at file offset 0 and no
	// event handle is given, so the call blocks until the lock is
	// granted. Locking a single byte at offset 0 is the conventional
	// whole-file idiom and works on zero-length files.
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &ol)
}

func unlockFileEx(f *os.File) error {
	var ol windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
}

// acquireConfigLock mirrors the unix implementation: open (creating) the
// lock file and take a blocking exclusive lock on it. The returned func
// releases the lock; the OS also releases it automatically on process
// death.
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
	if err := lockFileEx(f, true); err != nil {
		f.Close()
		return nil, fmt.Errorf("config lock: %w", err)
	}
	return func() {
		_ = unlockFileEx(f)
		f.Close()
	}, nil
}

// withConfigLock runs fn while holding the in-process config mutex and an
// exclusive LockFileEx on the config lock file. The mutex serializes
// goroutines sharing a Config; the LockFileEx serializes Courier
// processes on this machine — the same contract as the unix path.
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
