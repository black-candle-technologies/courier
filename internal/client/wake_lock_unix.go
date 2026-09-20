//go:build unix

package client

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// acquireWakeLock locks path for the daemon's lifetime (flock,
// non-blocking): a second `courier wake` refuses to start while the
// first holds it. The PID is written for operators; release removes
// the file and drops the lock. An empty path disables the lock.
func acquireWakeLock(path string) (release func(), err error) {
	noop := func() {}
	if path == "" {
		return noop, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return noop, fmt.Errorf("wake pidfile: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return noop, fmt.Errorf("wake pidfile: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return noop, fmt.Errorf("another wake daemon is already running (pidfile %s is locked)", path)
	}
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		_ = f.Truncate(0)
		fmt.Fprintf(f, "%d\n", os.Getpid())
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		_ = os.Remove(path)
	}, nil
}
