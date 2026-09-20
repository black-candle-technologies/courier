//go:build !unix

package client

import (
	"fmt"
	"os"
	"path/filepath"
)

// acquireWakeLock writes the PID file without cross-process locking on
// platforms without flock. The systemd unit still guarantees a single
// instance where it matters.
func acquireWakeLock(path string) (release func(), err error) {
	noop := func() {}
	if path == "" {
		return noop, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return noop, fmt.Errorf("wake pidfile: %w", err)
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		return noop, fmt.Errorf("wake pidfile: %w", err)
	}
	return func() { _ = os.Remove(path) }, nil
}
