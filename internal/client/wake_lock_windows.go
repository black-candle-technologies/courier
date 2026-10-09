//go:build windows

package client

import (
	"fmt"
	"os"
	"path/filepath"
)

func acquireWakeLock(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFileEx(f, false); err != nil {
		f.Close()
		return nil, fmt.Errorf("wake daemon lock: %w", err)
	}
	if err = f.Truncate(0); err != nil {
		unlockFileEx(f)
		f.Close()
		return nil, err
	}
	if _, err = fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		unlockFileEx(f)
		f.Close()
		return nil, err
	}
	// Keep the inode so another opener cannot acquire a different file.
	return func() { _ = unlockFileEx(f); _ = f.Close() }, nil
}
