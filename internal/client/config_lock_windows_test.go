//go:build windows

package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestLockFileExExclusion verifies the Windows cross-process lock
// primitive itself (issue #109): while one handle holds the exclusive
// LockFileEx, a non-blocking attempt from a second handle to the same
// file must fail with ERROR_LOCK_VIOLATION, and must succeed once the
// first handle releases. Deterministic: no goroutines, no timing.
//
// NOTE: this test only runs on Windows. On unix the equivalent
// cross-process guarantee is covered by
// TestWithConfigLockSerializesAcrossProcesses.
func TestLockFileExExclusion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := lockFileEx(f, true); err != nil {
		t.Fatalf("blocking acquire: %v", err)
	}

	// A second handle to the same file must not take the lock while held.
	g, err := os.OpenFile(p, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	err = lockFileEx(g, false)
	if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("try-lock while held: got %v, want ERROR_LOCK_VIOLATION", err)
	}

	if err := unlockFileEx(f); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := lockFileEx(g, false); err != nil {
		t.Fatalf("try-lock after release: %v", err)
	}
	if err := unlockFileEx(g); err != nil {
		t.Fatalf("unlock second handle: %v", err)
	}
}

// TestAcquireConfigLockRoundTripWindows mirrors the unix round-trip test:
// acquiring and releasing the config lock twice must succeed.
func TestAcquireConfigLockRoundTripWindows(t *testing.T) {
	t.Setenv("USERPROFILE", t.TempDir())
	for i := 0; i < 2; i++ {
		release, err := acquireConfigLock()
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		release()
	}
}
