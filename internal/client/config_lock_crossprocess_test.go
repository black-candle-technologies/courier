//go:build unix

package client

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

// TestWithConfigLockSerializesAcrossProcesses forks several child
// processes that each hammer Config.Update increments on the same config
// file. The lock file is shared across processes (HOME is inherited from
// the parent, which testConfig isolates to a temp dir), so every
// increment must survive: without a real cross-process lock, the
// read-modify-write races would lose increments. This is the unix
// counterpart of the Windows LockFileEx guarantee added for issue #109:
// the Windows side is covered by TestLockFileExExclusion plus this same
// test, which is portable once HOME-based isolation works there.
func TestWithConfigLockSerializesAcrossProcesses(t *testing.T) {
	if os.Getenv("COURIER_LOCK_TEST_CHILD") == "1" {
		t.Skip("child worker: see TestConfigLockChildWorker")
	}
	testConfig(t) // isolates HOME; children inherit it

	const children = 4
	const perChild = 25

	errs := make(chan error, children)
	for i := 0; i < children; i++ {
		go func() {
			cmd := exec.Command(os.Args[0],
				"-test.run=TestConfigLockChildWorker", "-test.count=1")
			cmd.Env = append(os.Environ(),
				"COURIER_LOCK_TEST_CHILD=1",
				"COURIER_LOCK_TEST_N="+strconv.Itoa(perChild),
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				errs <- fmt.Errorf("child process: %w\n%s", err, out)
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < children; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(children * perChild); reloaded.Cursor != want {
		t.Fatalf("lost increments across processes: got %d, want %d", reloaded.Cursor, want)
	}
}

// TestConfigLockChildWorker is the child-process entry point for
// TestWithConfigLockSerializesAcrossProcesses. It is re-executed as the
// test binary with COURIER_LOCK_TEST_CHILD=1 and performs N Update
// increments against the config in the inherited HOME.
func TestConfigLockChildWorker(t *testing.T) {
	if os.Getenv("COURIER_LOCK_TEST_CHILD") != "1" {
		t.Skip("not a child worker")
	}
	n, err := strconv.Atoi(os.Getenv("COURIER_LOCK_TEST_N"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Update(func(fresh *Config) error {
			fresh.Cursor++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAcquireConfigLockRoundTrip exercises the lock helper directly:
// acquire, release, and re-acquire must all succeed.
func TestAcquireConfigLockRoundTrip(t *testing.T) {
	testConfig(t)
	for i := 0; i < 2; i++ {
		release, err := acquireConfigLock()
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		release()
	}
}
