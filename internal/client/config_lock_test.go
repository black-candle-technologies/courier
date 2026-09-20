package client

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestUpdateReloadsFreshState is the F5 regression test: a stale
// in-memory Config must not clobber fields another process wrote.
// cfgA is loaded, then cfgB (same file) advances the cursor and saves;
// cfgA.Update must preserve cfgB's cursor while applying its own change.
// The old mutate-then-Save pattern would have reset the cursor to 0.
func TestUpdateReloadsFreshState(t *testing.T) {
	cfgA := testConfig(t)

	cfgB, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfgB.Cursor = 42
	if err := cfgB.Save(); err != nil {
		t.Fatal(err)
	}

	if err := cfgA.Update(func(fresh *Config) error {
		t := true
		fresh.AutoUpdate = &t
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Cursor != 42 {
		t.Fatalf("stale Update clobbered cursor: got %d, want 42", reloaded.Cursor)
	}
	if !reloaded.AutoUpdateEnabled() {
		t.Fatal("Update did not apply its own mutation")
	}
	// The receiver is refreshed to the saved state.
	if cfgA.Cursor != 42 || !cfgA.AutoUpdateEnabled() {
		t.Fatalf("receiver not refreshed: %+v", cfgA)
	}
}

// TestUpdateSerializesConcurrentWriters hammers Update from many
// goroutines (separate lock-file descriptions, so flock serializes them).
// Every increment must survive: without the lock, increments would be
// lost to read-modify-write races.
func TestUpdateSerializesConcurrentWriters(t *testing.T) {
	cfg := testConfig(t)
	const writers = 8
	const perWriter = 25
	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if err := cfg.Update(func(fresh *Config) error {
					fresh.Cursor++
					return nil
				}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(writers * perWriter); reloaded.Cursor != want {
		t.Fatalf("lost increments under concurrency: got %d, want %d", reloaded.Cursor, want)
	}
}

// TestSaveIsAtomic verifies the write-temp-then-rename discipline: after
// Save the config parses cleanly, has mode 0600, and no temp files are
// left behind.
func TestSaveIsAtomic(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cursor = 7
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	p, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Must still parse via the normal loader.
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("config does not parse after Save: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", fi.Mode().Perm())
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(p), "config-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
	if string(raw) == "" {
		t.Fatal("empty config file")
	}
}

// TestSavePersistsInMemoryState documents Save's contract: it writes the
// receiver as-is (no reload). Long-lived mutators must use Update.
func TestSavePersistsInMemoryState(t *testing.T) {
	cfg := testConfig(t)
	cfg.Cursor = 99
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Cursor != 99 {
		t.Fatalf("got %d, want 99", reloaded.Cursor)
	}
}
