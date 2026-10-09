package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

var ErrLegacyMigrated = errors.New("legacy Courier store has migrated; resolve the active context before opening stores")

// MigrationOptions requires the operator to stop all legacy writers, including
// dashboard/bridge processes and daemons using custom pidfiles. Historical
// binaries cannot be made migration-aware retroactively.
type MigrationOptions struct{ ConfirmLegacyWritersStopped bool }

type contextManifest struct {
	Version   int          `json:"version"`
	Principal string       `json:"principal"`
	Binding   RelayBinding `json:"binding"`
}

type migrationJournal struct {
	Manifest contextManifest   `json:"manifest"`
	Files    map[string]string `json:"files"`
}

var contextFiles = []string{"config.json", "groups.json", "fs.json", "vhl.json", "receipts.json", "sent.jsonl", "thread_cache.jsonl", "channels.json", "state.json"}

func (s Context) manifest() contextManifest { return contextManifest{1, s.principal, s.binding} }
func (m contextManifest) resolve(root string) (Context, error) {
	if m.Version != 1 {
		return Context{}, fmt.Errorf("unsupported context manifest")
	}
	h := Hosts{Enabled: true, Bindings: map[string]RelayBinding{m.Binding.ID: m.Binding}, Identities: map[string]NamedIdentity{"identity": {m.Principal, m.Binding.ID}}, Hosts: map[string]Host{"host": {m.Binding.ID, "identity"}}}
	return h.Resolve(root, "host", "")
}

// ActiveContext reads the single durable commit point. It never initiates or
// resumes migration; incomplete staging leaves the legacy context selected.
func (s Context) ActiveContext() (Context, error) {
	if s.principal != "" {
		return s, nil
	}
	p, err := s.path("active-context.json")
	if err != nil {
		return Context{}, err
	}
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return Context{}, err
	}
	var m contextManifest
	if err = json.Unmarshal(raw, &m); err != nil {
		return Context{}, err
	}
	return m.resolve(s.root)
}

func (s Context) refuseMigrated() error {
	if s.principal != "" {
		return nil
	}
	p, err := s.path("active-context.json")
	if err != nil {
		return err
	}
	if _, err = os.Lstat(p); err == nil {
		return ErrLegacyMigrated
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func durableReplace(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "context-*.tmp")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return commitContextFile(temp, path)
}
func syncContextDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func regularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("migration refuses non-regular file %s", filepath.Base(path))
	}
	return os.ReadFile(path)
}
func migrationHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// MigrateLegacy explicitly copies a quiescent legacy store into a named context.
// Existing sources are retained. Repeating after interruption resumes only when
// the source checksums and selected security binding still match the journal.
// Never revert to the retained copy after new ratchets/checkpoints advance.
func (s Context) MigrateLegacy(target Context, opts MigrationOptions) error {
	return s.migrateLegacy(target, opts, nil)
}

// stop is a test-only crash boundary. Production never injects failures.
func (s Context) migrateLegacy(target Context, opts MigrationOptions, stop func(string) error) error {
	if !opts.ConfirmLegacyWritersStopped {
		return fmt.Errorf("stop all legacy writers and explicitly confirm quiescence")
	}
	// Directory fsync and process-lock semantics must be verified before enabling
	// migration on additional platforms. Ordinary context I/O remains portable.
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "js" {
		return fmt.Errorf("journaled migration is not enabled on this platform")
	}
	if s.principal != "" || target.principal == "" {
		return fmt.Errorf("migration requires legacy source and named target")
	}
	expected, err := target.manifest().resolve(s.root)
	if err != nil {
		return err
	}
	if expected != target {
		return fmt.Errorf("target is outside the legacy installation")
	}
	for _, dir := range []string{s.root, filepath.Dir(target.root), target.root, target.root + ".staging"} {
		info, e := os.Lstat(dir)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("migration requires ordinary directories")
		}
	}
	configMu.Lock()
	defer configMu.Unlock()
	release, err := s.acquireConfigLock()
	if err != nil {
		return err
	}
	defer release()
	if err = target.checkBinding(false); err != nil {
		return err
	}
	// Supported binaries refuse mixed legacy writes once the commit point exists.
	active, err := s.ActiveContext()
	if err != nil {
		return err
	}
	if active.principal != "" {
		if active != target {
			return ErrContextMismatch
		}
		_, err = target.loadConfigRaw()
		return err
	}
	wakeRelease, err := acquireWakeLock(s.DefaultWakePIDFile())
	if err != nil {
		return err
	}
	defer wakeRelease()
	checkpoint := func(name string) error {
		if stop != nil {
			return stop(name)
		}
		return nil
	}
	raw, err := regularFile(filepath.Join(s.root, "config.json"))
	if err != nil {
		return err
	}
	var cfg Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if err = target.validateConfig(&cfg); err != nil {
		return err
	}
	j := migrationJournal{Manifest: target.manifest(), Files: map[string]string{}}
	contents := map[string][]byte{}
	for _, name := range contextFiles {
		raw, err = regularFile(filepath.Join(s.root, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		contents[name] = raw
		j.Files[name] = migrationHash(raw)
	}
	journalPath := filepath.Join(s.root, "context-migration.json")
	old, err := os.ReadFile(journalPath)
	if err == nil {
		var prior migrationJournal
		if err = json.Unmarshal(old, &prior); err != nil {
			return err
		}
		want, _ := json.Marshal(j)
		have, _ := json.Marshal(prior)
		if string(want) != string(have) {
			return fmt.Errorf("migration source or binding changed; preserve staging and investigate before recovery")
		}
	} else if os.IsNotExist(err) {
		if _, e := os.Lstat(target.root); !os.IsNotExist(e) {
			return fmt.Errorf("migration target already exists without journal")
		}
		if _, e := os.Lstat(target.root + ".staging"); !os.IsNotExist(e) {
			return fmt.Errorf("migration staging already exists without journal")
		}
		raw, _ = json.Marshal(j)
		if err = durableReplace(journalPath, raw); err != nil {
			return err
		}
	} else {
		return err
	}
	if err = checkpoint("journal"); err != nil {
		return err
	}
	stage := target.root + ".staging"
	// A target existing without this journal must never be overwritten. An
	// existing complete target with this journal is a recoverable post-rename.
	if _, err = os.Stat(target.root); os.IsNotExist(err) {
		if err = os.MkdirAll(stage, 0700); err != nil {
			return err
		}
		for _, name := range contextFiles {
			data, ok := contents[name]
			if !ok {
				continue
			}
			if err = durableReplace(filepath.Join(stage, name), data); err != nil {
				return err
			}
			if err = checkpoint("copy:" + name); err != nil {
				return err
			}
		}
		if err = checkpoint("staged"); err != nil {
			return err
		}
		if err = os.Rename(stage, target.root); err != nil {
			return err
		}
		if err = syncContextDir(filepath.Dir(target.root)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for name, hash := range j.Files {
		data, err := regularFile(filepath.Join(target.root, name))
		if err != nil {
			return err
		}
		if migrationHash(data) != hash {
			return fmt.Errorf("migration target checksum mismatch: %s", name)
		}
	}
	if err = checkpoint("verified"); err != nil {
		return err
	}
	if _, err = target.loadConfigRaw(); err != nil {
		return err
	}
	if err = target.checkBinding(true); err != nil {
		return err
	}
	if err = checkpoint("binding"); err != nil {
		return err
	}
	raw, _ = json.Marshal(j.Manifest)
	if err = durableReplace(filepath.Join(s.root, "active-context.json"), raw); err != nil {
		return err
	}
	return checkpoint("committed")
}
